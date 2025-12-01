import os
import json
import time
import sqlite3
import threading
import subprocess
import re
import psutil
from datetime import datetime
from flask import Flask, render_template, jsonify, request, session, redirect, url_for

# --- 配置 ---
DB_FILE = '/opt/fan_controller/data.db'
SECRET_KEY = os.urandom(24)
LOGIN_PASSWORD = 'linyijianb'
PORT = 90
RETENTION_DAYS = 7

app = Flask(__name__)
app.secret_key = SECRET_KEY

# 全局缓存 (带默认值防止启动时读取失败)
cache_lock = threading.Lock()
sys_cache = {
    'hw': {'temp': 0, 'power': 0, 'fan_rpm': 0, 'mode': 'auto', 'sensors': [], 'max_rpm': 0, 'min_rpm': 0},
    'res': {'cpu': 0, 'mem_percent': 0, 'mem_used': 0, 'mem_total': 0, 
            'net_in': 0, 'net_out': 0, 'disk_r': 0, 'disk_w': 0},
    'calibration': {'active': False, 'progress': 0, 'current_pwm': 0, 'current_rpm': 0, 'log': ''}
}
rpm_map = {} 
max_rpm = 0
min_rpm = 0

# --- 数据库 (关键优化：开启WAL模式) ---
def get_db_connection():
    conn = sqlite3.connect(DB_FILE, timeout=10) # 增加超时容错
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    # [关键优化] 开启 Write-Ahead Logging，允许并发读写，解决卡顿的核心！
    c.execute('PRAGMA journal_mode=WAL;')
    
    c.execute('''CREATE TABLE IF NOT EXISTS metrics_v2 
                 (timestamp INTEGER, cpu_temp REAL, fan_rpm INTEGER, power_watts INTEGER,
                  cpu_usage REAL, mem_usage REAL, net_recv_speed REAL, net_sent_speed REAL,
                  disk_read_speed REAL, disk_write_speed REAL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)''')
    
    # 初始化默认值
    c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('mode', 'auto')")
    
    default_curve = {}
    for t in range(30, 95, 5): default_curve[str(t)] = 20
    c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('curve', ?)", (json.dumps(default_curve),))
    c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('calibration_data', '{}')")
    
    conn.commit()
    conn.close()
    load_calibration_map()

def load_calibration_map():
    global rpm_map, max_rpm, min_rpm
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT value FROM config WHERE key='calibration_data'")
        res = c.fetchone()
        conn.close()
        
        raw_data = json.loads(res[0]) if res and res[0] else {}
        if not raw_data:
            rpm_map = {}; max_rpm = 0; min_rpm = 0
            return

        rpms = [int(v) for v in raw_data.values()]
        if not rpms: return
        max_rpm = max(rpms)
        min_rpm = min(rpms)
        
        # 建立映射
        temp_map = {}
        sorted_points = sorted([(int(k), int(v)) for k, v in raw_data.items()], key=lambda x: x[1])
        for target_pct in range(1, 101):
            target_rpm = max_rpm * (target_pct / 100.0)
            best_pwm = 10
            min_diff = 999999
            for pwm, rpm in sorted_points:
                diff = abs(rpm - target_rpm)
                if diff < min_diff: min_diff = diff; best_pwm = pwm
            temp_map[target_pct] = best_pwm
        rpm_map = temp_map
        
        # 更新缓存中的RPM信息
        with cache_lock:
            sys_cache['hw']['max_rpm'] = max_rpm
            sys_cache['hw']['min_rpm'] = min_rpm
            
    except Exception as e:
        print(f"Calib Load Error: {e}")

# --- 辅助函数 ---
def get_ipmi_dump():
    try: return subprocess.check_output(['ipmitool', 'sensor'], encoding='utf-8', timeout=3)
    except: return ""

def parse_ipmi_value(dump, regex):
    try:
        match = re.search(regex, dump, re.MULTILINE)
        if match: return float(match.group(1))
    except: pass
    return 0

def get_max_cpu_temp():
    try:
        output = subprocess.check_output(['sensors'], encoding='utf-8')
        temps = re.findall(r'Core \d+:\s+\+([\d\.]+)°C', output)
        if temps: return max([float(t) for t in temps])
        temps_pkg = re.findall(r'Package id \d+:\s+\+([\d\.]+)°C', output)
        if temps_pkg: return max([float(t) for t in temps_pkg])
    except: pass
    return 0

def set_fan_mode(mode):
    val = '0x01' if mode == 'auto' else '0x00'
    subprocess.run(['ipmitool', 'raw', '0x30', '0x30', '0x01', val], stdout=subprocess.DEVNULL)

def set_raw_pwm(pwm_percent):
    hex_val = hex(int(pwm_percent))
    subprocess.run(['ipmitool', 'raw', '0x30', '0x30', '0x02', '0xff', hex_val], stdout=subprocess.DEVNULL)

def get_pwm_from_rpm_percent(percent):
    if not rpm_map or percent <= 0: return percent
    if percent >= 100: return 100
    return rpm_map.get(int(percent), percent)

def get_realtime_rpm_only():
    dump = get_ipmi_dump()
    return int(parse_ipmi_value(dump, r'Fan1 RPM\s+\|\s+([\d\.]+)\s+'))

# --- 任务线程 ---
def calibration_task():
    global sys_cache
    conn = get_db_connection()
    c = conn.cursor()
    sys_cache['calibration']['active'] = True
    sys_cache['calibration']['log'] = 'Starting...'
    
    try:
        for i in range(3):
            time.sleep(1)
            sys_cache['calibration']['log'] = f'Waiting for system loop... {3-i}'
        
        set_fan_mode('manual')
        
        # Spin down
        set_raw_pwm(10)
        sys_cache['calibration']['current_pwm'] = 10
        for i in range(15):
            if not sys_cache['calibration']['active']: break
            current_rpm = get_realtime_rpm_only()
            sys_cache['calibration']['current_rpm'] = current_rpm
            sys_cache['calibration']['log'] = f'Spinning down... {15-i}s ({current_rpm} RPM)'
            time.sleep(1)
            
        calibration_data = {}
        steps = list(range(10, 101, 2))
        total = len(steps)
        
        for idx, pwm in enumerate(steps):
            if not sys_cache['calibration']['active']: break
            set_raw_pwm(pwm)
            sys_cache['calibration']['current_pwm'] = pwm
            sys_cache['calibration']['progress'] = int((idx / total) * 100)
            
            for i in range(5):
                current_rpm = get_realtime_rpm_only()
                sys_cache['calibration']['current_rpm'] = current_rpm
                sys_cache['calibration']['log'] = f'PWM {pwm}%... ({current_rpm} RPM)'
                time.sleep(1)
            
            calibration_data[str(pwm)] = sys_cache['calibration']['current_rpm']
            
        if sys_cache['calibration']['active']:
            sys_cache['calibration']['log'] = 'Saving...'
            c.execute("UPDATE config SET value=? WHERE key='calibration_data'", (json.dumps(calibration_data),))
            conn.commit()
            load_calibration_map()
            sys_cache['calibration']['log'] = 'Done!'
    except Exception as e:
        sys_cache['calibration']['log'] = f'Err: {str(e)}'
        print(e)
    finally:
        sys_cache['calibration']['active'] = False
        sys_cache['calibration']['progress'] = 100
        conn.close()

def background_worker():
    last_db_log_time = 0
    last_net_io = psutil.net_io_counters()
    last_disk_io = psutil.disk_io_counters()
    last_io_time = time.time()

    while True:
        try:
            start_time = time.time()
            
            if sys_cache['calibration']['active']:
                time.sleep(1)
                continue

            # HW Data
            ipmi_dump = get_ipmi_dump()
            cpu_temp = get_max_cpu_temp()
            if cpu_temp == 0: cpu_temp = parse_ipmi_value(ipmi_dump, r'Temp\s+\|\s+([\d\.]+)\s+\|')
            power = int(parse_ipmi_value(ipmi_dump, r'Pwr Consumption\s+\|\s+([\d\.]+)\s+'))
            fan_rpm = int(parse_ipmi_value(ipmi_dump, r'Fan1 RPM\s+\|\s+([\d\.]+)\s+'))

            # Res Data
            cpu_u = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            curr_net = psutil.net_io_counters()
            curr_disk = psutil.disk_io_counters()
            now = time.time()
            dt = now - last_io_time
            if dt < 0.1: dt = 0.1
            
            net_in = (curr_net.bytes_recv - last_net_io.bytes_recv) / dt
            net_out = (curr_net.bytes_sent - last_net_io.bytes_sent) / dt
            disk_r = (curr_disk.read_bytes - last_disk_io.read_bytes) / dt
            disk_w = (curr_disk.write_bytes - last_disk_io.write_bytes) / dt
            
            last_net_io = curr_net; last_disk_io = curr_disk; last_io_time = now

            # Sensors List
            sensors_list = []
            if ipmi_dump:
                for line in ipmi_dump.splitlines():
                    parts = line.split('|')
                    if len(parts) >= 4:
                        val = parts[1].strip(); st = parts[3].strip()
                        if val == 'na' or st == 'na': continue
                        sensors_list.append({'source': 'IPMI', 'name': parts[0].strip(), 'value': val, 'unit': parts[2].strip(), 'status': st})

            # Control
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT value FROM config WHERE key='mode'")
            mode_row = c.fetchone()
            mode = mode_row[0] if mode_row else 'auto'
            
            c.execute("SELECT value FROM config WHERE key='curve'")
            curve_row = c.fetchone()
            curve = json.loads(curve_row[0]) if curve_row else {}
            
            if mode == 'auto':
                set_fan_mode('auto')
            else:
                set_fan_mode('manual')
                step = 5
                target_key = str(int(cpu_temp // step) * step)
                if int(target_key) < 30: target_key = '30'
                if int(target_key) > 90: target_key = '90'
                target_percent = int(curve.get(target_key, 20))
                if cpu_temp >= 85: target_percent = 100
                
                set_raw_pwm(get_pwm_from_rpm_percent(target_percent))

            # Update Cache
            with cache_lock:
                sys_cache['hw'] = {
                    'temp': cpu_temp, 'power': power, 'fan_rpm': fan_rpm, 'mode': mode, 
                    'sensors': sensors_list, 'max_rpm': max_rpm, 'min_rpm': min_rpm
                }
                sys_cache['res'] = {
                    'cpu': round(cpu_u, 1), 
                    'mem_percent': round(mem.percent, 1), 
                    'mem_used': round(mem.used/1024**3, 1), 
                    'mem_total': round(mem.total/1024**3, 1),
                    'net_in': int(net_in), 'net_out': int(net_out), 
                    'disk_r': int(disk_r), 'disk_w': int(disk_w)
                }

            # DB Log
            if now - last_db_log_time >= 60:
                c.execute('''INSERT INTO metrics_v2 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                         (int(now), cpu_temp, fan_rpm, power, cpu_u, mem.percent, 
                          net_in/1024, net_out/1024, disk_r/1024/1024, disk_w/1024/1024))
                
                # Cleanup old data
                cutoff = int(now) - (RETENTION_DAYS * 86400)
                c.execute("DELETE FROM metrics_v2 WHERE timestamp < ?", (cutoff,))
                conn.commit()
                last_db_log_time = now
            conn.close()
            
            elapsed = time.time() - start_time
            time.sleep(max(0.5, 3 - elapsed))

        except Exception as e:
            print(f"Worker Error: {e}")
            time.sleep(3)

# --- 路由 ---
def login_required(f):
    def wrapper(*args, **kwargs):
        if not session.get('logged_in'): return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['password'] == LOGIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('hardware_page'))
        else: return render_template('login.html', error="Invalid Password")
    return render_template('login.html')

@app.route('/logout')
def logout(): session.pop('logged_in', None); return redirect(url_for('login'))
@app.route('/')
@login_required
def root(): return redirect(url_for('hardware_page'))
@app.route('/hardware')
@login_required
def hardware_page(): return render_template('hardware.html')
@app.route('/resources')
@login_required
def resources_page(): return render_template('resources.html')
@app.route('/history')
@login_required
def history_page(): return render_template('history.html')

@app.route('/api/status_hardware')
@login_required
def api_status_hardware():
    with cache_lock: return jsonify(sys_cache['hw'])

@app.route('/api/status_resources')
@login_required
def api_status_resources():
    with cache_lock: return jsonify(sys_cache['res'])

# --- 历史数据 (24h) 智能降采样 ---
@app.route('/api/history')
@login_required
def api_history():
    conn = get_db_connection()
    c = conn.cursor()
    cutoff = time.time() - (24 * 3600)
    # 只查需要的字段
    c.execute("SELECT timestamp, cpu_temp, fan_rpm, power_watts, cpu_usage, mem_usage, net_recv_speed, net_sent_speed, disk_read_speed, disk_write_speed FROM metrics_v2 WHERE timestamp > ? ORDER BY timestamp ASC", (cutoff,))
    data = c.fetchall()
    conn.close()
    
    # [关键修复] 数据降采样：防止返回几万个点卡死前端
    # 目标：限制在 600 个点以内
    step = max(1, len(data) // 600)
    data = data[::step]

    return jsonify({
        'times': [datetime.fromtimestamp(d[0]).strftime('%H:%M') for d in data],
        'hw': {'temps': [round(d[1],1) for d in data], 'fans': [d[2] for d in data], 'power': [d[3] for d in data]},
        'res': {'cpu': [round(d[4],1) for d in data], 'mem': [round(d[5],1) for d in data], 
                'net_in': [round(d[6],1) for d in data], 'net_out': [round(d[7],1) for d in data],
                'disk_r': [round(d[8],1) for d in data], 'disk_w': [round(d[9],1) for d in data]}
    })

# --- 自定义历史数据 智能降采样 ---
@app.route('/api/history_custom')
@login_required
def api_history_custom():
    hours = int(request.args.get('hours', 24))
    conn = get_db_connection()
    c = conn.cursor()
    cutoff = time.time() - (hours * 3600)
    c.execute("SELECT * FROM metrics_v2 WHERE timestamp > ? ORDER BY timestamp ASC", (cutoff,))
    data = c.fetchall()
    conn.close()
    
    # [关键修复] 智能降采样，防止加载过慢
    step = max(1, len(data) // 800)
    data = data[::step]
    
    return jsonify({
        'times': [datetime.fromtimestamp(d[0]).strftime('%m-%d %H:%M') for d in data],
        'cpu_temp': [round(d[1],1) for d in data],
        'fan_rpm': [d[2] for d in data],
        'power': [d[3] for d in data],
        'cpu_load': [round(d[4],1) for d in data],
        'mem_load': [round(d[5],1) for d in data],
        'net_in': [round(d[6],1) for d in data],
        'net_out': [round(d[7],1) for d in data],
        'disk_r': [round(d[8],1) for d in data],
        'disk_w': [round(d[9],1) for d in data]
    })

@app.route('/api/config', methods=['GET', 'POST'])
@login_required
def api_config():
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == 'GET':
        c.execute("SELECT value FROM config WHERE key='curve'")
        res = c.fetchone()
        conn.close()
        return jsonify(json.loads(res[0]) if res else {})
    if request.method == 'POST':
        data = request.json
        if 'mode' in data: c.execute("UPDATE config SET value=? WHERE key='mode'", (data['mode'],))
        if 'curve' in data: c.execute("UPDATE config SET value=? WHERE key='curve'", (json.dumps(data['curve']),))
        conn.commit()
        conn.close()
        return jsonify({'status': 'ok'})

@app.route('/api/calibration/start', methods=['POST'])
@login_required
def api_calib_start():
    if not sys_cache['calibration']['active']:
        t = threading.Thread(target=calibration_task, daemon=True)
        t.start()
        return jsonify({'status': 'started'})
    return jsonify({'status': 'already_running'})

@app.route('/api/calibration/status')
@login_required
def api_calib_status():
    return jsonify(sys_cache['calibration'])

if __name__ == '__main__':
    init_db()
    t = threading.Thread(target=background_worker, daemon=True)
    t.start()
    app.run(host='0.0.0.0', port=PORT, threaded=True)