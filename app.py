import os
import json
import time
import sqlite3
import threading
import subprocess
import re
import psutil
import urllib.request
import markupsafe
import shutil
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, session, redirect, url_for

# --- 配置 ---
def load_config():
    if not os.path.exists('config.json'):
        print("Config file not found, copying from example...")
        import shutil
        shutil.copy('config.json.example', 'config.json')

    with open('config.json', 'r') as f:
        return json.load(f)

config = load_config()

DB_FILE = config['DATABASE']['path']
RETENTION_DAYS = config['DATABASE']['retention_days']
PORT = config['SERVER']['port']
SERVER_NAME = config['SERVER'].get('server_name', 'IPMI Controller')
LOGIN_PASSWORD = config['SECURITY']['login_password']
SECRET_KEY = os.urandom(24)

# 安全白名单：这些 IP 永远不会被封禁
IP_WHITELIST = [] # 移除 127.0.0.1 白名单以启用内网穿透防护测试

app = Flask(__name__)
app.secret_key = SECRET_KEY

# 强制 HTTPS 跳转逻辑
@app.before_request
def before_request():
    if HAS_CERT and not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

# 检测 HTTPS 证书
cert_dir = 'cert'
cert_file = os.path.join(cert_dir, 'server.crt')
key_file = os.path.join(cert_dir, 'server.key')
# 同时也检查 pem 扩展名
if not os.path.exists(cert_file): cert_file = os.path.join(cert_dir, 'server.pem')
if not os.path.exists(key_file): key_file = os.path.join(cert_dir, 'server.pem') # 有时证书和私钥在一个文件

HAS_CERT = os.path.exists(cert_file) and os.path.exists(key_file)

app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=HAS_CERT,
    SESSION_COOKIE_HTTPONLY=True
)

# 全局缓存 (带默认值防止启动时读取失败)
cache_lock = threading.Lock()
sys_cache = {
    'env': {'ipmitool': True, 'sensors': True},
    'hw': {'temp': 0, 'power': 0, 'fan_rpm': 0, 'mode': 'auto', 'sensors': [], 'max_rpm': 0, 'min_rpm': 0},
    'res': {'cpu': 0, 'mem_percent': 0, 'mem_used': 0, 'mem_total': 0, 
            'net_in': 0, 'net_out': 0, 'disk_r': 0, 'disk_w': 0},
    'gpu': {'online': False, 'gpus': [], 'last_update': 0, 'retry_delay': 1},
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
    c.execute('CREATE INDEX IF NOT EXISTS idx_metrics_ts ON metrics_v2(timestamp)')
    
    c.execute('''CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)''')
    
    # 新增 GPU 历史数据表
    c.execute('''CREATE TABLE IF NOT EXISTS gpu_metrics
                 (timestamp INTEGER, gpu_index INTEGER, gpu_name TEXT, temp REAL, 
                  util_gpu REAL, util_mem REAL, mem_total REAL, mem_used REAL, 
                  power REAL, power_limit REAL, clock_core INTEGER, clock_mem INTEGER, 
                  fan INTEGER, ecc INTEGER)''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_gpu_metrics_ts ON gpu_metrics(timestamp)')

    # 防爆破表：记录 IP + User-Agent 组合尝试失败情况
    c.execute('''CREATE TABLE IF NOT EXISTS login_attempts
                 (ip TEXT, user_agent TEXT, last_attempt INTEGER, fail_count INTEGER,
                  PRIMARY KEY (ip, user_agent))''')

    # 初始化默认值
    c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('mode', 'auto')")
    c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('last_log_check', '0')")
  
    default_curve = {}
    for t in range(30, 95, 5): default_curve[str(t)] = 20
    c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('curve', ?)", (json.dumps(default_curve),))
    c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('calibration_data', '{}')")
  
    # [修复] 确保固定转速的配置项存在
    c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('fixed_fan_speed_enabled', 'false')")
    c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('fixed_fan_speed_target', '30')")
    
    # GPU 配置初始化
    c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('gpu_agent_enabled', 'false')")
    c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('gpu_agent_host', '127.0.0.1')")
    c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('gpu_agent_port', '9999')")
  
    conn.commit()
    conn.close()
    load_calibration_map()

def check_environment():
    global sys_cache
    with cache_lock:
        sys_cache['env']['ipmitool'] = shutil.which('ipmitool') is not None
        sys_cache['env']['sensors'] = shutil.which('sensors') is not None
    if not sys_cache['env']['ipmitool'] or not sys_cache['env']['sensors']:
        print("⚠️ Environment Warning: Some dependencies are missing!")
        if not sys_cache['env']['ipmitool']: print("  - ipmitool NOT FOUND")
        if not sys_cache['env']['sensors']: print("  - sensors NOT FOUND")

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
def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

def get_ipmi_dump():
    try: return subprocess.check_output(['ipmitool', 'sensor'], encoding='utf-8', timeout=3)
    except: return ""

def log_login_error(ip, ua, count, wait_time):
    with open('login_errors.log', 'a', encoding='utf-8') as f:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        f.write(f"[{timestamp}] IP: {ip} | UA: {ua} | 失败次数: {count} | 惩罚等待: {wait_time}s\n")

def get_log_unread_status():
    try:
        if not os.path.exists('login_errors.log'): return False
        log_time = int(os.path.getmtime('login_errors.log'))
        conn = get_db_connection()
        res = conn.execute("SELECT value FROM config WHERE key='last_log_check'").fetchone()
        conn.close()
        last_check = int(res[0]) if res else 0
        return log_time > last_check
    except: return False

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

            c.execute("SELECT value FROM config WHERE key='fixed_fan_speed_enabled'")
            fixed_enabled_row = c.fetchone()
            fixed_enabled = fixed_enabled_row[0] == 'true' if fixed_enabled_row else False

            c.execute("SELECT value FROM config WHERE key='fixed_fan_speed_target'")
            fixed_target_row = c.fetchone()
            fixed_target = int(fixed_target_row[0]) if fixed_target_row else 30
          
            if fixed_enabled:
                set_fan_mode('manual')
                set_raw_pwm(get_pwm_from_rpm_percent(fixed_target))
                mode = 'fixed' # 更新模式状态
            elif mode == 'auto':
                set_fan_mode('auto')
            else: # curve mode
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

            # DB Log (1s precision)
            if now - last_db_log_time >= 1.0:
                c.execute('''INSERT INTO metrics_v2 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                         (int(now), cpu_temp, fan_rpm, power, cpu_u, mem.percent, 
                          net_in/1024, net_out/1024, disk_r/1024/1024, disk_w/1024/1024))
              
                # Cleanup old data
                cutoff = int(now) - (RETENTION_DAYS * 86400)
                c.execute("DELETE FROM metrics_v2 WHERE timestamp < ?", (cutoff,))
                conn.commit()
                last_db_log_time = now
          
            # [关键修复] 显式关闭连接
            conn.close()
          
            elapsed = time.time() - start_time
            time.sleep(max(0.1, 1.0 - elapsed))

        except Exception as e:
            print(f"Worker Error: {e}")
            time.sleep(3)

def gpu_worker():
    last_db_log_time = 0
    retry_delay = 1
    max_retry_delay = 30
    
    while True:
        try:
            start_time = time.time()
            
            # 从数据库读取配置
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT value FROM config WHERE key='gpu_agent_enabled'")
            enabled = c.fetchone()[0] == 'true'
            c.execute("SELECT value FROM config WHERE key='gpu_agent_host'")
            host = c.fetchone()[0]
            c.execute("SELECT value FROM config WHERE key='gpu_agent_port'")
            port = c.fetchone()[0]
            conn.close()

            if not enabled:
                with cache_lock:
                    sys_cache['gpu']['online'] = False
                time.sleep(5)
                continue

            # 请求 Agent
            url = f"http://{host}:{port}/metrics"
            try:
                with urllib.request.urlopen(url, timeout=3) as response:
                    data = json.loads(response.read().decode())
                    if 'error' in data:
                        raise Exception(data['error'])
                    
                    with cache_lock:
                        sys_cache['gpu']['online'] = True
                        sys_cache['gpu']['gpus'] = data['gpus']
                        sys_cache['gpu']['last_update'] = int(time.time())
                        sys_cache['gpu']['retry_delay'] = 1
                    
                    retry_delay = 1 # 成功后重置延迟
                    
                    # 记录历史数据 (1s一次)
                    now = time.time()
                    if now - last_db_log_time >= 1.0:
                        conn = get_db_connection()
                        c = conn.cursor()
                        for g in data['gpus']:
                            c.execute('''INSERT INTO gpu_metrics VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                     (int(now), g['index'], g['name'], g['temp'], 
                                      g['util_gpu'], g['util_mem'], g['memory_total'], g['memory_used'],
                                      g['power_draw'], g['power_limit'], g['clock_core'], g['clock_mem'], 
                                      g['fan_speed'], g['ecc_errors']))
                        conn.commit()
                        conn.close()
                        last_db_log_time = now
                
                elapsed = time.time() - start_time
                time.sleep(max(0.1, 1.0 - elapsed))

            except Exception as e:
                with cache_lock:
                    sys_cache['gpu']['online'] = False
                    sys_cache['gpu']['retry_delay'] = retry_delay
                print(f"GPU Agent Error (Retrying in {retry_delay}s): {e}")
                
                time.sleep(retry_delay)
                # 指数退避
                retry_delay = min(max_retry_delay, retry_delay * 2)

        except Exception as e:
            print(f"GPU Worker Loop Error: {e}")
            time.sleep(5)

# --- 路由 ---
def login_required(f):
    def wrapper(*args, **kwargs):
        if not session.get('logged_in'): return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = get_client_ip()
    ua = markupsafe.escape(request.headers.get('User-Agent', 'Unknown'))
    now = int(time.time())
    is_whitelisted = ip in IP_WHITELIST
    
    # 指纹逻辑：如果是 127.0.0.1 (内网穿透)，则结合 UA 区分；否则仅根据 IP 区分
    db_ip = ip
    db_ua = ua if ip == '127.0.0.1' else '*'
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT last_attempt, fail_count FROM login_attempts WHERE ip=? AND user_agent=?", (db_ip, db_ua))
    row = c.fetchone()
    
    fail_count = row['fail_count'] if row else 0
    last_attempt = row['last_attempt'] if row else 0
    
    # 从 session 获取一次性的错误消息 (PRG 模式)
    session_error = session.pop('login_error', None)
    
    # 延迟/封禁判定 (冷却中): 取消 10s 上限，改为最高 300s 渐进递增
    if not is_whitelisted and fail_count >= 3:
        # 算法：从第 3 次开始，每次失败增加 30 秒等待，封顶 300s (5 分钟)
        required_delay = min(300, (fail_count - 2) * 30)
        
        if now - last_attempt < required_delay:
            conn.close()
            remaining = required_delay - (now - last_attempt)
            err = session_error or "密码错误次数过多，请稍后重试。"
            return render_template('login.html', error=err, wait_seconds=remaining, server_name=SERVER_NAME)

    if request.method == 'POST':
        is_correct = (request.form['password'] == LOGIN_PASSWORD)
        
        if is_correct:
            # 密码正确：如果有失败记录，执行 3s 宽恕延迟后进入
            if not is_whitelisted and fail_count > 0:
                time.sleep(3)
                c.execute("DELETE FROM login_attempts WHERE ip=? AND user_agent=?", (db_ip, db_ua))
                conn.commit()
            conn.close()
            session['logged_in'] = True
            session.permanent = True
            return redirect(url_for('hardware_page'))
        else:
            # 密码错误：执行正常的阶梯式惩罚
            fail_count += 1
            wait_current = 0
            if not is_whitelisted:
                # 记录最新的失败状态
                c.execute("INSERT OR REPLACE INTO login_attempts (ip, user_agent, last_attempt, fail_count) VALUES (?, ?, ?, ?)", (db_ip, db_ua, int(time.time()), fail_count))
                conn.commit()
                # 执行阶梯惩罚延迟 (前端逻辑使用此值，但后台统一 sleep 5s 以防爆破并保持响应一致性)
                if fail_count >= 3:
                    wait_current = min(300, (fail_count - 2) * 30)
                
                # 统一后台延迟 5s
                time.sleep(5)

            conn.close()
            log_login_error(ip, ua, fail_count, wait_current)
            # PRG 模式重定向
            session['login_error'] = "密码错误次数过多，请稍后重试。"
            return redirect(url_for('login'))
    
    conn.close()
    return render_template('login.html', server_name=SERVER_NAME)

@app.route('/logout')
def logout(): session.pop('logged_in', None); return redirect(url_for('login'))
@app.route('/')
@login_required
def root(): return redirect(url_for('hardware_page'))
@app.route('/hardware')
@login_required
def hardware_page(): return render_template('hardware.html', server_name=SERVER_NAME)
@app.route('/resources')
@login_required
def resources_page(): return render_template('resources.html', server_name=SERVER_NAME)
@app.route('/history')
@login_required
def history_page(): return render_template('history.html', server_name=SERVER_NAME)

@app.route('/gpu')
@login_required
def gpu_page(): return render_template('gpu.html', server_name=SERVER_NAME)

@app.route('/logs')
@login_required
def logs_page():
    # 标记已读
    conn = get_db_connection()
    conn.execute("UPDATE config SET value=? WHERE key='last_log_check'", (int(time.time()),))
    conn.commit()
    conn.close()
    return render_template('logs.html', server_name=SERVER_NAME)

@app.route('/api/log_status')
@login_required
def api_log_status():
    return jsonify({'unread': get_log_unread_status()})

@app.route('/api/logs')
@login_required
def api_logs():
    if not os.path.exists('login_errors.log'): return jsonify([])
    
    logs = []
    try:
        with open('login_errors.log', 'r', encoding='utf-8') as f:
            lines = f.readlines()
            # 倒序显示，最新的在前面
            for line in reversed(lines):
                match = re.search(r'\[(.*?)\] IP: (.*?) \| UA: (.*?) \| 失败次数: (.*?) \| 惩罚等待: (.*?)s', line)
                if match:
                    logs.append({
                        'time': match.group(1),
                        'ip': match.group(2),
                        'ua': match.group(3),
                        'count': int(match.group(4)),
                        'wait': int(match.group(5))
                    })
    except Exception as e:
        print(f"Log Read Error: {e}")

    # 智能归类逻辑：按 (IP, UA) 归组
    groups = {}
    for l in logs:
        key = f"{l['ip']}_{l['ua']}"
        if key not in groups:
            # 提取简短 UA 标签
            ua_tag = "Unknown"
            if "Edg/" in l['ua']: ua_tag = "Edge"
            elif "Chrome" in l['ua']: ua_tag = "Chrome"
            elif "Firefox" in l['ua']: ua_tag = "Firefox"
            elif "Safari" in l['ua'] and "Chrome" not in l['ua']: ua_tag = "Safari"
            elif "python" in l['ua'].lower(): ua_tag = "Python Bot"
            elif "curl" in l['ua'].lower(): ua_tag = "cURL"
            
            groups[key] = {
                'ip': l['ip'],
                'ua': l['ua'],
                'ua_tag': ua_tag,
                'total_attempts': 0, # 总行数
                'max_fail_count': 0, # 记录中出现的最大失败计数
                'last_time': l['time'],
                'max_wait': 0,
                'history': []
            }
        
        groups[key]['total_attempts'] += 1
        if l['count'] > groups[key]['max_fail_count']:
            groups[key]['max_fail_count'] = l['count']
        if l['wait'] > groups[key]['max_wait']:
            groups[key]['max_wait'] = l['wait']
            
        groups[key]['history'].append(l)

    # 格式化输出数据，使前端显示更准确
    result = []
    for g in groups.values():
        result.append({
            'ip': g['ip'],
            'ua': g['ua'],
            'ua_tag': g['ua_tag'],
            'total_attempts': g['total_attempts'],
            'current_fail_count': g['max_fail_count'], # 这一轮中最高的计数值
            'last_time': g['last_time'],
            'max_wait': g['max_wait'],
            'history': g['history']
        })

    return jsonify(result)

@app.route('/api/status_hardware')
@login_required
def api_status_hardware():
    with cache_lock: return jsonify(sys_cache['hw'])

@app.route('/api/status_resources')
@login_required
def api_status_resources():
    with cache_lock: return jsonify(sys_cache['res'])

@app.route('/api/status_gpu')
@login_required
def api_status_gpu():
    with cache_lock: return jsonify(sys_cache['gpu'])

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
    cutoff = int(time.time() - (hours * 3600))
    
    # 归一化查询：将时间戳按秒取整，确保对齐
    c.execute("SELECT timestamp, cpu_temp, fan_rpm, power_watts, cpu_usage, mem_usage, net_recv_speed, net_sent_speed, disk_read_speed, disk_write_speed FROM metrics_v2 WHERE timestamp > ? ORDER BY timestamp ASC", (cutoff,))
    raw_data = c.fetchall()
    
    # 获取对应时间段的 GPU 数据用于对齐
    c.execute("SELECT timestamp, temp, util_gpu, util_mem, mem_used, power FROM gpu_metrics WHERE timestamp > ? ORDER BY timestamp ASC", (cutoff,))
    gpu_raw = c.fetchall()
    conn.close()
    
    if not raw_data:
        return jsonify({'times': [], 'cpu_temp': [], 'fan_rpm': [], 'power': [], 'cpu_load': [], 'mem_load': [], 'net_in': [], 'net_out': [], 'disk_r': [], 'disk_w': [], 'stats': {}})

    # 将 GPU 数据放入字典，方便快速查找
    gpu_map = {d[0]: d for d in gpu_raw}
    
    # 计算全局统计信息（抽样前）
    cpu_temps = [d[1] for d in raw_data]
    cpu_loads = [d[4] for d in raw_data]
    net_ins = [d[6] for d in raw_data]
    disk_rs = [d[8] for d in raw_data]
    
    stats = {
        'max_temp': round(max(cpu_temps), 1),
        'avg_load': round(sum(cpu_loads) / len(cpu_loads), 1),
        'max_net': round(max(net_ins), 1),
        'max_disk': round(max(disk_rs), 1)
    }
  
    # [关键修复] LTTB 降采样思路简化：在 1s 精度下，步进采样需配合局部极值保留
    # 目标：限制在 1200 个点以内（1s精度下稍微多留一些点以保证曲线平滑）
    target_points = 1200
    step = max(1, len(raw_data) // target_points)
    
    # 如果步长较大，我们不仅取起始点，还应确保这一段内的极值不被丢失（简单做法是取每段的第一个点）
    sampled_data = raw_data[::step]
  
    # 时间格式优化：如果是 1H 视图，显示到秒
    time_fmt = '%H:%M:%S' if hours <= 1 else '%m-%d %H:%M'
  
    # 对齐 GPU 数据到系统数据的时间轴
    aligned_gpu = {
        'temp': [], 'util_gpu': [], 'util_mem': [], 'mem_used': [], 'power': []
    }
    
    last_gpu_idx = 0
    gpu_len = len(gpu_raw)
    
    for d in sampled_data:
        ts = d[0]
        # 寻找最近的 GPU 数据点 (允许前后 2s 的误差)
        found = False
        # 简单的双指针优化查找
        while last_gpu_idx < gpu_len and gpu_raw[last_gpu_idx][0] < ts - 2:
            last_gpu_idx += 1
            
        if last_gpu_idx < gpu_len and abs(gpu_raw[last_gpu_idx][0] - ts) <= 2:
            g = gpu_raw[last_gpu_idx]
            aligned_gpu['temp'].append(g[1])
            aligned_gpu['util_gpu'].append(g[2])
            aligned_gpu['util_mem'].append(g[3])
            aligned_gpu['mem_used'].append(g[4])
            aligned_gpu['power'].append(g[5])
            found = True
        
        if not found:
            for k in aligned_gpu: aligned_gpu[k].append(None)

    return jsonify({
        'times': [datetime.fromtimestamp(d[0]).strftime(time_fmt) for d in sampled_data],
        'cpu_temp': [round(d[1],1) for d in sampled_data],
        'fan_rpm': [d[2] for d in sampled_data],
        'power': [d[3] for d in sampled_data],
        'cpu_load': [round(d[4],1) for d in sampled_data],
        'mem_load': [round(d[5],1) for d in sampled_data],
        'net_in': [round(d[6],1) for d in sampled_data],
        'net_out': [round(d[7],1) for d in sampled_data],
        'disk_r': [round(d[8],1) for d in sampled_data],
        'disk_w': [round(d[9],1) for d in sampled_data],
        'gpu': aligned_gpu, # 直接包含对齐后的 GPU 数据
        'stats': stats
    })

# --- [关键修复] Config 路由重写，防止数据库连接错误 ---
@app.route('/api/config', methods=['GET', 'POST'])
@login_required
def api_config():
    conn = get_db_connection()
    c = conn.cursor()
  
    if request.method == 'GET':
        try:
            # 统一查询逻辑，避免多次开关连接
            res_curve = c.execute("SELECT value FROM config WHERE key='curve'").fetchone()
            res_fixed_enabled = c.execute("SELECT value FROM config WHERE key='fixed_fan_speed_enabled'").fetchone()
            res_fixed_target = c.execute("SELECT value FROM config WHERE key='fixed_fan_speed_target'").fetchone()
          
            # 处理数据，给默认值防止 NoneType 错误
            curve_data = json.loads(res_curve[0]) if res_curve and res_curve[0] else {}
            if not curve_data:
                curve_data = {str(i): 20 for i in range(30, 95, 5)}

            fixed_enabled = (res_fixed_enabled[0] == 'true') if res_fixed_enabled and res_fixed_enabled[0] else False
          
            fixed_target = 30
            if res_fixed_target and res_fixed_target[0]:
                try:
                    fixed_target = int(res_fixed_target[0])
                except:
                    fixed_target = 30

            return jsonify({
                'curve': curve_data,
                'fixed_fan_speed_enabled': fixed_enabled,
                'fixed_fan_speed_target': fixed_target
            })
        except Exception as e:
            print(f"Config GET Error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500
        finally:
            conn.close()

    if request.method == 'POST':
        try:
            data = request.json
            if 'mode' in data: 
                c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('mode', ?)", (data['mode'],))
          
            if 'curve' in data: 
                c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('curve', ?)", (json.dumps(data['curve']),))
          
            # 兼容性保存
            if 'enabled' in data:
                val = 'true' if data['enabled'] else 'false'
                c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('fixed_fan_speed_enabled', ?)", (val,))
          
            if 'target' in data:
                c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('fixed_fan_speed_target', ?)", (str(data['target']),))

            conn.commit()
            return jsonify({'status': 'ok'})
        except Exception as e:
            print(f"Config POST Error: {e}")
            return jsonify({'error': str(e)}), 500
        finally:
            conn.close()

@app.route('/api/config/fixed_fan_speed', methods=['POST'])
@login_required
def api_config_fixed_fan_speed():
    conn = get_db_connection()
    c = conn.cursor()
    try:
        data = request.json
        if 'enabled' in data:
            c.execute("UPDATE config SET value=? WHERE key='fixed_fan_speed_enabled'", (str(data['enabled']).lower(),))
        if 'target' in data:
            c.execute("UPDATE config SET value=? WHERE key='fixed_fan_speed_target'", (str(data['target']),))
        conn.commit()
        return jsonify({'status': 'ok'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

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

# --- GPU 配置接口 ---
@app.route('/api/config/gpu', methods=['GET', 'POST'])
@login_required
def api_config_gpu():
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == 'GET':
        c.execute("SELECT key, value FROM config WHERE key LIKE 'gpu_agent_%'")
        res = {row['key']: row['value'] for row in c.fetchall()}
        conn.close()
        return jsonify(res)
    
    if request.method == 'POST':
        data = request.json
        if 'gpu_agent_enabled' in data:
            c.execute("UPDATE config SET value=? WHERE key='gpu_agent_enabled'", (str(data['gpu_agent_enabled']).lower(),))
        if 'gpu_agent_host' in data:
            c.execute("UPDATE config SET value=? WHERE key='gpu_agent_host'", (data['gpu_agent_host'],))
        if 'gpu_agent_port' in data:
            c.execute("UPDATE config SET value=? WHERE key='gpu_agent_port'", (str(data['gpu_agent_port']),))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'})

# --- GPU 历史数据接口 ---
@app.route('/api/history_gpu')
@login_required
def api_history_gpu():
    hours = int(request.args.get('hours', 24))
    gpu_index = int(request.args.get('index', 0))
    conn = get_db_connection()
    c = conn.cursor()
    cutoff = int(time.time() - (hours * 3600))
    c.execute("SELECT timestamp, temp, util_gpu, util_mem, mem_total, mem_used, power FROM gpu_metrics WHERE timestamp > ? AND gpu_index = ? ORDER BY timestamp ASC", (cutoff, gpu_index))
    data = c.fetchall()
    conn.close()
    
    if not data:
        return jsonify({'times': [], 'temp': [], 'util_gpu': [], 'util_mem': [], 'mem_used': [], 'power': []})
  
    # 智能降采样
    target_points = 1200
    step = max(1, len(data) // target_points)
    sampled_data = data[::step]
    
    time_fmt = '%H:%M:%S' if hours <= 1 else '%m-%d %H:%M'
  
    return jsonify({
        'times': [datetime.fromtimestamp(d[0]).strftime(time_fmt) for d in sampled_data],
        'temp': [d[1] for d in sampled_data],
        'util_gpu': [d[2] for d in sampled_data],
        'util_mem': [d[3] for d in sampled_data],
        'mem_used': [d[5] for d in sampled_data],
        'power': [d[6] for d in sampled_data]
    })

if __name__ == '__main__':
    check_environment()
    init_db()
    # 启动后台工作线程
    threading.Thread(target=background_worker, daemon=True).start()
    threading.Thread(target=gpu_worker, daemon=True).start()
    
    if HAS_CERT:
        print(f" * SSL Certificate found, starting HTTPS on port {PORT}")
        app.run(host='0.0.0.0', port=PORT, threaded=True, ssl_context=(cert_file, key_file))
    else:
        print(f" * No SSL Certificate found, starting HTTP on port {PORT}")
        app.run(host='0.0.0.0', port=PORT, threaded=True)
