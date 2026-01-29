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
import io
import zipfile
import csv
import logging
import queue
from logging.handlers import RotatingFileHandler
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
    if HAS_CERT:
        # 检查是否为 https 或者是否有代理头
        is_https = request.is_secure or request.headers.get('X-Forwarded-Proto', '').lower() == 'https'
        if not is_https:
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

# --- 日志配置 ---
def setup_logging():
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # 文件日志 (Rotating 10MB, keep 5 backups)
    file_handler = RotatingFileHandler('app.log', maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
    file_handler.setFormatter(log_formatter)
    file_handler.setLevel(logging.INFO)
    
    # 控制台日志
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    console_handler.setLevel(logging.INFO)
    
    # Root Logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

setup_logging()

# 全局变量：记录上次检测到的时间戳，用于间隔检测
last_audit_check_ts = {}

# --- 异步数据库写入队列 ---
db_write_queue = queue.Queue(maxsize=1000)

def db_writer_worker():
    """专门负责数据库写操作的线程"""
    while True:
        try:
            # 从队列获取任务 (sql, params, callback_event)
            task = db_write_queue.get()
            if task is None: break
            
            sql, params, event = task
            
            # 执行写入
            conn = get_db_connection()
            try:
                if isinstance(sql, list): # 支持批量执行
                    for s, p in zip(sql, params):
                        conn.execute(s, p)
                else:
                    conn.execute(sql, params)
                conn.commit()
            except Exception as e:
                logging.error(f"Async DB Write Error: {e} | SQL: {sql}")
            finally:
                conn.close()
                if event: event.set()
                db_write_queue.task_done()
        except Exception as e:
            logging.error(f"DB Writer Thread Critical Error: {e}")

# 启动写入线程
threading.Thread(target=db_writer_worker, daemon=True).start()

def execute_db_async(sql, params=None, wait=False):
    """将数据库写操作放入队列"""
    event = threading.Event() if wait else None
    try:
        db_write_queue.put((sql, params or (), event), timeout=5)
        if wait: event.wait(timeout=10)
    except queue.Full:
        logging.error("DB Write Queue is FULL! Dropping request.")

def write_audit(level, module, action, message, details=None, operator=None, force_check=False):
    """
    全方位审计日志写入函数
    :param level: INFO/WARN/ERROR/SECURITY
    :param module: AUTH, FAN, SYSTEM, CONFIG, CALIBRATION
    :param action: LOGIN, UPDATE, IMPORT, etc.
    :param message: Human readable message
    :param details: JSON object or dict with technical details
    :param operator: IP address or 'SYSTEM'
    """
    try:
        if operator is None:
            # 尝试自动获取 IP
            try:
                operator = get_client_ip()
            except:
                operator = 'SYSTEM'
        
        # 尝试自动获取 UA
        ua = 'Unknown'
        try:
            ua = request.headers.get('User-Agent', 'Unknown')
        except: 
            pass

        now = int(time.time())
        details_json = json.dumps(details) if details else '{}'
        
        # 1. 写入数据库 (异步)
        sql = '''INSERT INTO audit_logs (timestamp, level, module, operator, action, message, details, ua)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)'''
        params = (now, level, module, operator, action, message, details_json, ua)
        execute_db_async(sql, params)

        # 2. 写入文件日志 (作为备份和调试)
        log_msg = f"[{module}][{action}] {message} | Op: {operator} | Details: {details_json}"
        if level == 'ERROR' or level == 'SECURITY':
            logging.error(log_msg)
        elif level == 'WARN':
            logging.warning(log_msg)
        else:
            logging.info(log_msg)
            
    except Exception as e:
        print(f"CRITICAL LOGGING FAILURE: {e}")

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
    
    # 清理存量 0 值数据 (仅运行一次)
    c.execute("SELECT value FROM config WHERE key='db_zero_cleanup_done'")
    if not c.fetchone():
        print("Cleaning up legacy zero metrics (Lookback repair)...")
        # 查找所有错误的 0 值记录
        c.execute("SELECT timestamp, power_watts, fan_rpm FROM metrics_v2 WHERE power_watts = 0 OR fan_rpm = 0")
        zero_rows = c.fetchall()
        repaired_count = 0
        deleted_count = 0
        
        for row in zero_rows:
            ts, p, f = row
            # 寻找 20s 内的前一个有效点
            c.execute("""SELECT power_watts, fan_rpm FROM metrics_v2 
                         WHERE timestamp < ? AND timestamp >= ? AND power_watts > 0 AND fan_rpm > 0 
                         ORDER BY timestamp DESC LIMIT 1""", (ts, ts - 20))
            prev = c.fetchone()
            
            if prev:
                # 找到前一个有效点，进行修复
                new_p = prev[0] if p == 0 else p
                new_f = prev[1] if f == 0 else f
                c.execute("UPDATE metrics_v2 SET power_watts = ?, fan_rpm = ? WHERE timestamp = ?", (new_p, new_f, ts))
                repaired_count += 1
            else:
                # 没找到（说明采集断裂超过 20s），按逻辑舍弃（删除）
                c.execute("DELETE FROM metrics_v2 WHERE timestamp = ?", (ts,))
                deleted_count += 1
                
        c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('db_zero_cleanup_done', 'true')")
        print(f"Cleanup done. Repaired: {repaired_count}, Deleted (no ref): {deleted_count}")

    # GPU 配置初始化
    c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('gpu_agent_enabled', 'false')")
    c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('gpu_agent_host', '127.0.0.1')")
    c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('gpu_agent_port', '9999')")

    # 耗电量永久化表 (Wh)
    c.execute('''CREATE TABLE IF NOT EXISTS energy_hourly 
                 (timestamp INTEGER PRIMARY KEY, energy_wh REAL, samples INTEGER)''')

    # 全方位审计日志表 (Audit Log)
    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs
                 (timestamp INTEGER, level TEXT, module TEXT, operator TEXT, 
                  action TEXT, message TEXT, details TEXT, ua TEXT)''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_ts ON audit_logs(timestamp)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_module ON audit_logs(module)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_level ON audit_logs(level)')

    # 新增延迟记录表
    c.execute('''CREATE TABLE IF NOT EXISTS recording_intervals (timestamp INTEGER, interval REAL)''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_intervals_ts ON recording_intervals(timestamp)')

    # 初始化延迟色彩阈值
    c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('log_delay_warn', '1.5')")
    c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('log_delay_danger', '5.0')")

    # 数据保留及看板设置初始化
    c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('data_retention_days', '7')")
    c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('pending_retention_days', '0')")
    c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('retention_change_ts', '0')")
    c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('dashboard_hours_hw', '[1, 24]')")
    c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('dashboard_hours_hist', '[1, 6, 24, 72, 168]')")

    # 新增告警规则表
    c.execute('''CREATE TABLE IF NOT EXISTS alert_rules
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  name TEXT, 
                  metric TEXT, 
                  operator TEXT, 
                  threshold REAL, 
                  duration INTEGER, 
                  notify_interval INTEGER,
                  enabled INTEGER DEFAULT 1,
                  level TEXT DEFAULT 'WARN')''')

    # 检查并迁移：为旧表增加 level 字段
    try:
        c.execute("PRAGMA table_info(alert_rules)")
        columns = [col[1] for col in c.fetchall()]
        if 'level' not in columns:
            print("Migration: Adding 'level' column to 'alert_rules' table...")
            c.execute("ALTER TABLE alert_rules ADD COLUMN level TEXT DEFAULT 'WARN'")
    except Exception as e:
        print(f"Migration Error (alert_rules level): {e}")

    # 新增告警状态追踪表 (内存中或DB中，此处选DB以防重启丢失)
    c.execute('''CREATE TABLE IF NOT EXISTS alert_status
                 (rule_id INTEGER PRIMARY KEY,
                  start_ts INTEGER, 
                  last_notify_ts INTEGER,
                  is_alerting INTEGER DEFAULT 0)''')

    # --- 一次性初始化延迟分布数据库逻辑 ---
    c.execute("SELECT value FROM config WHERE key='recording_intervals_init_done'")
    if not c.fetchone():
        print("Initializing recording intervals database from metrics_v2...")
        try:
            # 从 metrics_v2 中重建 recording_intervals 表
            # 获取 metrics_v2 的时间戳，按时间排序
            c.execute("SELECT timestamp FROM metrics_v2 ORDER BY timestamp ASC")
            timestamps = [row[0] for row in c.fetchall()]
            
            if len(timestamps) > 1:
                intervals = []
                for i in range(1, len(timestamps)):
                    gap = timestamps[i] - timestamps[i-1]
                    # 只记录有效的间隔（排除异常大间隔）
                    if gap > 0 and gap <= 300:  # 最大 300s 间隔
                        intervals.append((timestamps[i], gap))
                
                # 批量插入
                c.executemany("INSERT INTO recording_intervals VALUES (?, ?)", intervals)
                print(f"Initialized {len(intervals)} interval records from metrics_v2")
            
            c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('recording_intervals_init_done', 'true')")
            print("Recording intervals initialization completed.")
        except Exception as e:
            print(f"Failed to initialize recording intervals: {e}")
  
    # --- 一次性历史日志迁移逻辑 ---
    c.execute("SELECT value FROM config WHERE key='log_migration_done'")
    if not c.fetchone() and os.path.exists('login_errors.log'):
        print("Migrating legacy login logs to database...")
        try:
            with open('login_errors.log', 'r', encoding='utf-8') as f:
                lines = f.readlines()
                for line in lines:
                    match = re.search(r'\[(.*?)\] IP: (.*?) \| UA: (.*?) \| 失败次数: (.*?) \| 惩罚等待: (.*?)s', line)
                    if match:
                        time_str, ip, ua, count, wait = match.groups()
                        try:
                            # 转换时间字符串为时间戳
                            dt = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
                            ts = int(dt.timestamp())
                            details = json.dumps({'fail_count': int(count), 'wait_time': int(wait)})
                            c.execute('''INSERT INTO audit_logs (timestamp, level, module, operator, action, message, details, ua)
                                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', 
                                      (ts, 'SECURITY', 'AUTH', ip, 'LOGIN_FAIL', f'登录失败 (次数: {count})', details, ua))
                        except Exception as e:
                            print(f"Failed to migrate line: {line.strip()} | Error: {e}")
            
            c.execute("INSERT INTO config (key, value) VALUES ('log_migration_done', 'true')")
            print(f"Successfully migrated {len(lines)} log entries.")
            # 迁移完成后重命名旧文件
            os.rename('login_errors.log', 'login_errors.log.bak')
        except Exception as e:
            print(f"Log migration error: {e}")

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

def get_log_unread_status():
    try:
        # 检查 audit_logs 中是否有新的 ERROR, SECURITY 或 WARN 级别的日志
        # WARN 级别包括异常间隔检测 (DATA_GAP)
        conn = get_db_connection()
        c = conn.cursor()
        
        # 获取上次检查时间
        c.execute("SELECT value FROM config WHERE key='last_log_check'")
        res = c.fetchone()
        last_check = int(res[0]) if res else 0
        
        # 查询是否有更新的警告日志（包括异常间隔）
        c.execute("SELECT COUNT(*) FROM audit_logs WHERE timestamp > ? AND (level='ERROR' OR level='SECURITY' OR level='WARN')", (last_check,))
        count = c.fetchone()[0]
        conn.close()
        
        return count > 0
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
def calculate_energy_consumption(start_ts, end_ts):
    """计算指定时间段内的耗电量 (Wh), 考虑断点"""
    conn = get_db_connection()
    c = conn.cursor()
    # 查询功率数据，按时间排序
    c.execute("SELECT timestamp, power_watts FROM metrics_v2 WHERE timestamp >= ? AND timestamp < ? ORDER BY timestamp ASC", (start_ts, end_ts))
    data = c.fetchall()
    conn.close()
    
    if not data:
        return 0, 0
    
    if len(data) == 1:
        # 只有一个点时，无法积分，但如果区间很短，可以估算
        return 0, 1
    
    total_energy_ws = 0.0 # 瓦秒
    samples = len(data)
    # 扩大容忍度到 120 秒，处理可能的采集缺失
    gap_threshold = 120
    
    # 记录总覆盖时长，用于调试或补偿
    actual_integrated_time = 0
    
    for i in range(len(data) - 1):
        t1, p1 = data[i]
        t2, p2 = data[i+1]
        dt = t2 - t1
        
        # 排除异常 dt (负数或 0)
        if dt <= 0: continue
        
        if dt <= gap_threshold:
            # 梯形积分
            total_energy_ws += (p1 + p2) / 2.0 * dt
            actual_integrated_time += dt
        else:
            # 遇到断点，跳过
            pass
            
    # 如果采集非常密集且几乎覆盖了整个请求区间，但因为前后边界没有对齐导致 actual_integrated_time 略小
    # 我们不使用复杂的 coverage 缩放，而是采用一种更稳健的思路：
    # 如果 actual_integrated_time 超过请求区间 80%，则认为系统一直在线，按平均功率补足边界。
    request_duration = end_ts - start_ts
    if request_duration > 0 and actual_integrated_time > request_duration * 0.8:
        avg_power = total_energy_ws / actual_integrated_time
        total_energy_ws = avg_power * request_duration
            
    return total_energy_ws / 3600.0, samples

def energy_maintenance_task():
    """维护 energy_hourly 表，补全缺失的小时数据，并处理数据保留期变更"""
    while True:
        try:
            now = int(time.time())
            # 当前整点
            current_hour_ts = (now // 3600) * 3600
            
            conn = get_db_connection()
            c = conn.cursor()

            # --- 处理数据保留期变更 (3天反悔期) ---
            c.execute("SELECT value FROM config WHERE key='retention_change_ts'")
            change_ts_row = c.fetchone()
            change_ts = int(change_ts_row[0]) if change_ts_row else 0

            if change_ts > 0 and (now - change_ts) >= (3 * 86400):
                # 3天到期，正式生效
                c.execute("SELECT value FROM config WHERE key='pending_retention_days'")
                pending_row = c.fetchone()
                if pending_row and int(pending_row[0]) > 0:
                    new_val = pending_row[0]
                    c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('data_retention_days', ?)", (new_val,))
                    c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('retention_change_ts', '0')")
                    c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('pending_retention_days', '0')")
                    conn.commit()
                    write_audit('INFO', 'SYSTEM', 'RETENTION_APPLIED', f'数据保留期变更已生效: {new_val} 天', operator='SYSTEM')
            
            # 1. 查找 metrics_v2 中最早的数据时间
            c.execute("SELECT MIN(timestamp) FROM metrics_v2")
            min_ts_row = c.fetchone()
            if not min_ts_row or min_ts_row[0] is None:
                conn.close()
                time.sleep(60)
                continue
            
            first_metrics_ts = (min_ts_row[0] // 3600) * 3600
            
            # 2. 补全从最早数据到上一个整点的数据
            # 我们检查过去 7 天内缺失的小时数据
            start_backfill = max(first_metrics_ts, current_hour_ts - 7 * 86400)
            
            for h_ts in range(start_backfill, current_hour_ts, 3600):
                # 检查是否已存在
                c.execute("SELECT timestamp FROM energy_hourly WHERE timestamp = ?", (h_ts,))
                if not c.fetchone():
                    energy, samples = calculate_energy_consumption(h_ts, h_ts + 3600)
                    if samples > 0:
                        c.execute("INSERT INTO energy_hourly (timestamp, energy_wh, samples) VALUES (?, ?, ?)",
                                 (h_ts, energy, samples))
                        conn.commit()
            
            conn.close()
        except Exception as e:
            print(f"Energy Maintenance Error: {e}")
        
        # 每 10 分钟检查一次（主要是为了跨过整点时能触发上一小时的计算）
        time.sleep(600)

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
            write_audit('INFO', 'CALIBRATION', 'SUCCESS', '风扇校准完成', details={'points': len(calibration_data)})
    except Exception as e:
        sys_cache['calibration']['log'] = f'Err: {str(e)}'
        write_audit('ERROR', 'CALIBRATION', 'FAIL', f'风扇校准失败: {str(e)}')
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
    
    # 记录上一次有效的 IPMI 数据用于容错
    last_valid_hw = {'power': 0, 'fan_rpm': 0, 'timestamp': 0}
    
    # 异常间隔检测：记录上次审计日志时间戳
    global last_audit_check_ts
    last_audit_check_ts['last_check'] = int(time.time())

    # 加载告警状态缓存
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT rule_id, start_ts, last_notify_ts, is_alerting FROM alert_status")
        alert_states = {row['rule_id']: dict(row) for row in cur.fetchall()}
        conn.close()
    except:
        alert_states = {}

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
            
            now = time.time()
            is_hw_invalid = False
            
            # IPMI 容错逻辑：如果 power 或 fan 为 0，尝试使用 20s 内的前一个点，否则标记无效
            if power == 0 or fan_rpm == 0:
                if now - last_valid_hw['timestamp'] < 20 and last_valid_hw['timestamp'] > 0:
                    # 使用前一个有效值补偿
                    if power == 0: power = last_valid_hw['power']
                    if fan_rpm == 0: fan_rpm = last_valid_hw['fan_rpm']
                else:
                    # 超过 20s 或无历史数据，舍弃该时间点
                    is_hw_invalid = True
            else:
                # 数据有效，更新历史记录
                last_valid_hw = {'power': power, 'fan_rpm': fan_rpm, 'timestamp': now}

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
                # 获取数据保留配置
                c.execute("SELECT value FROM config WHERE key='data_retention_days'")
                retention_row = c.fetchone()
                current_retention_days = int(retention_row[0]) if retention_row else RETENTION_DAYS
                
                if not is_hw_invalid:
                    execute_db_async('''INSERT INTO metrics_v2 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                             (int(now), cpu_temp, fan_rpm, power, cpu_u, mem.percent, 
                              net_in/1024, net_out/1024, disk_r/1024/1024, disk_w/1024/1024))
              
                # Cleanup old data (遵循动态设置的 current_retention_days)
                cutoff = int(now) - (current_retention_days * 86400)
                execute_db_async("DELETE FROM metrics_v2 WHERE timestamp < ?", (cutoff,))
                
                # 延迟记录只保留 24 小时
                execute_db_async("DELETE FROM recording_intervals WHERE timestamp < ?", (int(now) - 86400,))
                
                # === 秒级告警规则检测 ===
                c.execute("SELECT * FROM alert_rules WHERE enabled = 1")
                rules = c.fetchall()
                
                # 包含 GPU 数据用于告警检测 (移除 online 判定，只要缓存中有值就检测)
                gpu_m = {}
                with cache_lock:
                    if sys_cache['gpu']['gpus']:
                        # 默认取第一个 GPU 的指标作为告警基准
                        g0 = sys_cache['gpu']['gpus'][0]
                        gpu_m = {
                            'gpu_temp': g0.get('temp', 0),
                            'gpu_util': g0.get('util_gpu', 0),
                            'gpu_mem': g0.get('util_mem', 0)
                        }

                current_metrics = {
                    'cpu_temp': cpu_temp,
                    'fan_rpm': fan_rpm,
                    'power': power,
                    'cpu_usage': cpu_u,
                    'mem_usage': mem.percent,
                    'net_in': net_in/1024,
                    'net_out': net_out/1024,
                    'gpu_temp': gpu_m.get('gpu_temp', 0),
                    'gpu_util': gpu_m.get('gpu_util', 0),
                    'gpu_mem': gpu_m.get('gpu_mem', 0)
                }

                for rule in rules:
                    rid = rule['id']
                    # 获取指标值，如果指标不存在于当前字典中，跳过
                    if rule['metric'] not in current_metrics:
                        continue
                    val = current_metrics[rule['metric']]
                    op = rule['operator']
                    threshold = rule['threshold']
                    
                    is_anomaly = False
                    if op == '>' and val > threshold: is_anomaly = True
                    elif op == '<' and val < threshold: is_anomaly = True
                    elif op == '>=' and val >= threshold: is_anomaly = True
                    elif op == '<=' and val <= threshold: is_anomaly = True
                    elif op == '==' and val == threshold: is_anomaly = True
                    
                    state = alert_states.get(rid, {'rule_id': rid, 'start_ts': 0, 'last_notify_ts': 0, 'is_alerting': 0})
                    
                    if is_anomaly:
                        if state['start_ts'] == 0:
                            state['start_ts'] = int(now)
                        
                        duration_met = (int(now) - state['start_ts']) >= rule['duration']
                        if duration_met:
                            # 达到触发条件
                            can_notify = (int(now) - state['last_notify_ts']) >= rule['notify_interval']
                            if can_notify:
                                # 健壮性获取级别
                                r_level = 'WARN'
                                try:
                                    if 'level' in rule.keys(): r_level = rule['level']
                                except: pass
                                
                                msg = f"告警触发 [{rule['name']}]: {rule['metric']} 当前值 {round(val, 1)} {rule['operator']} {threshold} (持续 {int(now)-state['start_ts']}s)"
                                # 强制写入审计日志
                                write_audit(r_level, 'SYSTEM', 'ALERT_TRIGGER', msg, 
                                           details={'metric': rule['metric'], 'value': val, 'threshold': threshold, 'rule_id': rid},
                                           operator='SYSTEM')
                                state['last_notify_ts'] = int(now)
                                state['is_alerting'] = 1
                                # 打印调试信息
                                print(f"[ALERT] Triggered: {rule['name']} ({val} {rule['operator']} {threshold})")
                    else:
                        if state['is_alerting'] == 1:
                            # 告警恢复
                            write_audit('INFO', 'SYSTEM', 'ALERT_RECOVER', f"告警恢复 [{rule['name']}]: {rule['metric']} 已恢复正常 (当前值 {round(val, 1)})", 
                                       details={'metric': rule['metric'], 'value': val, 'rule_id': rid},
                                       operator='SYSTEM')
                        state['start_ts'] = 0
                        state['is_alerting'] = 0
                    
                    alert_states[rid] = state
                    execute_db_async("INSERT OR REPLACE INTO alert_status (rule_id, start_ts, last_notify_ts, is_alerting) VALUES (?, ?, ?, ?)",
                             (rid, state['start_ts'], state['last_notify_ts'], state['is_alerting']))

                # === 异常间隔检测：检查数据采集是否连续 ===
                current_ts = int(now)
                last_check = last_audit_check_ts.get('last_check', current_ts)
                gap_seconds = current_ts - last_check
                
                # 记录每一个循环的实际延迟到数据库
                execute_db_async("INSERT INTO recording_intervals VALUES (?, ?)", (current_ts, gap_seconds))
                last_db_log_time = now
                
                # 如果间隔超过 2 分钟（120秒），记录异常间隔日志
                if gap_seconds > 120:
                    # 写入异常间隔日志（级别为 WARN，触发小红点刷新）
                    write_audit('WARN', 'SYSTEM', 'DATA_GAP', f'检测到 {gap_seconds} 秒无数据采集区间', 
                               details={'gap_seconds': gap_seconds, 'last_check': last_check, 'current': current_ts},
                               operator='SYSTEM')
                    print(f"[DATA_GAP] Detected gap of {gap_seconds} seconds (last_check: {last_check}, current: {current_ts})")
                
                # 更新最后检查时间戳
                last_audit_check_ts['last_check'] = current_ts
          
            # [关键修复] 显式关闭连接
            conn.close()
          
            elapsed = time.time() - start_time
            time.sleep(max(0.1, 1.0 - elapsed))

        except Exception as e:
            print(f"Worker Error: {e}")
            time.sleep(3)

# GPU 状态追踪变量（用于日志去重，避免重启后重复记录）
gpu_tracking = {
    'was_online': None,  # 上次在线状态
    'has_logged_offline': False,  # 是否已记录过离线日志
    'has_logged_online': False,   # 是否已记录过上线路志
    'last_known_gpus': []  # 最近识别到的 GPU 列表
}

def gpu_worker():
    global gpu_tracking
    last_db_log_time = 0
    retry_delay = 1
    max_retry_delay = 30
    
    # 初始化：检查是否已有历史记录，决定是否需要记录上线日志
    # 如果当前缓存显示在线，且之前没有记录过上线路志，说明是重启恢复
    # 需要在首次成功获取数据后补录上线日志
    with cache_lock:
        current_online = sys_cache['gpu']['online']
        gpu_tracking['was_online'] = current_online
        gpu_tracking['last_known_gpus'] = sys_cache['gpu']['gpus'] or []
    
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
                was_online = gpu_tracking.get('was_online', False)
                # 如果之前是在线状态，现在被关闭
                if was_online:
                    gpus = gpu_tracking.get('last_known_gpus', [])
                    gpu_names = [{'name': g.get('name', 'Unknown'), 'index': g.get('index', 0)} for g in gpus]
                    write_audit('INFO', 'GPU', 'AGENT_STOPPED', '用户主动关闭 GPU 监控', 
                               details={'gpus': gpu_names}, operator='SYSTEM')
                    gpu_tracking['was_online'] = False
                    gpu_tracking['has_logged_offline'] = False
                    gpu_tracking['has_logged_online'] = False
                
                with cache_lock:
                    sys_cache['gpu']['online'] = False
                    sys_cache['gpu']['gpus'] = []
                time.sleep(5)
                continue

            # 请求 Agent
            url = f"http://{host}:{port}/metrics"
            try:
                with urllib.request.urlopen(url, timeout=3) as response:
                    data = json.loads(response.read().decode())
                    if 'error' in data:
                        raise Exception(data['error'])
                    
                    current_gpus = data.get('gpus', [])
                    
                    with cache_lock:
                        sys_cache['gpu']['online'] = True
                        sys_cache['gpu']['gpus'] = current_gpus
                        sys_cache['gpu']['last_update'] = int(time.time())
                        sys_cache['gpu']['retry_delay'] = 1
                    
                    retry_delay = 1 # 成功后重置延迟
                    
                    # === 状态变更检测与日志记录 ===
                    was_online = gpu_tracking.get('was_online', False)
                    
                    # 1. 上线检测：从离线变为在线
                    if not was_online:
                        # 如果之前没有记录过上线路志（或者是首次启动/重启恢复）
                        if not gpu_tracking.get('has_logged_online', False):
                            gpu_names = [{'name': g.get('name', 'Unknown'), 'index': g.get('index', 0)} for g in current_gpus]
                            write_audit('INFO', 'GPU', 'AGENT_ONLINE', 'GPU Agent 已上线', 
                                       details={'gpus': gpu_names}, operator='SYSTEM')
                            gpu_tracking['has_logged_online'] = True
                            gpu_tracking['has_logged_offline'] = False
                    
                    # 更新追踪状态
                    gpu_tracking['was_online'] = True
                    gpu_tracking['last_known_gpus'] = current_gpus
                    
                    # 记录历史数据 (1s一次)
                    now = time.time()
                    if now - last_db_log_time >= 1.0:
                        # 批量执行优化
                        sqls = []
                        all_params = []
                        for g in current_gpus:
                            sqls.append('''INSERT INTO gpu_metrics VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''')
                            all_params.append((int(now), g['index'], g['name'], g['temp'], 
                                      g['util_gpu'], g['util_mem'], g['memory_total'], g['memory_used'],
                                      g['power_draw'], g['power_limit'], g['clock_core'], g['clock_mem'], 
                                      g['fan_speed'], g['ecc_errors']))
                        
                        # 清理旧数据 (遵循 RETENTION_DAYS)
                        cutoff = int(now) - (RETENTION_DAYS * 86400)
                        sqls.append("DELETE FROM gpu_metrics WHERE timestamp < ?")
                        all_params.append((cutoff,))
                        
                        execute_db_async(sqls, all_params)
                        last_db_log_time = now
                
                elapsed = time.time() - start_time
                time.sleep(max(0.1, 1.0 - elapsed))

            except Exception as e:
                # === 离线检测：从在线变为离线 ===
                was_online = gpu_tracking.get('was_online', False)
                if was_online and not gpu_tracking.get('has_logged_offline', False):
                    # 记录离线日志
                    gpus = gpu_tracking.get('last_known_gpus', [])
                    gpu_names = [{'name': g.get('name', 'Unknown'), 'index': g.get('index', 0)} for g in gpus]
                    write_audit('WARN', 'GPU', 'AGENT_OFFLINE', 'GPU Agent 离线', 
                               details={'gpus': gpu_names}, operator='SYSTEM')
                    gpu_tracking['has_logged_offline'] = True
                    gpu_tracking['has_logged_online'] = False
                
                gpu_tracking['was_online'] = False
                
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
            
            write_audit('INFO', 'AUTH', 'LOGIN_SUCCESS', '用户登录成功', operator=ip)
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
            
            # 记录审计日志
            write_audit('SECURITY', 'AUTH', 'LOGIN_FAIL', f'登录失败 (次数: {fail_count})', 
                       details={'fail_count': fail_count, 'wait_time': wait_current}, operator=ip)
            
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

@app.route('/api/audit_logs')
@login_required
def api_audit_logs():
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))
    module = request.args.get('module')
    level = request.args.get('level')
    search = request.args.get('search')
    
    conn = get_db_connection()
    c = conn.cursor()
    
    query = "SELECT * FROM audit_logs WHERE 1=1"
    params = []
    
    if module:
        query += " AND module = ?"
        params.append(module)
    if level:
        query += " AND level = ?"
        params.append(level)
    if search:
        query += " AND (message LIKE ? OR action LIKE ? OR operator LIKE ?)"
        wildcard = f"%{search}%"
        params.extend([wildcard, wildcard, wildcard])
        
    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    c.execute(query, params)
    rows = c.fetchall()
    
    # Get total count for pagination
    count_query = "SELECT COUNT(*) FROM audit_logs WHERE 1=1"
    count_params = []
    if module:
        count_query += " AND module = ?"
        count_params.append(module)
    if level:
        count_query += " AND level = ?"
        count_params.append(level)
    if search:
        count_query += " AND (message LIKE ? OR action LIKE ? OR operator LIKE ?)"
        wildcard = f"%{search}%"
        count_params.extend([wildcard, wildcard, wildcard])
        
    c.execute(count_query, count_params)
    total = c.fetchone()[0]
    conn.close()
    
    logs = []
    for row in rows:
        logs.append({
            'timestamp': row['timestamp'],
            'time_str': datetime.fromtimestamp(row['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
            'level': row['level'],
            'module': row['module'],
            'operator': row['operator'],
            'action': row['action'],
            'message': row['message'],
            'details': json.loads(row['details']) if row['details'] else {},
            'ua': row['ua']
        })
        
    return jsonify({
        'total': total,
        'logs': logs
    })

@app.route('/api/config/precheck', methods=['POST'])
@login_required
def api_config_precheck():
    try:
        new_config = request.json
        if not new_config or 'settings' not in new_config:
            return jsonify({'error': '无效的配置文件'}), 400
            
        conn = get_db_connection()
        c = conn.cursor()
        
        # 获取当前设置
        c.execute("SELECT key, value FROM config")
        current_rows = c.fetchall()
        current_settings = {row['key']: row['value'] for row in current_rows}
        
        # 获取当前告警规则 (加上 level 字段，防止报错)
        try:
            c.execute("SELECT name, metric, operator, threshold, duration, notify_interval, enabled, level FROM alert_rules")
        except:
            c.execute("SELECT name, metric, operator, threshold, duration, notify_interval, enabled FROM alert_rules")
        current_alerts = [dict(row) for row in c.fetchall()]
        conn.close()
        
        diffs = []
        new_settings = new_config.get('settings', {})
        
        # 1. 对比设置
        all_keys = set(list(current_settings.keys()) + list(new_settings.keys()))
        # 过滤掉一些不该被导入覆盖的内部状态键
        ignore_keys = {'last_log_check', 'db_zero_cleanup_done', 'recording_intervals_init_done', 'log_migration_done', 'retention_change_ts', 'pending_retention_days'}
        
        for k in all_keys:
            if k in ignore_keys: continue
            
            old_v_raw = current_settings.get(k)
            new_v_raw = new_settings.get(k)
            
            # 智能对比逻辑：统一归一化，解决 6.0 vs 6 等问题
            def normalize_val(v):
                if v is None: return None
                # 统一布尔值表示 (解决 true vs 1)
                if v is True or v == "true": return True
                if v is False or v == "false": return False
                # 尝试转为数值
                try:
                    f = float(v)
                    return f
                except: pass
                # 尝试解析 JSON
                if isinstance(v, str):
                    try:
                        parsed = json.loads(v)
                        # 递归归一化解析后的内容（处理 JSON 字符串里的布尔值/数值）
                        if isinstance(parsed, (dict, list, bool, int, float)):
                            return normalize_val(parsed)
                        return parsed
                    except:
                        return v.strip()
                return v

            old_norm = normalize_val(old_v_raw)
            new_norm = normalize_val(new_v_raw)
            
            # 最终对比逻辑
            def are_equal(v1, v2):
                if v1 is v2: return True
                # 处理数值精度问题 (6.0 == 6)
                if isinstance(v1, (int, float)) and isinstance(v2, (int, float)):
                    return abs(v1 - v2) < 0.000001
                # 处理列表/字典
                if type(v1) != type(v2): return False
                if isinstance(v1, (dict, list)):
                    return json.dumps(v1, sort_keys=True) == json.dumps(v2, sort_keys=True)
                return v1 == v2

            changed = not are_equal(old_norm, new_norm) if new_v_raw is not None else False

            # 序列化用于前端展示：确保样式一致
            def get_show_val(norm):
                if norm is None: return "-"
                if isinstance(norm, (dict, list)): 
                    return json.dumps(norm, separators=(',', ':'))
                if norm is True: return "true"
                if norm is False: return "false"
                # 数值统一格式
                if isinstance(norm, (int, float)):
                    return str(int(norm) if norm == int(norm) else round(norm, 2))
                return str(norm)

            diffs.append({
                'type': 'setting',
                'key': k,
                'old': get_show_val(old_norm),
                'new': get_show_val(new_norm),
                'changed': changed
            })

        # 2. 对比告警规则 (深度比对，解决数值类型与默认值偏差)
        new_alerts = new_config.get('alert_rules', [])
        alert_diffs = []
        
        # 定义核心比对函数
        def are_rules_different(v1, v2, field):
            # 特殊处理 level：如果一方为 None/null 且另一方为 WARN，视为一致 (处理迁移引起的差异)
            if field == 'level':
                v1_clean = str(v1 or 'WARN').strip().upper()
                v2_clean = str(v2 or 'WARN').strip().upper()
                return v1_clean != v2_clean
            
            if v1 is None or v2 is None:
                return v1 != v2
                
            # 尝试数值比对 (处理 0 vs 0.0, 600 vs 600.0)
            try:
                f1, f2 = float(v1), float(v2)
                return abs(f1 - f2) > 0.000001
            except (ValueError, TypeError):
                # 文本比对
                return str(v1).strip() != str(v2).strip()

        # 创建待匹配池副本，支持同名规则消费
        alerts_pool = list(current_alerts)

        for na in new_alerts:
            # 寻找同名规则 (优先匹配完全一致的，其次匹配名字相同的)
            existing_idx = -1
            
            # 第一轮：寻找名称且所有关键字段都完全一致的规则 (避免同名顺序打乱导致的误报)
            def is_perfect_match(na, ca):
                if na['name'] != ca['name']: return False
                for f in ['metric', 'operator', 'threshold', 'duration', 'notify_interval', 'level']:
                    if are_rules_different(ca.get(f), na.get(f), f): return False
                return True

            for i, ca in enumerate(alerts_pool):
                if is_perfect_match(na, ca):
                    existing_idx = i
                    break
            
            # 第二轮：如果没找到完美的，则按名称找第一个
            if existing_idx == -1:
                for i, ca in enumerate(alerts_pool):
                    if ca['name'] == na['name']:
                        existing_idx = i
                        break

            params_changed = []
            existing = None
            if existing_idx != -1:
                existing = alerts_pool.pop(existing_idx) # 从池中消费掉
                
                # 检查所有关键字段
                for field in ['metric', 'operator', 'threshold', 'duration', 'notify_interval', 'level']:
                    ev = existing.get(field)
                    nv = na.get(field)
                    
                    if are_rules_different(ev, nv, field):
                        params_changed.append({
                            'field': field, 
                            'old': str(ev) if ev is not None else 'null', 
                            'new': str(nv) if nv is not None else 'null'
                        })

            # 只有当规则真正发生变化，或者数据库中完全没有此规则时，才标记为 changed
            is_new = existing is None
            has_real_changes = len(params_changed) > 0
            
            alert_diffs.append({
                'type': 'alert',
                'name': na['name'],
                'is_new': is_new,
                'changed': is_new or has_real_changes,
                'params_changed': params_changed,
                'data': na
            })
            
        metadata = new_config.get('metadata', {})
        return jsonify({
            'version': metadata.get('version', 1),
            'export_time': metadata.get('export_time', '未知'),
            'software_version': metadata.get('software_version', '未知'),
            'diffs': diffs,
            'alerts': alert_diffs
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alert_rules', methods=['GET', 'POST', 'DELETE'])
@login_required
def api_alert_rules():
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == 'GET':
        c.execute("SELECT * FROM alert_rules")
        res = [dict(row) for row in c.fetchall()]
        conn.close()
        return jsonify(res)
    
    if request.method == 'POST':
        try:
            data = request.json
            if 'id' in data:
                # 更新 (包含新增的 level 字段)
                c.execute('''UPDATE alert_rules SET name=?, metric=?, operator=?, threshold=?, duration=?, notify_interval=?, enabled=?, level=?
                             WHERE id=?''', 
                          (data['name'], data['metric'], data['operator'], data['threshold'], data['duration'], data['notify_interval'], data['enabled'], data.get('level', 'WARN'), data['id']))
            else:
                # 新增 (包含新增的 level 字段)
                c.execute('''INSERT INTO alert_rules (name, metric, operator, threshold, duration, notify_interval, enabled, level)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                          (data['name'], data['metric'], data['operator'], data['threshold'], data['duration'], data['notify_interval'], 1, data.get('level', 'WARN')))
            conn.commit()
            return jsonify({'status': 'success'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        finally:
            conn.close()

    if request.method == 'DELETE':
        try:
            rule_id = request.args.get('id')
            c.execute("DELETE FROM alert_rules WHERE id=?", (rule_id,))
            c.execute("DELETE FROM alert_status WHERE rule_id=?", (rule_id,))
            conn.commit()
            return jsonify({'status': 'success'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        finally:
            conn.close()

@app.route('/api/settings', methods=['GET', 'POST'])
@login_required
def api_settings():
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == 'GET':
        keys = ('log_delay_warn', 'log_delay_danger', 'data_retention_days', 
                'pending_retention_days', 'retention_change_ts', 
                'dashboard_hours_hw', 'dashboard_hours_hist')
        c.execute(f"SELECT key, value FROM config WHERE key IN {keys}")
        res = {row['key']: row['value'] for row in c.fetchall()}
        conn.close()
        
        # 格式化处理
        for k in ('log_delay_warn', 'log_delay_danger'):
            res[k] = float(res.get(k, 1.5 if 'warn' in k else 5.0))
        for k in ('data_retention_days', 'pending_retention_days', 'retention_change_ts'):
            res[k] = int(res.get(k, 0))
            if k == 'data_retention_days' and res[k] == 0: res[k] = 7
        for k in ('dashboard_hours_hw', 'dashboard_hours_hist'):
            try: res[k] = json.loads(res.get(k, '[]'))
            except: res[k] = []
            
        # 获取数据库文件大小 (字节)
        try:
            db_size = os.path.getsize(DB_FILE)
            res['db_size_bytes'] = db_size
        except:
            res['db_size_bytes'] = 0
            
        return jsonify(res)

    if request.method == 'POST':
        try:
            data = request.json
            now = int(time.time())
            
            # 获取当前所有配置用于对比，避免刷写未修改的项
            c.execute("SELECT key, value FROM config")
            current_configs = {row['key']: row['value'] for row in c.fetchall()}
            
            # 辅助函数：判断是否真正改变（改进版：处理数值精度和数组顺序问题）
            def is_changed(key, new_val):
                if key not in current_configs: return True
                old_val = current_configs[key]
                
                # 统一归一化函数
                def normalize(v):
                    if v is None: return None
                    # 布尔值
                    if v is True or v == "true": return "true"
                    if v is False or v == "false": return "false"
                    # 数值类型：处理 7.0 == 7 问题
                    if isinstance(v, (int, float)):
                        # 转字符串时去掉无意义的小数点
                        if v == int(v): return str(int(v))
                        return str(float(v))
                    # 数组/字典：排序后转 JSON
                    if isinstance(v, str):
                        try:
                            parsed = json.loads(v)
                            return normalize(parsed)
                        except:
                            return v.strip()
                    if isinstance(v, (list, dict)):
                        return json.dumps(v, sort_keys=True)
                    return str(v)
                
                old_norm = normalize(old_val)
                new_norm = normalize(new_val)
                
                # 数组排序后比较顺序
                if old_norm != new_norm:
                    # 额外处理：对于 JSON 数组，比较排序后的结果
                    if old_norm.startswith('[') and new_norm.startswith('['):
                        try:
                            old_arr = json.loads(old_norm)
                            new_arr = json.loads(new_norm)
                            if sorted(old_arr) == sorted(new_arr):
                                return False
                        except:
                            pass
                    return True
                return False

            # 处理保留期变更 (带反悔期逻辑)
            if 'data_retention_days' in data:
                new_val = int(data['data_retention_days'])
                c.execute("SELECT value FROM config WHERE key='data_retention_days'")
                curr_val_res = c.fetchone()
                curr_val = int(curr_val_res[0]) if curr_val_res else 7
                
                if new_val < curr_val:
                    # 缩短，进入反悔期
                    c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('pending_retention_days', ?)", (str(new_val),))
                    c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('retention_change_ts', ?)", (str(now),))
                    write_audit('WARN', 'SYSTEM', 'RETENTION_PENDING', f'计划缩短数据保留期至 {new_val} 天 (3天内可撤销)', operator=get_client_ip())
                else:
                    # 延长或不变，立即生效并取消 pending
                    c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('data_retention_days', ?)", (str(new_val),))
                    c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('pending_retention_days', '0')")
                    c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('retention_change_ts', '0')")
                    write_audit('INFO', 'SYSTEM', 'RETENTION_UPDATE', f'更新数据保留期为 {new_val} 天', operator=get_client_ip())

            # 处理其它简单设置 (仅在变化时更新)
            if 'log_delay_warn' in data:
                val = str(float(data['log_delay_warn']))
                if is_changed('log_delay_warn', val):
                    c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('log_delay_warn', ?)", (val,))
            if 'log_delay_danger' in data:
                val = str(float(data['log_delay_danger']))
                if is_changed('log_delay_danger', val):
                    c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('log_delay_danger', ?)", (val,))
            if 'dashboard_hours_hw' in data:
                val = json.dumps(data['dashboard_hours_hw'])
                if is_changed('dashboard_hours_hw', val):
                    c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('dashboard_hours_hw', ?)", (val,))
            if 'dashboard_hours_hist' in data:
                val = json.dumps(data['dashboard_hours_hist'])
                if is_changed('dashboard_hours_hist', val):
                    c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('dashboard_hours_hist', ?)", (val,))

            # 批量处理告警规则：完整处理新增、更新、删除
            if 'alert_rules' in data and isinstance(data['alert_rules'], list):
                # 1. 获取前端发来的所有规则 ID
                frontend_ids = set()
                for rule in data['alert_rules']:
                    if 'id' in rule:
                        frontend_ids.add(int(rule['id']))
                
                # 2. 获取数据库中当前的所有规则 ID
                c.execute("SELECT id FROM alert_rules")
                db_ids = {row['id'] for row in c.fetchall()}
                
                # 3. 计算需要删除的 ID（数据库有但前端没有的）
                ids_to_delete = db_ids - frontend_ids
                
                # 4. 执行更新和新增
                sqls = []
                all_params = []
                for rule in data['alert_rules']:
                    if 'id' in rule:
                        # 更新现有规则
                        sqls.append('''UPDATE alert_rules SET name=?, metric=?, operator=?, threshold=?, duration=?, notify_interval=?, enabled=?, level=?
                                     WHERE id=?''')
                        all_params.append((rule['name'], rule['metric'], rule['operator'], rule['threshold'], rule['duration'], rule['notify_interval'], rule['enabled'], rule.get('level', 'WARN'), rule['id']))
                    else:
                        # 新增规则（没有 id）
                        sqls.append('''INSERT INTO alert_rules (name, metric, operator, threshold, duration, notify_interval, enabled, level)
                                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''')
                        all_params.append((rule['name'], rule['metric'], rule['operator'], rule['threshold'], rule['duration'], rule['notify_interval'], rule['enabled'], rule.get('level', 'WARN')))
                
                # 5. 执行删除（使用 DELETE FROM alert_status）
                for del_id in ids_to_delete:
                    sqls.append("DELETE FROM alert_rules WHERE id=?")
                    all_params.append((del_id,))
                    sqls.append("DELETE FROM alert_status WHERE rule_id=?")
                    all_params.append((del_id,))
                
                if sqls:
                    execute_db_async(sqls, all_params, wait=True) # 等待完成以确保后续读操作正确
            
            conn.commit()
            return jsonify({'status': 'success'})
        except Exception as e:
            if conn: conn.rollback()
            return jsonify({'error': str(e)}), 500
        finally:
            conn.close()

@app.route('/api/log_delay_config', methods=['GET', 'POST'])
@login_required
def api_log_delay_config():
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == 'GET':
        c.execute("SELECT key, value FROM config WHERE key IN ('log_delay_warn', 'log_delay_danger')")
        res = {row['key']: float(row['value']) for row in c.fetchall()}
        conn.close()
        # 补全缺失值
        if 'log_delay_warn' not in res: res['log_delay_warn'] = 1.5
        if 'log_delay_danger' not in res: res['log_delay_danger'] = 5.0
        return jsonify(res)
    
    if request.method == 'POST':
        try:
            data = request.json
            if 'log_delay_warn' in data:
                c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('log_delay_warn', ?)", (str(float(data['log_delay_warn'])),))
            if 'log_delay_danger' in data:
                c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('log_delay_danger', ?)", (str(float(data['log_delay_danger'])),))
            conn.commit()
            write_audit('INFO', 'CONFIG', 'UPDATE_DELAY', '更新采集延迟阈值', details=data, operator=get_client_ip())
            return jsonify({'status': 'success'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        finally:
            conn.close()

@app.route('/api/config/export')
@login_required
def api_config_export():
    """
    导出完整配置快照
    [开发者注意]：
    1. 每次增加或修改 config 表的 key，或修改 alert_rules 表结构时，需考虑是否需要提升 metadata.version。
    2. 提升版本号后，需在导入逻辑 (api_config_import/api_config_precheck) 中保持向下兼容。
    3. 当前版本 4: 包含所有 config 项、告警规则（含 level）、导出时间文本。
    """
    conn = get_db_connection()
    c = conn.cursor()
    # 确保导出所有的配置项 (config 表)
    c.execute("SELECT key, value FROM config")
    config_rows = c.fetchall()
    
    settings = {}
    for row in config_rows:
        try:
            # 尝试解析 JSON 值，如果不是 JSON 则按字符串存储
            settings[row['key']] = json.loads(row['value'])
        except:
            settings[row['key']] = row['value']

    # 导出告警规则 (包含新增的 level 字段)
    c.execute("SELECT name, metric, operator, threshold, duration, notify_interval, enabled, level FROM alert_rules")
    alert_rules = [dict(row) for row in c.fetchall()]
    conn.close()
            
    now_ts = int(time.time())
    export_data = {
        "metadata": {
            "version": 4, # 提升至版本 4
            "timestamp": now_ts,
            "export_time": datetime.fromtimestamp(now_ts).strftime('%Y-%m-%d %H:%M:%S'),
            "export_by": get_client_ip(),
            "server_name": SERVER_NAME,
            "software_version": "1.2.0" # 建议此处记录当前软件版本号
        },
        "settings": settings,
        "alert_rules": alert_rules
    }
    
    # Audit log
    write_audit('INFO', 'CONFIG', 'EXPORT', '导出系统配置', operator=get_client_ip())
    
    return jsonify(export_data)

@app.route('/api/config/import', methods=['POST'])
@login_required
def api_config_import():
    """
    执行配置导入
    [向下兼容说明]：
    - 版本 3 及以下：可能缺少 export_time，且告警规则可能缺少 level。
    - 版本 4：包含 level 字段及完整 metadata。
    - 逻辑：遍历 settings 键值对，若 config 表中已存在则更新，不存在则忽略（防止版本跨度过大导致无效键污染）。
    """
    try:
        data = request.json
        if not data or 'metadata' not in data or 'settings' not in data:
            return jsonify({'error': '无效的配置文件格式'}), 400
            
        settings = data['settings']
        version = data['metadata'].get('version', 0)
        
        # 记录变更详情
        changes = []
        
        conn = get_db_connection()
        c = conn.cursor()
        
        # 遍历设置并更新
        for key, value in settings.items():
            # 获取旧值用于对比
            c.execute("SELECT value FROM config WHERE key=?", (key,))
            old_row = c.fetchone()
            old_val = old_row['value'] if old_row else None
            
            # 将值转回字符串存储
            new_val_str = json.dumps(value) if isinstance(value, (dict, list, bool, int, float)) else str(value)
            
            # 简单对比 (字符串层面)
            if old_val != new_val_str:
                changes.append(f"{key}: {old_val} -> {new_val_str}")
                c.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", (key, new_val_str))
        
        conn.commit()
        conn.close()
        
        # 刷新缓存
        load_calibration_map()
        
        write_audit('WARN', 'CONFIG', 'IMPORT', '导入系统配置', 
                   details={'version': version, 'changes_count': len(changes), 'changes': changes},
                   operator=get_client_ip())
        
        return jsonify({'status': 'success', 'changes': len(changes)})
        
    except Exception as e:
        write_audit('ERROR', 'CONFIG', 'IMPORT_FAIL', f'配置导入失败: {str(e)}')
        return jsonify({'error': str(e)}), 500

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

@app.route('/api/export_data')
@login_required
def api_export_data():
    conn = get_db_connection()
    c = conn.cursor()
    
    # 导出 metrics_v2
    c.execute("SELECT * FROM metrics_v2 ORDER BY timestamp ASC")
    metrics_rows = c.fetchall()
    metrics_cols = [description[0] for description in c.description]
    
    # 导出 energy_hourly
    c.execute("SELECT * FROM energy_hourly ORDER BY timestamp ASC")
    energy_rows = c.fetchall()
    energy_cols = [description[0] for description in c.description]
    
    # 导出 recording_intervals
    c.execute("SELECT * FROM recording_intervals ORDER BY timestamp ASC")
    interval_rows = c.fetchall()
    interval_cols = [description[0] for description in c.description]
    
    # 导出 gpu_metrics
    c.execute("SELECT * FROM gpu_metrics ORDER BY timestamp ASC")
    gpu_rows = c.fetchall()
    gpu_cols = [description[0] for description in c.description]
    
    conn.close()

    # 创建内存 ZIP 文件
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        # 写入 metrics_history.csv
        metrics_csv = io.StringIO()
        writer = csv.writer(metrics_csv)
        writer.writerow(metrics_cols)
        writer.writerows(metrics_rows)
        zf.writestr('metrics_history.csv', metrics_csv.getvalue())
        
        # 写入 energy_persistence.csv
        energy_csv = io.StringIO()
        writer = csv.writer(energy_csv)
        writer.writerow(energy_cols)
        writer.writerows(energy_rows)
        zf.writestr('energy_persistence.csv', energy_csv.getvalue())
        
        # 写入 recording_intervals.csv
        interval_csv = io.StringIO()
        writer = csv.writer(interval_csv)
        writer.writerow(interval_cols)
        writer.writerows(interval_rows)
        zf.writestr('recording_intervals.csv', interval_csv.getvalue())

        # 写入 gpu_history.csv
        if gpu_rows:
            gpu_csv = io.StringIO()
            writer = csv.writer(gpu_csv)
            writer.writerow(gpu_cols)
            writer.writerows(gpu_rows)
            zf.writestr('gpu_history.csv', gpu_csv.getvalue())

    memory_file.seek(0)
    filename = f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    
    from flask import send_file
    return send_file(
        memory_file,
        mimetype='application/zip',
        as_attachment=True,
        download_name=filename
    )

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
    
    if not data:
        return jsonify({'times': [], 'hw': {'temps': [], 'fans': [], 'power': []}, 'res': {'cpu': [], 'mem': [], 'net_in': [], 'net_out': [], 'disk_r': [], 'disk_w': []}})
    
    # [关键修复] 数据降采样：防止返回几万个点卡死前端
    # 目标：限制在 600 个点以内
    step = max(1, len(data) // 600)
    sampled_data = data[::step]

    # [优化断点显示] 统一 2min 宽容断点逻辑
    final_data = []
    # 绝对断裂阈值 (秒) - 设定为 2 分钟，防止负载波动漏点，反映真实断电
    ABSOLUTE_GAP_LIMIT = 120 
    
    for i in range(len(sampled_data)):
        if i > 0:
            prev_ts = sampled_data[i-1][0]
            curr_ts = sampled_data[i][0]
            if curr_ts - prev_ts > max(ABSOLUTE_GAP_LIMIT, step * 5):
                # 插入一个 null 数据点，时间戳取中间，各字段设为 None
                final_data.append(( (prev_ts + curr_ts) // 2, None, None, None, None, None, None, None, None, None))
        
        final_data.append(sampled_data[i])

    return jsonify({
        'times': [datetime.fromtimestamp(d[0]).strftime('%H:%M') for d in final_data],
        'hw': {'temps': [round(d[1],1) if d[1] is not None else None for d in final_data], 
                'fans': [d[2] for d in final_data], 
                'power': [d[3] for d in final_data]},
        'res': {'cpu': [round(d[4],1) if d[4] is not None else None for d in final_data], 
                'mem': [round(d[5],1) if d[5] is not None else None for d in final_data], 
                'net_in': [round(d[6],1) if d[6] is not None else None for d in final_data], 
                'net_out': [round(d[7],1) if d[7] is not None else None for d in final_data],
                'disk_r': [round(d[8],1) if d[8] is not None else None for d in final_data], 
                'disk_w': [round(d[9],1) if d[9] is not None else None for d in final_data]}
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
  
    # [优化断点显示] 更加宽容的断点检测
    # 核心思路：步进采样本身就会拉大点距。只有当两点间距远大于步长 *且* 大于一个绝对阈值（10分钟）时，才判定为关机/断电
    final_data = []
    
    # 绝对断裂阈值 (秒) - 设定为 2 分钟，只有较长时间失联才断开，解决 CPU 满载漏点问题
    ABSOLUTE_GAP_LIMIT = 120 
    
    for i in range(len(sampled_data)):
        if i > 0:
            prev_ts = sampled_data[i-1][0]
            curr_ts = sampled_data[i][0]
            
            # 判断逻辑：不仅要超过 step 的倍数，还要超过 ABSOLUTE_GAP_LIMIT
            # 这样在 7D 视图下 (step 较大)，普通的小抖动会被 step 本身覆盖，不会误判
            if curr_ts - prev_ts > max(ABSOLUTE_GAP_LIMIT, step * 10):
                # 插入一个 null 数据点，时间戳取中间，各字段设为 None
                # 前端 Chart.js 会识别并断开连线
                final_data.append(( (prev_ts + curr_ts) // 2, None, None, None, None, None, None, None, None, None))
        
        final_data.append(sampled_data[i])

    # 对齐 GPU 数据到系统数据的时间轴
    aligned_gpu = {
        'temp': [], 'util_gpu': [], 'util_mem': [], 'mem_used': [], 'power': []
    }
    
    last_gpu_idx = 0
    gpu_len = len(gpu_raw)
    
    for d in final_data:
        ts = d[0]
        # 如果是断点占位符
        if d[1] is None:
            for k in aligned_gpu: aligned_gpu[k].append(None)
            continue
            
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

    # 耗电量统计 (Wh)
    # 1. 区间耗电: 直接利用当前已查出的原始功率数据 (raw_data) 进行实时积分，保证 1H/6H 等视图的精确性
    # 因为 raw_data 本身就是 cutoff 之后的数据
    interval_energy_wh = 0.0
    if len(raw_data) >= 2:
        # 复用计算逻辑，但直接针对本次查询出的 raw_data
        temp_ws = 0.0
        gap_limit = 120
        for i in range(len(raw_data) - 1):
            t1, _, _, p1, _, _, _, _, _, _ = raw_data[i]
            t2, _, _, p2, _, _, _, _, _, _ = raw_data[i+1]
            dt = t2 - t1
            if 0 < dt <= gap_limit:
                temp_ws += (p1 + p2) / 2.0 * dt
        
        # 边界补齐逻辑
        actual_dur = raw_data[-1][0] - raw_data[0][0]
        req_dur = int(time.time()) - cutoff
        if req_dur > 0 and actual_dur > req_dur * 0.8:
            interval_energy_wh = (temp_ws / actual_dur * req_dur) / 3600.0
        else:
            interval_energy_wh = temp_ws / 3600.0

    # 2. 累计耗电 (支持自定义起始时间)
    current_hour_ts = (int(time.time()) // 3600) * 3600
    conn = get_db_connection()
    c = conn.cursor()
    
    # 获取最早的记录时间
    c.execute("SELECT MIN(timestamp) FROM energy_hourly")
    abs_min_row = c.fetchone()
    abs_min_ts = abs_min_row[0] if abs_min_row and abs_min_row[0] is not None else current_hour_ts
    
    energy_start_ts = int(request.args.get('energy_start', 0))
    if energy_start_ts == 0:
        energy_start_ts = abs_min_ts

    c.execute("SELECT SUM(energy_wh) FROM energy_hourly WHERE timestamp >= ?", (energy_start_ts,))
    row = c.fetchone()
    total_energy_wh = row[0] if row and row[0] is not None else 0.0
    # 加上最新的
    if current_hour_ts >= energy_start_ts:
        latest_energy_all, _ = calculate_energy_consumption(max(energy_start_ts, current_hour_ts), int(time.time()))
        total_energy_wh += latest_energy_all
    
    conn.close()
    
    # 转换为 kWh
    stats['energy_interval'] = round(interval_energy_wh / 1000.0, 3)
    stats['energy_total'] = round(total_energy_wh / 1000.0, 3)
    stats['energy_start_date'] = datetime.fromtimestamp(energy_start_ts).strftime('%Y-%m-%d')
    stats['energy_earliest_date'] = datetime.fromtimestamp(abs_min_ts).strftime('%Y-%m-%d')

    return jsonify({
        'times': [datetime.fromtimestamp(d[0]).strftime(time_fmt) for d in final_data],
        'cpu_temp': [round(d[1],1) if d[1] is not None else None for d in final_data],
        'fan_rpm': [d[2] for d in final_data],
        'power': [d[3] for d in final_data],
        'cpu_load': [round(d[4],1) if d[4] is not None else None for d in final_data],
        'mem_load': [round(d[5],1) if d[5] is not None else None for d in final_data],
        'net_in': [round(d[6],1) if d[6] is not None else None for d in final_data],
        'net_out': [round(d[7],1) if d[7] is not None else None for d in final_data],
        'disk_r': [round(d[8],1) if d[8] is not None else None for d in final_data],
        'disk_w': [round(d[9],1) if d[9] is not None else None for d in final_data],
        'gpu': aligned_gpu, # 直接包含对齐后的 GPU 数据
        'stats': stats
    })

# --- 深度分析接口 (支持懒加载，全量秒级聚合) ---
@app.route('/api/insights')
@login_required
def api_insights():
    hours = int(request.args.get('hours', 24))
    conn = get_db_connection()
    c = conn.cursor()
    cutoff = int(time.time() - (hours * 3600))
    
    # 获取全量原始数据进行精准分析
    c.execute("SELECT timestamp, cpu_temp, power_watts, cpu_usage FROM metrics_v2 WHERE timestamp > ? ORDER BY timestamp ASC", (cutoff,))
    raw_data = c.fetchall()
    
    c.execute("SELECT timestamp, temp, util_gpu, util_mem, power FROM gpu_metrics WHERE timestamp > ? ORDER BY timestamp ASC", (cutoff,))
    gpu_raw = c.fetchall()
    conn.close()
    
    analysis = {
        'cpu_power_avg': 0, 'gpu_power_avg': 0,
        'cpu_temp_labels': [], 'cpu_temp_dist': [], 
        'gpu_temp_dist': [],
        'cpu_load_dist': [0]*5, # <10, 10-30, 30-60, 60-90, >90
        'gpu_load_dist': [0]*5,
        'vram_efficiency': []
    }
    
    raw_total_points = len(raw_data)
    if raw_total_points == 0:
        return jsonify(analysis)

    # 温度精度优化：1度步长，自动寻找范围
    all_cpu_temps = [d[1] for d in raw_data if d[1] is not None]
    all_gpu_temps = [g[1] for g in gpu_raw if g[1] is not None]
    
    min_t = int(min(all_cpu_temps + all_gpu_temps + [30]))
    max_t = int(max(all_cpu_temps + all_gpu_temps + [80]))
    
    temp_labels = list(range(min_t, max_t + 1))
    analysis['cpu_temp_labels'] = [f"{t}°C" for t in temp_labels]
    cpu_temp_counts = {t: 0 for t in temp_labels}
    gpu_temp_counts = {t: 0 for t in temp_labels}
    
    cpu_load_counts = [0]*5
    gpu_load_counts = [0]*5
    gpu_pwr_sum = 0
    cpu_pwr_sum = 0
    gpu_pwr_points = 0
    
    # 散点图空间聚类预处理 (100x100 网格，精确到 1%)
    grid_size = 100
    vram_eff_grid = {}
    
    gpu_raw_map = {g[0]: g for g in gpu_raw}
    
    for d in raw_data:
        ts, t, p, l = d
        if t is not None:
            it = int(round(t))
            if it in cpu_temp_counts: cpu_temp_counts[it] += 1
        if l is not None:
            if l < 10: cpu_load_counts[0] += 1
            elif l < 30: cpu_load_counts[1] += 1
            elif l < 60: cpu_load_counts[2] += 1
            elif l < 90: cpu_load_counts[3] += 1
            else: cpu_load_counts[4] += 1
        
        g = gpu_raw_map.get(ts)
        if g:
            gt, gl, gm, gp = g[1], g[2], g[3], g[4]
            if gt is not None:
                igt = int(round(gt))
                if igt in gpu_temp_counts: gpu_temp_counts[igt] += 1
            if gl is not None:
                if gl < 10: gpu_load_counts[0] += 1
                elif gl < 30: gpu_load_counts[1] += 1
                elif gl < 60: gpu_load_counts[2] += 1
                elif gl < 90: gpu_load_counts[3] += 1
                else: gpu_load_counts[4] += 1
            if gl is not None and gm is not None:
                gx = int(gl * grid_size / 100.1)
                gy = int(gm * grid_size / 100.1)
                vram_eff_grid[(gx, gy)] = vram_eff_grid.get((gx, gy), 0) + 1
            if gp is not None:
                gpu_pwr_sum += gp
                cpu_pwr_sum += max(0, p - gp)
                gpu_pwr_points += 1
            else:
                cpu_pwr_sum += p
        else:
            cpu_pwr_sum += p

    max_weight = max(vram_eff_grid.values()) if vram_eff_grid else 1
    for (gx, gy), weight in vram_eff_grid.items():
        analysis['vram_efficiency'].append({
            'x': round(gx * 100 / grid_size, 1), 'y': round(gy * 100 / grid_size, 1),
            'r': round(2 + (weight / max_weight) * 8, 1)
        })

    gpu_total_points = sum(gpu_temp_counts.values()) 
    analysis['cpu_temp_dist'] = [round(cpu_temp_counts[t] / raw_total_points * 100, 2) for t in temp_labels]
    analysis['cpu_load_dist'] = [round(c / raw_total_points * 100, 2) for c in cpu_load_counts]
    
    if gpu_total_points > 0:
        analysis['gpu_temp_dist'] = [round(gpu_temp_counts[t] / gpu_total_points * 100, 2) for t in temp_labels]
        analysis['gpu_load_dist'] = [round(c / gpu_total_points * 100, 2) for c in gpu_load_counts]
    else:
        analysis['gpu_temp_dist'] = [0] * len(temp_labels)
        analysis['gpu_load_dist'] = [0] * 5
    
    analysis['cpu_power_avg'] = round(cpu_pwr_sum / raw_total_points, 1)
    if gpu_pwr_points > 0:
        analysis['gpu_power_avg'] = round(gpu_pwr_sum / gpu_pwr_points, 1)

    return jsonify(analysis)

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
            details = {}
            msg_parts = []
            
            if 'mode' in data: 
                c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('mode', ?)", (data['mode'],))
                details['mode'] = data['mode']
                msg_parts.append(f"模式->{data['mode']}")
          
            if 'curve' in data: 
                c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('curve', ?)", (json.dumps(data['curve']),))
                details['curve_updated'] = True
                msg_parts.append("更新曲线")
          
            # 兼容性保存
            if 'enabled' in data:
                val = 'true' if data['enabled'] else 'false'
                c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('fixed_fan_speed_enabled', ?)", (val,))
                details['fixed_enabled'] = val
                msg_parts.append(f"定速开启->{val}")
          
            if 'target' in data:
                c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('fixed_fan_speed_target', ?)", (str(data['target']),))
                details['fixed_target'] = data['target']
                msg_parts.append(f"定速目标->{data['target']}")

            conn.commit()
            
            write_audit('INFO', 'FAN', 'UPDATE_CONFIG', f"更新风扇配置: {', '.join(msg_parts)}", details=details)
            return jsonify({'status': 'ok'})
        except Exception as e:
            write_audit('ERROR', 'FAN', 'UPDATE_FAIL', f"更新风扇配置失败: {str(e)}")
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
        details = {}
        msg_parts = []
        
        if 'enabled' in data:
            val = str(data['enabled']).lower()
            c.execute("UPDATE config SET value=? WHERE key='fixed_fan_speed_enabled'", (val,))
            details['enabled'] = val
            msg_parts.append(f"开启->{val}")
            
        if 'target' in data:
            val = str(data['target'])
            c.execute("UPDATE config SET value=? WHERE key='fixed_fan_speed_target'", (val,))
            details['target'] = val
            msg_parts.append(f"目标->{val}")
            
        conn.commit()
        write_audit('INFO', 'FAN', 'UPDATE_FIXED', f"更新定速设置: {', '.join(msg_parts)}", details=details)
        return jsonify({'status': 'ok'})
    except Exception as e:
        write_audit('ERROR', 'FAN', 'UPDATE_FIXED_FAIL', f"更新定速设置失败: {str(e)}")
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/calibration/start', methods=['POST'])
@login_required
def api_calib_start():
    if not sys_cache['calibration']['active']:
        write_audit('INFO', 'CALIBRATION', 'START', '启动风扇校准', operator=get_client_ip())
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
        try:
            data = request.json
            details = {}
            msg_parts = []
            
            if 'gpu_agent_enabled' in data:
                val = str(data['gpu_agent_enabled']).lower()
                c.execute("UPDATE config SET value=? WHERE key='gpu_agent_enabled'", (val,))
                details['enabled'] = val
                msg_parts.append(f"Agent开启->{val}")
                
            if 'gpu_agent_host' in data:
                c.execute("UPDATE config SET value=? WHERE key='gpu_agent_host'", (data['gpu_agent_host'],))
                details['host'] = data['gpu_agent_host']
                msg_parts.append(f"Host->{data['gpu_agent_host']}")
                
            if 'gpu_agent_port' in data:
                val = str(data['gpu_agent_port'])
                c.execute("UPDATE config SET value=? WHERE key='gpu_agent_port'", (val,))
                details['port'] = val
                msg_parts.append(f"Port->{val}")
                
            conn.commit()
            write_audit('INFO', 'GPU', 'UPDATE_CONFIG', f"更新GPU Agent配置: {', '.join(msg_parts)}", details=details)
            return jsonify({'status': 'success'})
        except Exception as e:
            write_audit('ERROR', 'GPU', 'UPDATE_CONFIG_FAIL', f"更新GPU Agent配置失败: {str(e)}")
            return jsonify({'error': str(e)}), 500
        finally:
            conn.close()

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

    # [修复断点显示] 注入 null 值处理数据缺失
    final_data = []
    gap_threshold = max(30, step * 3)
    
    for i in range(len(sampled_data)):
        if i > 0:
            prev_ts = sampled_data[i-1][0]
            curr_ts = sampled_data[i][0]
            # 统一 2min 宽容断点逻辑
            if curr_ts - prev_ts > max(120, step * 5):
                final_data.append(( (prev_ts + curr_ts) // 2, None, None, None, None, None, None))
        final_data.append(sampled_data[i])
  
    return jsonify({
        'times': [datetime.fromtimestamp(d[0]).strftime(time_fmt) for d in final_data],
        'temp': [d[1] for d in final_data],
        'util_gpu': [d[2] for d in final_data],
        'util_mem': [d[3] for d in final_data],
        'mem_used': [d[5] for d in final_data],
        'power': [d[6] for d in final_data]
    })

@app.route('/api/recording_stats')
@login_required
def api_recording_stats():
    conn = get_db_connection()
    c = conn.cursor()
    cutoff = int(time.time() - 86400)
    # 获取过去24小时数据
    c.execute("SELECT timestamp, interval FROM recording_intervals WHERE timestamp > ? ORDER BY timestamp ASC", (cutoff,))
    data = c.fetchall()
    conn.close()
    
    if not data: return jsonify([])
    
    # 为了前端性能，如果点数过多则进行最大值降采样（保留毛刺）
    target_points = 500 
    if len(data) > target_points:
        step = len(data) / target_points # 使用浮点步长确保更均匀的分布
        sampled = []
        for i in range(target_points):
            idx_start = int(i * step)
            idx_end = int((i + 1) * step)
            chunk = data[idx_start:idx_end]
            if chunk:
                max_val = max([x[1] for x in chunk])
                sampled.append({'t': data[idx_end-1][0], 'v': max_val})
        return jsonify(sampled)
    
    return jsonify([{'t': x[0], 'v': x[1]} for x in data])

from werkzeug.serving import WSGIRequestHandler

class SilentHandler(WSGIRequestHandler):
    """静默处理常见的网络中断报错"""
    def log_error(self, format, *args):
        # 忽略 BrokenPipe 和 SSL 相关的非致命错误
        err_msg = str(args[0]) if args else ""
        if "BrokenPipeError" in err_msg or "Errno 32" in err_msg or "SSLError" in err_msg or "EOF" in err_msg:
            return
        super().log_error(format, *args)

if __name__ == '__main__':
    check_environment()
    init_db()
    # 启动后台工作线程
    threading.Thread(target=background_worker, daemon=True).start()
    threading.Thread(target=gpu_worker, daemon=True).start()
    threading.Thread(target=energy_maintenance_task, daemon=True).start()
    
    if HAS_CERT:
        print(f" * SSL Certificate found, starting HTTPS on port {PORT}")
        app.run(host='0.0.0.0', port=PORT, threaded=True, ssl_context=(cert_file, key_file), request_handler=SilentHandler)
    else:
        print(f" * No SSL Certificate found, starting HTTP on port {PORT}")
        app.run(host='0.0.0.0', port=PORT, threaded=True, request_handler=SilentHandler)
