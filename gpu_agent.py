import http.server
import socketserver
import subprocess
import json
import csv
import io
import sys
import threading
import time

# 配置
PORT = 9999

# NVIDIA-SMI 命令
# 注意：我们使用 --format=csv,noheader,nounits 来获取纯数值，方便解析
NVIDIA_CMD = [
    'nvidia-smi',
    '--query-gpu=index,name,temperature.gpu,utilization.gpu,utilization.memory,memory.total,memory.used,power.draw,power.limit,clocks.current.graphics,clocks.current.memory,fan.speed,ecc.errors.corrected.volatile.total',
    '--format=csv,noheader,nounits'
]

# 字段映射 (对应命令中的顺序)
FIELDS = [
    'index', 'name', 'temp', 'util_gpu', 'util_mem', 
    'memory_total', 'memory_used', 'power_draw', 'power_limit', 
    'clock_core', 'clock_mem', 'fan_speed', 'ecc_errors'
]

def get_gpu_stats():
    try:
        # 执行命令
        result = subprocess.run(
            NVIDIA_CMD, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            timeout=3, 
            encoding='utf-8'
        )
        
        if result.returncode != 0:
            return {'error': 'nvidia-smi failed', 'details': result.stderr.strip()}

        # 解析 CSV
        gpus = []
        f = io.StringIO(result.stdout)
        reader = csv.reader(f)
        
        for row in reader:
            if len(row) != len(FIELDS):
                continue
                
            gpu_data = {}
            for i, field in enumerate(FIELDS):
                val = row[i].strip()
                # 尝试转换为数字
                try:
                    if '.' in val:
                        gpu_data[field] = float(val)
                    elif val.isdigit():
                        gpu_data[field] = int(val)
                    elif val in ['[Not Supported]', '[N/A]']:
                        gpu_data[field] = 0
                    else:
                        gpu_data[field] = val
                except:
                    gpu_data[field] = val
            
            # 特殊处理：如果风扇显示为 [Not Supported] 或者无法获取，默认为 0
            if isinstance(gpu_data.get('fan_speed'), str):
                 gpu_data['fan_speed'] = 0

            gpus.append(gpu_data)
            
        return {'timestamp': int(time.time()), 'gpus': gpus}

    except subprocess.TimeoutExpired:
        return {'error': 'nvidia-smi timeout'}
    except FileNotFoundError:
        return {'error': 'nvidia-smi not found'}
    except Exception as e:
        return {'error': str(e)}

class GPURequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            data = get_gpu_stats()
            self.wfile.write(json.dumps(data).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        # 禁用默认的控制台日志，避免刷屏
        pass

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Handle requests in a separate thread."""
    pass

if __name__ == '__main__':
    print(f"Starting GPU Agent on port {PORT}...")
    print(f"Test command: curl http://localhost:{PORT}/metrics")
    
    server = ThreadedHTTPServer(('0.0.0.0', PORT), GPURequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        server.shutdown()
