# IPMI 硬件监控与风扇控制面板

这是一个轻量级的、基于 Web 的仪表板，用于通过 IPMI 监控服务器硬件状态并控制风扇速度。它使用 Python Flask 作为后端，并调用 `ipmitool` 和 `sensors` 等系统命令来收集数据。

## 主要功能

- **硬件状态监控**: 实时显示 CPU 温度、功耗、风扇转速 (RPM) 以及所有可用的 IPMI 传感器数据。
- **系统资源监控**: 实时图表展示 CPU 使用率、内存使用情况、网络吞吐量和磁盘 I/O。
- **智能风扇控制**:
    - **自动模式**: 将风扇控制权交还给主板 IPMI 控制器。
    - **手动曲线模式**: 用户可以自定义一个温度-风扇转速百分比的响应曲线，实现更安静或更高效的散热策略。
- **风扇校准**: 内置校准程序，可自动测试并生成 PWM 占空比到实际风扇 RPM 的映射关系，从而实现更精确的风扇速度控制。
- **历史数据图表**: 查看过去 24 小时或更长时间的详细性能指标图表，数据经过智能降采样处理，即使在长时间范围内也能快速加载。
- **简单安全**: 所有页面均受密码保护。

## 技术栈

- **后端**: Flask
- **数据采集**: `ipmitool`, `sensors` (lm-sensors), `psutil`
- **数据库**: SQLite (开启 WAL 模式以提高并发性能)
- **前端**: HTML, JavaScript (使用 Chart.js 绘图)

## 如何运行

1.  **安装依赖**:
    ```bash
    # 确保系统已安装 ipmitool 和 lm-sensors
    sudo apt-get update
    sudo apt-get install ipmitool lm-sensors
    
    # 安装 Python 依赖
    pip install Flask psutil
    ```

2.  **初始化数据库**:
    脚本首次运行时会自动创建并初始化 SQLite 数据库文件 (`/opt/fan_controller/data.db`)。

3.  **运行应用**:
    ```bash
    python app.py
    ```

4.  **访问**:
    在浏览器中打开 `http://<your-server-ip>:90`。
    - **默认密码**: `linyijianb` (可在 `app.py` 中修改 `LOGIN_PASSWORD` 变量)

## 配置

所有主要配置项都在 [`app.py`](app.py) 文件的顶部，您可以根据需要进行修改：

- `DB_FILE`: 数据库文件的路径。
- `LOGIN_PASSWORD`: 登录页面的密码。
- `PORT`: Web 服务的端口。
- `RETENTION_DAYS`: 历史数据的保留天数。