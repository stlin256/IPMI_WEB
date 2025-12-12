# IPMI 硬件监控与风扇控制面板

这是一个轻量级的、基于 Web 的仪表板，用于通过 IPMI 监控服务器硬件状态并控制风扇速度。它使用 Python Flask 作为后端，并调用 `ipmitool` 和 `sensors` 等系统命令来收集数据。

本仪表板已在本人的**DELL PowerEdge R730xd**上部署并正常使用，其他型号服务器/PC也可部署。

![alt text](/img/image.png)
![alt text](/img/image-1.png)
![alt text](/img/image-2.png)

<p align="center">
  <img src="img/phone-1.jpg" width="32%" />
  <img src="img/phone-2.jpg" width="32%" />
  <img src="img/phone-3.jpg" width="32%" />
</p>

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
- **数据采集**: `ipmitool`, `lm-sensors` , `psutil`
- **数据库**: SQLite
- **前端**: HTML, JavaScript 

## 如何运行

1.  **安装依赖**:
    ```bash
    # 确保系统已安装 ipmitool 和 lm-sensors
    sudo apt-get update
    sudo apt-get install ipmitool lm-sensors
    
    # 安装 Python 依赖
    pip install Flask psutil
    ```

2.  **配置应用**:
    首次运行前，请先配置应用。
    ```bash
    # 从模板复制配置文件
    cp config.json.example config.json
    ```
    然后，使用文本编辑器打开 `config.json` 并根据您的环境修改其中的值，特别是 `login_password`。

3.  **运行应用**:
    ```bash
    python app.py
    ```
    应用首次运行时，会自动创建并初始化 SQLite 数据库。

4.  **访问**:
    在浏览器中打开 `http://<your-server-ip>:<port>` (端口在 `config.json` 中定义)。
    - **密码**: 您在 `config.json` 中设置的密码。

## 配置

所有配置项现在都在 `config.json` 文件中进行管理。

- `DATABASE.path`: 数据库文件的路径。
- `DATABASE.retention_days`: 历史数据的保留天数。
- `SERVER.port`: Web 服务的端口。
- `SERVER.server_name`: 显示在页面标题和导航栏的服务器名称。
- `SECURITY.login_password`: 登录页面的密码。