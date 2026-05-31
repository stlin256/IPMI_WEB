# Changelog

## 1.4.1 - 2026-05-31

### 中文

- 修复 Python 3.13 启动时 `datetime.utcnow()` 弃用警告，并把完整硬件探测载荷从 INFO 日志降为 DEBUG，避免 journal 被大段启动信息刷屏。
- 过滤 Werkzeug 开发服务器中常见的客户端断开噪声，减少 `BrokenPipeError` 和 SSL unexpected EOF 对运行日志的干扰。
- 优化硬件页、历史页、设置弹窗和版本更新弹窗的加载路径，减少首屏和按钮点击时被重型设置接口阻塞。
- 设置页“关于”新增更新日志入口，证书上传失败改为项目内渲染弹窗提示，并隐藏证书/私钥文件路径。
- 证书上传保存前会校验证书格式、有效期和私钥匹配关系，拒绝过期或尚未生效的证书。
- 存储状态拆分为独立接口，低磁盘普通历史清理只写 INFO；只有确实删除历史审计日志时才写 WARN 并唤醒红点。
- 压缩策略升级为带格式前缀的 zlib/LZMA 自适应压缩，传感器历史写入和审计归档可使用更高压缩比，同时兼容旧 zlib 数据。
- 重整 README 的中英文结构，补齐项目背景、图表说明、架构图、存储策略、安全说明和古早截图提示。

### English

- Fixed the Python 3.13 `datetime.utcnow()` startup deprecation warning and moved the full hardware probe payload from INFO to DEBUG to avoid oversized journal output.
- Filtered common Werkzeug development-server client disconnect noise, including `BrokenPipeError` and SSL unexpected EOF traces.
- Optimized the loading paths for hardware, history, settings, and update notice views so first render and settings clicks are less blocked by heavy configuration calls.
- Added release notes to Settings/About, rendered certificate upload failures with the app modal, and stopped showing certificate/key file paths in the UI.
- Certificate uploads now validate PEM format, validity dates, and private-key matching before saving, rejecting expired or not-yet-valid certificates.
- Split storage status into a dedicated API; routine low-disk history pruning now writes INFO, while WARN and the red dot are reserved for deleted historical audit logs.
- Upgraded compression to prefixed zlib/LZMA adaptive payloads for sensor history and audit archives while retaining compatibility with legacy zlib blobs.
- Reworked README with clearly separated Chinese/English content, project background, chart explanations, architecture diagrams, storage/security notes, and ancient screenshot warnings.

## 1.4.0 - 2026-05-31

### 中文

- GPU 卡片页面新增核心频率曲线，方便和温度、功耗、显存频率一起观察趋势。
- 版本更新后首次登录会显示带 IPMI_WEB ASCII 风格 Logo 的更新弹窗；如有更新说明，会一并展示。
- 设置页新增证书管理，支持上传 PEM 证书和私钥、查看证书过期时间，并在上传成功后使用系统弹窗询问是否重启服务。
- 存储管理现在会显示已存储天数和磁盘剩余空间。
- 30 天以前的审计日志会按自然日压缩归档，降低长期运行时的数据库占用。
- 磁盘剩余空间低于 800MB 时，系统会按最早自然日自动丢弃历史数据，并为每次丢弃写入 WARN 审计日志以触发提醒红点。

### English

- Added a GPU core clock trend line on the GPU card page for correlation with temperature, power, and memory clock trends.
- Added a first-login update notice after version changes, including the IPMI_WEB ASCII-style logo and optional release notes.
- Added certificate management in Settings for uploading PEM certificate/key files, viewing certificate expiration, and confirming service restart after upload.
- Storage management now shows stored data age and remaining disk space.
- Audit logs older than 30 days are compressed into daily archives to reduce long-term database growth.
- When free disk space drops below 800MB, the oldest history days are pruned automatically and each prune writes a WARN audit log to wake the alert dot.
