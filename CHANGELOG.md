# Changelog

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
