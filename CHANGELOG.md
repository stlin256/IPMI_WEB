# Changelog

## 1.6.1 - 2026-06-21

### 中文

- 优化风扇调控策略：手动曲线改为温度插值、平滑调速和安全下限组合，减少 5°C 档位跳变和高温前响应滞后。
- 目标温度模式在高温区升速更快、降速更保守，并缓存风扇模式和 PWM 下发结果，减少对 BMC 的重复写入。
- 优化硬件页曲线编辑：移动端滑块保留纵向滚动手势并过滤滚动误触，PC 端支持直接拖动曲线点同步调整参数。

### English

- Optimized fan control: manual curves now use temperature interpolation, smoothing, and safety floors to reduce 5°C step jumps and late high-temperature response.
- Target-temperature mode now ramps up faster in hot ranges, ramps down more conservatively, and caches fan mode/PWM writes to reduce repeated BMC commands.
- Improved Hardware curve editing: mobile sliders preserve vertical scrolling and suppress scroll mis-touches, while desktop users can drag curve points directly to adjust parameters.

## 1.6.0 - 2026-06-16

### 中文

- 新增首次运行安装与配置流程：Linux 和 Windows 安装脚本会交互式设置端口、安装目录、数据目录、服务名和运行方式，启动后进入 `/setup` 配置向导。
- 新增基于登录页视觉体系的首次配置界面，支持浏览器语言默认、中文/英文切换、逐步校验、GPU 监控、邮件告警、自动更新模式和更新通道配置。
- 新增自动更新基础框架：安装元数据和系统设置支持 `release` / `dev` 更新通道，默认使用 `release`；新增手动 GitHub Actions release 打包 workflow，生成压缩包、校验文件和 manifest。
- 首次配置入口移除 setup token，改为安装态 `setup_required` 标记控制；未完成配置时访问登录页或受保护页面会自动跳转到 `/setup`。
- 优化首次配置的入场和切换动效，移动端语言卡片到配置向导使用预计算 FLIP 变形，避免只表现为高度拉伸。
- 移除重复的 GPU Agent 配置接口，减少前端调用歧义。

### English

- Added the first-run installation and setup flow: Linux and Windows installers now ask for the port, install path, data path, service name, and runtime mode before starting the service and entering `/setup`.
- Added a first-run setup UI based on the login visual system, with browser-language defaults, Chinese/English switching, step validation, GPU monitoring, email alerts, auto-update mode, and update-channel configuration.
- Added the auto-update foundation: install metadata and settings now support `release` / `dev` update channels, defaulting to `release`; a manual GitHub Actions release workflow now builds the archive, checksum, and manifest.
- Removed setup tokens from the first-run entry path. Setup mode is now controlled by the installed `setup_required` flag, and unfinished instances redirect login or protected pages to `/setup`.
- Improved first-run motion: mobile transitions from the language card to the setup wizard now use precomputed FLIP morphing instead of reading as a simple height stretch.
- Removed a duplicate GPU Agent configuration endpoint to reduce frontend API ambiguity.

## 1.5.1 - 2026-06-16

### 中文

- 硬件页曲线刷新改为平滑推进，避免每次刷新时曲线重新从头冒出。
- 优化桌面端导航间距，缩小左侧徽标和顶部导航之间的空白。
- 历史页预加载逻辑改为轻量跳转优先，避免上次选择 30D 后下次打开页面长时间无响应；硬件传感器详情页复用同类快速加载体验。
- 系统日志支持点击整条日志展开详情，同时保留右侧详情按钮；审计日志压缩归档这类维护事件不再显示在 logs 列表中。
- GPU 监控支持配置多个 Agent，单独启用/关闭并填写备注；部分 Agent 离线时只给对应卡片加离线遮罩，全部失效时保持原有全局离线效果，并兼容旧版单 Agent 配置迁移。
- 修复 GPU 卡片信息栏分割线缺失问题；资源页底部网络和磁盘 IO 数值区域收窄，趋势图横向空间加宽，方便查看。

### English

- Hardware charts now advance smoothly during refreshes instead of reappearing from the beginning each time.
- Tightened desktop navigation spacing between the left logo and top navigation.
- History preloading now prioritizes lightweight navigation so reopening after a long 30D selection no longer feels unresponsive; hardware sensor detail loading now uses the same fast path.
- System logs can be expanded by clicking the whole row while keeping the detail button; audit-log compression archive maintenance events are hidden from the logs list.
- GPU monitoring now supports multiple Agents with per-Agent enable switches and notes. Offline enabled Agents get per-card overlays, while all-offline still uses the original global offline effect, with migration from legacy single-Agent settings.
- Fixed missing separators in GPU card info rows; widened the Resources page network and disk IO trend charts by moving the live values further aside.

## 1.5.0 - 2026-06-15

### 中文

- 前端体验升级：IPMI_WEB 完成一次大规模界面风格重塑，核心页面统一为新的现代化运维面板设计。
- 登录、导航、硬件、资源、GPU、历史和日志/设置页面均完成视觉、动效和移动端体验优化。
- 新增预取式 PJAX 页面切换与页面生命周期清理，让跨页切换更快、更稳定。

### English

- Frontend experience upgraded: IPMI_WEB has received a large-scale visual redesign, unifying core pages under a new modern operations-panel style.
- Login, navigation, Hardware, Resources, GPU, History, and Logs/Settings pages now have improved visuals, motion, and mobile behavior.
- Added prefetched PJAX navigation and page lifecycle cleanup for faster and more stable route switching.

## 1.4.6 - 2026-06-01

### 中文

- GPU 卡片中的核心频率曲线改为绿色，和其他指标线条区分更清晰。
- 传感器全量历史新增小时级压缩归档，近 6 小时保留热表，较旧数据打包为可查询、可导出的归档块，降低长期数据库占用。
- 审计日志归档改为更紧凑的列式格式，同时兼容旧版归档数据。
- SQLite 可回收空间改为后台自动压缩；达到阈值且磁盘空间足够时自动执行，低磁盘开关只负责必要时删除最早历史日。
- 存储管理文案改为“低磁盘自动删除”，避免把 SQLite 空间压缩和历史删除混为一谈。
- 补全空间清理和压缩审计日志：审计归档、传感器归档、SQLite 压缩、保留期清理都会写入可本地化摘要，折叠状态下也能看懂发生了什么。

### English

- Changed the GPU card core-clock trend line to green so it is easier to distinguish from other metrics.
- Added hourly compressed archives for full sensor history. The latest 6 hours stay in the hot table, while older samples are packed into queryable and exportable archive blocks to reduce long-term database growth.
- Switched archived audit logs to a more compact columnar format while keeping compatibility with existing archives.
- SQLite reclaimable space is now compacted automatically by background maintenance once it reaches the threshold and enough disk space is available. The low-disk switch now only controls deletion of the oldest history day when necessary.
- Renamed the storage setting copy to “Low-disk Auto Delete” to separate SQLite compaction from destructive history deletion.
- Added complete audit summaries for space cleanup and compression: audit archives, sensor archives, SQLite compaction, and retention cleanup now write localized summaries that are clear without expanding details.

## 1.4.5 - 2026-06-01

### 中文

- 完善全站 i18n 覆盖，补齐硬件、GPU、历史、资源、设置、证书、导入导出、邮件摘要和审计日志中的残留硬编码文案。
- 修复中文/英文切换后部分动态日志仍使用另一种语言的问题，审计与配置变更显示会按当前界面语言重建。
- 修复首次打开页面可能卡死的问题，i18n 前端同步只在内容确实变化时更新 DOM。
- 更新日志和版本更新弹窗现在严格按当前语言显示；中文模式不再混入英文更新说明，英文模式也不再混入中文。

### English

- Completed i18n coverage across hardware, GPU, history, resources, settings, certificates, import/export, email summaries, and audit-log copy.
- Fixed dynamic logs that could still appear in the other language after switching Chinese/English; audit and configuration-change entries are rebuilt for the current UI language.
- Fixed a first-page-load freeze by making frontend i18n synchronization update the DOM only when content actually changes.
- Changelog and version-update modals now render strictly in the current language; Chinese mode no longer includes English release notes, and English mode no longer includes Chinese notes.

## 1.4.4 - 2026-06-01

### 中文

- 新增中文/英文界面语言设置，首次访问会根据浏览器语言自动选择，之后可在系统设置中固定切换。
- 新增独立 i18n 词表，登录页、页面标题、导航、系统设置入口和语言设置文案改为通过词表维护，减少模板与脚本中的重复硬编码。
- 语言设置会随系统设置一起保存；切换语言后自动刷新当前页面，使服务端模板和前端提示同步生效。

### English

- Added Chinese/English UI language settings. The first visit follows the browser language, and administrators can later pin the language in System Settings.
- Added a dedicated i18n catalog. Login, page titles, navigation, the settings entry, and language-setting copy are now maintained through the catalog instead of repeated hard-coded strings in templates and scripts.
- Language changes are saved with system settings. After switching language, the current page reloads so server-rendered templates and frontend messages update together.

## 1.4.3 - 2026-05-31

### 中文

- 存储管理新增低磁盘自动回收开关，默认保持关闭，管理员可在设置中显式开启。
- 低磁盘清理在删除历史前会先尝试回收 SQLite freelist 空间；如果空间已经恢复到目标值，不再删除历史记录。
- 自动删除前会检查 SQLite 是否具备安全整理所需空间，无法安全回收时会熔断并写入保护日志，避免再次出现删除记录但数据库文件不缩小的情况。
- 存储状态新增 SQLite 可回收空间显示，方便判断 `data.db` 文件体积和实际可用空间之间的差异。
- 设置关于页恢复为原来的项目信息布局，并改为通过“查看更新日志”按钮打开独立更新日志弹窗。

### English

- Added a low-disk auto-reclaim switch in Storage Management. It remains disabled by default and must be explicitly enabled by an administrator.
- Low-disk cleanup now attempts to reclaim SQLite freelist space before deleting history; if the target free space is restored, no history rows are removed.
- Automatic deletion now checks whether SQLite can be compacted safely. If compaction is unsafe, pruning is blocked and a protection log is written to avoid deleting rows while the database file stays large.
- Storage status now shows SQLite reclaimable space so the difference between `data.db` size and reusable internal pages is visible.
- Restored the Settings/About project information layout and moved release notes behind a dedicated “View changelog” action.

## 1.4.2 - 2026-05-31

### 中文

- 紧急修复低磁盘保护逻辑：默认禁用破坏性的自动历史删除，磁盘空间不足时只写限流告警，不再删除任何记录。
- 即使显式开启低磁盘自动清理，也必须保留至少最近 7 天和当前保留期内的数据，且只删除完整落在保护窗口之外的旧自然日。
- 低磁盘自动清理单次最多删除 1 天，并增加 6 小时冷却，避免 SQLite 文件未收缩时连续删除库内历史记录。
- 如果删除后文件系统可用空间没有明显增加，会自动熔断后续删除并写入保护日志。

### English

- Emergency fix for low-disk protection: destructive automatic history deletion is disabled by default; low disk space now only writes rate-limited warnings and deletes no records.
- Even when low-disk auto pruning is explicitly enabled, at least the last 7 days and the configured retention window are protected, and only fully expired natural days can be removed.
- Low-disk auto pruning is capped to one day per run with a 6-hour cooldown to avoid repeated database-row deletion when SQLite files do not shrink immediately.
- If deletion does not noticeably increase filesystem free space, further pruning is automatically blocked and a protection log is written.

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
