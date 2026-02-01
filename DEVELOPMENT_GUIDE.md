# IPMI_WEB 配置文件开发与版本控制指南

本指南旨在指导开发者在系统中新增配置项（项目）时，如何保持配置文件的完整性、兼容性以及版本的一致性。

> [!IMPORTANT]
> **版本控制规范**：
> 任何涉及 `config` 表结构变更、新增配置项或修改导入导出逻辑的操作，**必须请示项目负责人（User）以获取新的全局版本号（VERSION）**。严禁擅自修改版本号。

---

## 当新增一个配置项（项目）时，需要修改的地方：

### 1. 数据库初始化 (app.py -> `init_db`)
必须在 `init_db` 函数中为新配置项添加 `INSERT OR IGNORE` 逻辑，确保系统首次启动时能自动创建该配置及其默认值。
```python
# 示例
c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('new_item_key', 'default_value')")
```

### 2. 设置读写与审计逻辑 (app.py -> `api_settings`)
*   **GET 请求**：在 `keys` 元组中增加新项的 Key，确保前端能读取到。
*   **POST 请求**：
    *   在 `mapping` 字典中增加“中文描述”，用于审计日志输出。
    *   在 `is_changed` 逻辑中确保该项能被脏检查捕捉。
    *   确保该项被正确写入 `config` 表。

### 3. 配置导出逻辑 (app.py -> `api_config_export`)
核查 `settings` 字典的生成逻辑。目前系统采用遍历 `config` 表全量导出的策略，通常无需改动，但若新增了独立的数据表（如 `alert_rules`），则需手动在 `export_data` 中添加对应的数组。

### 4. 导入预检逻辑 (app.py -> `api_config_precheck`)
*   **忽略键列表** (`ignore_keys`)：如果新项是内部状态（如时间戳），请将其加入忽略列表，防止导入时覆盖。
*   **归一化函数** (`normalize_val`)：如果新项涉及复杂的 JSON 字符串、布尔值或数值精度，请在预检逻辑中增加对应的归一化处理，防止“虚假变更”报告。

### 5. 前端 UI 与交互 (templates/logs.html)
*   **UI 渲染**：在设置 Modal 的对应 Tab 下增加输入控件（Input/Switch）。
*   **数据绑定**：在 `openDelaySettings()` 函数中增加对新项的 `document.getElementById(...).value` 赋值逻辑。
*   **脏检查机制** (`checkChanges`)：在 `currentSnapshot` 字典中增加新项的采集逻辑，确保用户修改后能触发“未保存”拦截提示。
*   **保存逻辑** (`saveGlobalSettings`)：在 `payload` 字典中增加新项的提交逻辑。

---

## 配置文件核查清单 (Checklist)

每次提交涉及配置的更改前，请确保：
- [ ] 执行一次导出，检查生成的 JSON 是否包含新项。
- [ ] 使用旧版导出的 JSON 进行一次“交叉导入”，确保不会报错（向下兼容）。
- [ ] 检查审计日志，确认新项的变更能被清晰地记录（如：`项目A: 旧值 -> 新值`）。
- [ ] **已向负责人请示并更新了版本号。**

---

## 当前系统配置项参考 (V1.3.0)
目前系统包含以下 14+ 核心配置项：
- `log_delay_warn / danger` (采集延迟)
- `data_retention_days` (数据保留)
- `dashboard_hours_hw / hist` (看板时效)
- `email_enabled / sender / receiver` (邮件通知)
- `alert_rules` (告警规则数组)
- 其他内部状态位...
