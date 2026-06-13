from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from jinja2 import Environment, FileSystemLoader


ROOT = Path(__file__).resolve().parents[2]
MAIN_TEMPLATES = [
    "login.html",
    "hardware.html",
    "resources.html",
    "gpu.html",
    "history.html",
    "logs.html",
]
IGNORED_JS_FILES = {
    ROOT / "static" / "js" / "bootstrap.bundle.min.js",
    ROOT / "static" / "js" / "chart.min.js",
}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def load_messages() -> dict:
    messages_path = ROOT / "static" / "i18n" / "messages.json"
    return json.loads(messages_path.read_text(encoding="utf-8"))


def translate(messages: dict, key: str, **kwargs: object) -> str:
    text = messages.get("en", {}).get(key, key)
    for name, value in kwargs.items():
        text = text.replace("{" + name + "}", str(value))
    return text


def render_templates(messages: dict) -> dict[str, str]:
    env = Environment(loader=FileSystemLoader(str(ROOT / "templates")))
    env.globals["url_for"] = (
        lambda endpoint, filename=None, **kwargs:
        f"/static/{filename}" if endpoint == "static" else "#"
    )

    rendered = {}
    for name in MAIN_TEMPLATES:
        rendered[name] = env.get_template(name).render(
            locale="en",
            server_name="CI Node",
            t=lambda key, **kwargs: translate(messages, key, **kwargs),
            i18n_messages=messages.get("en", {}),
        )
    return rendered


def run_node_check(path: Path) -> None:
    result = subprocess.run(
        ["node", "--check", str(path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        fail(f"JavaScript syntax check failed: {path}")


def check_javascript(rendered: dict[str, str]) -> None:
    if not shutil.which("node"):
        fail("Node.js is required for JavaScript syntax checks")

    for path in sorted((ROOT / "static" / "js").rglob("*.js")):
        if path.resolve() in {p.resolve() for p in IGNORED_JS_FILES}:
            continue
        run_node_check(path)

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_root = Path(temp_dir)
        for name, html in rendered.items():
            scripts = []
            for match in re.finditer(
                r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>",
                html,
                flags=re.S | re.I,
            ):
                code = match.group(1).strip()
                if code:
                    scripts.append(code)
            if not scripts:
                continue
            script_path = temp_root / f"{name.replace('.html', '')}.inline.js"
            script_path.write_text("\n;\n".join(scripts), encoding="utf-8")
            run_node_check(script_path)


def iter_source_files() -> list[Path]:
    files = []
    for base in [ROOT / "templates", ROOT / "static"]:
        files.extend(base.rglob("*"))
    files.extend([ROOT / "app.py", ROOT / "i18n.py", ROOT / "gpu_agent.py"])
    return [
        path for path in files
        if path.is_file()
        and path.suffix.lower() in {".html", ".js", ".py"}
        and path.resolve() not in {p.resolve() for p in IGNORED_JS_FILES}
    ]


def check_no_native_dialogs() -> None:
    pattern = re.compile(r"\b(alert|confirm|prompt)\s*\(")
    issues = []
    for path in iter_source_files():
        for line_no, line in enumerate(read_text(path).splitlines(), 1):
            if pattern.search(line):
                issues.append(f"{path.relative_to(ROOT)}:{line_no}: {line.strip()}")
    if issues:
        fail("Native browser dialogs are forbidden:\n" + "\n".join(issues))


def check_i18n(messages: dict) -> None:
    locales = sorted(messages)
    keys_by_locale = {
        locale: set(values) - {"_textMap"}
        for locale, values in messages.items()
        if isinstance(values, dict)
    }
    patterns = [
        re.compile(r"\bt\(\s*['\"]([A-Za-z0-9_.-]+)['\"]"),
        re.compile(r"\btx\(\s*['\"]([A-Za-z0-9_.-]+)['\"]"),
        re.compile(r"translate_current\(\s*['\"]([A-Za-z0-9_.-]+)['\"]"),
        re.compile(r"translate_locale\([^,]+,\s*['\"]([A-Za-z0-9_.-]+)['\"]"),
        re.compile(r"data-i18n(?:-[a-z-]+)?=\s*['\"]([A-Za-z0-9_.-]+)['\"]"),
    ]
    used: dict[str, set[str]] = {}
    for path in iter_source_files():
        text = read_text(path)
        for pattern in patterns:
            for match in pattern.finditer(text):
                key = match.group(1)
                if key == "logs.alert.metric.":
                    continue
                used.setdefault(key, set()).add(str(path.relative_to(ROOT)))

    missing = []
    for locale in locales:
        if locale not in keys_by_locale:
            continue
        missing_keys = sorted(key for key in used if key not in keys_by_locale[locale])
        for key in missing_keys:
            missing.append(f"{locale}: {key} used in {', '.join(sorted(used[key]))}")
    if missing:
        fail("Missing i18n keys:\n" + "\n".join(missing))


def check_modal_semantics() -> None:
    issues = []
    modal_count = 0
    for path in sorted((ROOT / "templates").glob("*.html")):
        text = read_text(path)
        ids = set(re.findall(r'\bid="([^"]+)"', text))
        for match in re.finditer(r'<div\s+class="modal fade"[^>]*>', text):
            modal_count += 1
            tag = match.group(0)
            modal_id_match = re.search(r'id="([^"]+)"', tag)
            modal_id = modal_id_match.group(1) if modal_id_match else "<missing-id>"
            for attr in ['role="dialog"', "aria-hidden=", "aria-labelledby="]:
                if attr not in tag:
                    issues.append(f"{path.relative_to(ROOT)}:{modal_id} missing {attr}")
            label = re.search(r'aria-labelledby="([^"]+)"', tag)
            if label and label.group(1) not in ids:
                issues.append(f"{path.relative_to(ROOT)}:{modal_id} bad label {label.group(1)}")
            desc = re.search(r'aria-describedby="([^"]+)"', tag)
            if desc and desc.group(1) not in ids:
                issues.append(f"{path.relative_to(ROOT)}:{modal_id} bad desc {desc.group(1)}")

        for line_no, line in enumerate(text.splitlines(), 1):
            if "btn-close" in line and "data-i18n-aria-label=" not in line:
                issues.append(f"{path.relative_to(ROOT)}:{line_no} close missing aria i18n")

    if modal_count == 0:
        fail("No modals found; modal semantics check is probably misconfigured")
    if issues:
        fail("Modal accessibility issues:\n" + "\n".join(issues))


def check_app_core_loaded() -> None:
    missing = []
    for template in MAIN_TEMPLATES:
        text = read_text(ROOT / "templates" / template)
        if "js/app-core.js" not in text:
            missing.append(template)
    if missing:
        fail("app-core.js is missing from templates: " + ", ".join(missing))


def main() -> None:
    messages = load_messages()
    rendered = render_templates(messages)
    for name, html in rendered.items():
        if len(html) < 1000:
            fail(f"Rendered template unexpectedly short: {name}")
    check_app_core_loaded()
    check_no_native_dialogs()
    check_i18n(messages)
    check_modal_semantics()
    check_javascript(rendered)
    print("Frontend CI checks passed")


if __name__ == "__main__":
    main()
