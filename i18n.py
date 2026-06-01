import json
import os


SUPPORTED_LOCALES = ("zh-CN", "en")
DEFAULT_LOCALE = "zh-CN"


def normalize_locale(value):
    text = str(value or "").strip().replace("_", "-")
    if not text:
        return None
    lower = text.lower()
    if lower.startswith("zh"):
        return "zh-CN"
    if lower.startswith("en"):
        return "en"
    return None


def pick_browser_locale(accept_languages):
    for language, _quality in accept_languages:
        locale = normalize_locale(language)
        if locale:
            return locale
    return DEFAULT_LOCALE


class I18n:
    def __init__(self, messages_path):
        self.messages_path = messages_path
        self._mtime = None
        self._messages = {}

    def _load(self):
        try:
            mtime = os.path.getmtime(self.messages_path)
        except OSError:
            self._messages = {}
            self._mtime = None
            return

        if self._mtime == mtime:
            return

        with open(self.messages_path, "r", encoding="utf-8") as f:
            self._messages = json.load(f)
        self._mtime = mtime

    def catalog(self, locale):
        self._load()
        locale = normalize_locale(locale) or DEFAULT_LOCALE
        base = self._messages.get(DEFAULT_LOCALE, {})
        current = self._messages.get(locale, {})
        return {**base, **current}

    def t(self, locale, key, **kwargs):
        text = self.catalog(locale).get(key, key)
        if kwargs:
            try:
                return text.format(**kwargs)
            except (KeyError, ValueError):
                return text
        return text
