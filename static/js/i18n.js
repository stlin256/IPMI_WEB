(function () {
    const messages = window.I18N_MESSAGES || {};

    function format(text, params) {
        return String(text).replace(/\{(\w+)\}/g, (_match, key) => {
            return Object.prototype.hasOwnProperty.call(params, key) ? params[key] : `{${key}}`;
        });
    }

    function hasMessage(key) {
        return Object.prototype.hasOwnProperty.call(messages, key);
    }

    function translateKey(key, params = {}) {
        return hasMessage(key) ? format(messages[key], params) : null;
    }

    window.t = function (key, params = {}) {
        return format(hasMessage(key) ? messages[key] : key, params);
    };

    function translateMappedAttribute(el, attr, textMap) {
        if (!el.hasAttribute(attr)) return;
        const value = el.getAttribute(attr);
        if (!textMap[value]) return;
        const translated = translateKey(textMap[value]);
        if (translated !== null && translated !== value) el.setAttribute(attr, translated);
    }

    function translateTextNode(node, textMap) {
        const original = node.nodeValue;
        const trimmed = original.trim();
        if (!trimmed || !textMap[trimmed]) return;
        const translated = translateKey(textMap[trimmed]);
        if (translated === null) return;
        if (translated === trimmed) return;
        const nextValue = original.replace(trimmed, translated);
        if (nextValue !== original) node.nodeValue = nextValue;
    }

    window.applyI18n = function (root = document) {
        root.querySelectorAll('[data-i18n]').forEach((el) => {
            const translated = translateKey(el.dataset.i18n);
            if (translated === null) return;
            if (el.textContent !== translated) el.textContent = translated;
        });
        root.querySelectorAll('[data-i18n-title]').forEach((el) => {
            const translated = translateKey(el.dataset.i18nTitle);
            if (translated === null) return;
            if (el.title !== translated) el.title = translated;
        });
        root.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
            const translated = translateKey(el.dataset.i18nPlaceholder);
            if (translated === null) return;
            if (el.placeholder !== translated) el.placeholder = translated;
        });
        root.querySelectorAll('[data-i18n-aria-label]').forEach((el) => {
            const translated = translateKey(el.dataset.i18nAriaLabel);
            if (translated === null) return;
            if (el.getAttribute('aria-label') !== translated) el.setAttribute('aria-label', translated);
        });
        const textMap = messages._textMap || {};
        const elementRoot = root.nodeType === Node.ELEMENT_NODE ? root : (root.body || root);
        const mappedElements = elementRoot.querySelectorAll ? elementRoot.querySelectorAll('[title], [placeholder], [aria-label], [value]') : [];
        mappedElements.forEach((el) => {
            translateMappedAttribute(el, 'title', textMap);
            translateMappedAttribute(el, 'placeholder', textMap);
            translateMappedAttribute(el, 'aria-label', textMap);
            if (['BUTTON', 'INPUT'].includes(el.tagName)) translateMappedAttribute(el, 'value', textMap);
        });
        const skipTags = new Set(['SCRIPT', 'STYLE', 'TEXTAREA', 'INPUT', 'CANVAS']);
        const walkerRoot = root.body || root;
        const walker = document.createTreeWalker(walkerRoot, NodeFilter.SHOW_TEXT, {
            acceptNode(node) {
                const parent = node.parentElement;
                if (!parent || skipTags.has(parent.tagName)) return NodeFilter.FILTER_REJECT;
                const trimmed = node.nodeValue.trim();
                return trimmed && textMap[trimmed] ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
            }
        });
        const nodes = [];
        while (walker.nextNode()) nodes.push(walker.currentNode);
        nodes.forEach((node) => translateTextNode(node, textMap));
    };

    document.addEventListener('DOMContentLoaded', () => {
        window.applyI18n();
        const observer = new MutationObserver((mutations) => {
            const textMap = messages._textMap || {};
            mutations.forEach((mutation) => {
                if (mutation.type === 'characterData' && mutation.target.parentElement) {
                    translateTextNode(mutation.target, textMap);
                }
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === Node.ELEMENT_NODE) window.applyI18n(node);
                });
            });
        });
        observer.observe(document.body, { childList: true, subtree: true, characterData: true });
    });
})();
