(function () {
    const storageKey = 'ipmi.web.theme';
    const root = document.documentElement;

    function validTheme(value) {
        return value === 'light' || value === 'dark';
    }

    function preferredTheme() {
        try {
            const saved = window.localStorage.getItem(storageKey);
            if (validTheme(saved)) return saved;
        } catch (_e) {}
        return root.getAttribute('data-bs-theme') || 'light';
    }

    function setTheme(theme) {
        const nextTheme = validTheme(theme) ? theme : 'light';
        root.setAttribute('data-bs-theme', nextTheme);
        root.style.colorScheme = nextTheme;
        try {
            window.localStorage.setItem(storageKey, nextTheme);
        } catch (_e) {}
        updateThemeColor(nextTheme);
        window.dispatchEvent(new CustomEvent('ipmi:theme-change', { detail: { theme: nextTheme } }));
    }

    function updateThemeColor(theme) {
        let meta = document.querySelector('meta[name="theme-color"]');
        if (!meta) {
            meta = document.createElement('meta');
            meta.setAttribute('name', 'theme-color');
            document.head.appendChild(meta);
        }
        meta.setAttribute('content', theme === 'light' ? '#f3ead7' : '#12110e');
    }

    function labelFor(theme) {
        const isZh = (root.lang || '').toLowerCase().startsWith('zh');
        if (theme === 'dark') return isZh ? '切换为浅色模式' : 'Switch to light mode';
        return isZh ? '切换为深色模式' : 'Switch to dark mode';
    }

    function syncButton(button) {
        const theme = root.getAttribute('data-bs-theme') || 'light';
        const icon = theme === 'dark' ? 'fa-sun' : 'fa-moon';
        let iconNode = button.querySelector('i');
        if (!iconNode) {
            button.textContent = '';
            iconNode = document.createElement('i');
            iconNode.setAttribute('aria-hidden', 'true');
            button.appendChild(iconNode);
        }
        const iconClass = `fas ${icon}`;
        if (iconNode.className !== iconClass) iconNode.className = iconClass;
        button.setAttribute('aria-label', labelFor(theme));
        button.setAttribute('title', labelFor(theme));
    }

    function bindButton(button) {
        if (button.dataset.ipmiThemeBound === 'true') return;
        button.dataset.ipmiThemeBound = 'true';
        button.addEventListener('click', () => {
            const current = root.getAttribute('data-bs-theme') || 'light';
            setTheme(current === 'dark' ? 'light' : 'dark');
            syncButton(button);
        });
    }

    function createButton(extraClass) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = `btn btn-outline-secondary ipmi-theme-toggle ${extraClass || ''}`.trim();
        bindButton(button);
        syncButton(button);
        return button;
    }

    function mountThemeToggle() {
        const existing = document.querySelectorAll('.ipmi-theme-toggle');
        if (existing.length) {
            existing.forEach((button) => {
                bindButton(button);
                syncButton(button);
            });
            return;
        }

        const navbar = document.querySelector('.navbar .container-fluid');
        if (navbar) {
            const button = createButton('me-2');
            const target = navbar.querySelector('a[href="/logout"], a[href="/hardware"].btn');
            if (target) {
                target.parentElement.insertBefore(button, target);
            } else {
                navbar.appendChild(button);
            }
            return;
        }

        const button = createButton('ipmi-floating-theme-toggle');
        document.body.appendChild(button);
    }

    setTheme(preferredTheme());

    window.IPMITheme = {
        get: () => root.getAttribute('data-bs-theme') || 'light',
        set: setTheme,
        toggle: () => setTheme((root.getAttribute('data-bs-theme') || 'light') === 'dark' ? 'light' : 'dark'),
        mountToggle: mountThemeToggle,
        chart: () => {
            const styles = getComputedStyle(root);
            return {
                text: styles.getPropertyValue('--text-main').trim(),
                muted: styles.getPropertyValue('--text-muted').trim(),
                grid: styles.getPropertyValue('--border-color').trim(),
                panel: styles.getPropertyValue('--bg-card').trim()
            };
        }
    };

    document.addEventListener('DOMContentLoaded', mountThemeToggle);
    window.addEventListener('ipmi:theme-change', () => {
        document.querySelectorAll('.ipmi-theme-toggle').forEach(syncButton);
    });
})();
