(function () {
    const storageKey = 'ipmi.web.theme';
    const root = document.documentElement;
    const motionClass = 'ipmi-theme-shifting';
    const loginMotionClass = 'login-theme-shifting';
    const themeSwitchDelayMs = 84;
    const themeMotionTotalMs = 432;
    let themeMotionTimer = null;
    let themeSwitchTimer = null;

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
        root.style.colorScheme = 'only light';
        try {
            window.localStorage.setItem(storageKey, nextTheme);
        } catch (_e) {}
        updateColorSchemeMeta();
        updateThemeColor(nextTheme);
        window.dispatchEvent(new CustomEvent('ipmi:theme-change', { detail: { theme: nextTheme } }));
    }

    function prefersReducedMotion() {
        return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    }

    function updateVisualViewportMetrics() {
        const viewport = window.visualViewport;
        const visualWidth = viewport ? viewport.width : window.innerWidth;
        const offsetLeft = viewport ? viewport.offsetLeft : 0;
        const rightOffset = Math.max(0, window.innerWidth - visualWidth - offsetLeft);
        const nextRightOffset = `${rightOffset.toFixed(2)}px`;
        if (root.style.getPropertyValue('--ipmi-visual-right-offset') !== nextRightOffset) {
            root.style.setProperty('--ipmi-visual-right-offset', nextRightOffset);
        }
    }

    function installThemeMotionStyles() {
        if (document.getElementById('ipmi-theme-motion-style')) return;
        const style = document.createElement('style');
        style.id = 'ipmi-theme-motion-style';
        style.textContent = `
body {
    --ipmi-theme-x: calc(100vw - 2rem);
    --ipmi-theme-y: 2rem;
}
body::after {
    content: "";
    position: fixed;
    inset: 0;
    z-index: 2070;
    pointer-events: none;
    opacity: 0;
    clip-path: circle(0 at var(--ipmi-theme-x) var(--ipmi-theme-y));
    background:
        radial-gradient(circle at var(--ipmi-theme-x) var(--ipmi-theme-y), color-mix(in srgb, var(--accent-yellow) 42%, transparent), transparent 9rem),
        radial-gradient(circle at var(--ipmi-theme-x) var(--ipmi-theme-y), color-mix(in srgb, var(--bg-body) 78%, transparent), transparent 62vmax),
        linear-gradient(135deg, color-mix(in srgb, var(--accent-blue) 18%, transparent), color-mix(in srgb, var(--accent-red) 16%, transparent));
    filter: blur(14px) saturate(1.2);
    mix-blend-mode: screen;
}
html[data-bs-theme="light"] body::after {
    mix-blend-mode: multiply;
    background:
        radial-gradient(circle at var(--ipmi-theme-x) var(--ipmi-theme-y), color-mix(in srgb, var(--accent-yellow) 34%, transparent), transparent 8rem),
        radial-gradient(circle at var(--ipmi-theme-x) var(--ipmi-theme-y), color-mix(in srgb, var(--bg-body) 74%, transparent), transparent 62vmax),
        linear-gradient(135deg, color-mix(in srgb, var(--accent-blue) 12%, transparent), color-mix(in srgb, var(--accent-red) 10%, transparent));
}
@keyframes ipmi-theme-wash {
    0% {
        opacity: 0;
        clip-path: circle(0 at var(--ipmi-theme-x) var(--ipmi-theme-y));
        filter: blur(16px) saturate(0.95);
    }
    32% {
        opacity: 0.68;
        clip-path: circle(44vmax at var(--ipmi-theme-x) var(--ipmi-theme-y));
        filter: blur(8px) saturate(1.22);
    }
    72% {
        opacity: 0.28;
        clip-path: circle(112vmax at var(--ipmi-theme-x) var(--ipmi-theme-y));
        filter: blur(4px) saturate(1.08);
    }
    100% {
        opacity: 0;
        clip-path: circle(142vmax at var(--ipmi-theme-x) var(--ipmi-theme-y));
        filter: blur(2px) saturate(1);
    }
}
@keyframes ipmi-theme-surface-lift {
    0% { filter: brightness(0.96) saturate(0.96); }
    42% { filter: brightness(1.14) saturate(1.18); }
    100% { filter: brightness(1) saturate(1); }
}
@media (prefers-reduced-motion: no-preference) {
    body,
    .navbar,
    .card,
    .modal-content,
    .dropdown-menu,
    .terminal-body,
    .login-card,
    .form-control,
    .form-select,
    .input-group-text,
    .table,
    .table-dark {
        transition:
            background-color 252ms cubic-bezier(0.22, 0.61, 0.36, 1),
            border-color 252ms cubic-bezier(0.22, 0.61, 0.36, 1),
            box-shadow 252ms cubic-bezier(0.22, 0.61, 0.36, 1),
            color 252ms cubic-bezier(0.22, 0.61, 0.36, 1),
            filter 252ms cubic-bezier(0.22, 0.61, 0.36, 1);
    }
    .btn,
    .nav-link {
        transition:
            transform 160ms ease,
            background-color 252ms cubic-bezier(0.22, 0.61, 0.36, 1),
            border-color 252ms cubic-bezier(0.22, 0.61, 0.36, 1),
            box-shadow 252ms cubic-bezier(0.22, 0.61, 0.36, 1),
            color 252ms cubic-bezier(0.22, 0.61, 0.36, 1),
            filter 252ms cubic-bezier(0.22, 0.61, 0.36, 1);
    }
    html.ipmi-theme-shifting body::after {
        animation: ipmi-theme-wash 384ms cubic-bezier(0.16, 1, 0.3, 1) both;
    }
    html.ipmi-theme-shifting:not(.login-theme-shifting) body > :not(script):not(style):not(.navbar):not(.modal):not(.modal-backdrop):not(.toast-container) {
        animation: ipmi-theme-surface-lift 384ms cubic-bezier(0.16, 1, 0.3, 1) both;
    }
}
`;
        document.head.appendChild(style);
    }

    function setThemeMotionPoint(button) {
        const target = button || document.querySelector('.ipmi-theme-toggle');
        if (!target || !document.body) return;
        const rect = target.getBoundingClientRect();
        const x = `${rect.left + rect.width / 2}px`;
        const y = `${rect.top + rect.height / 2}px`;
        document.body.style.setProperty('--ipmi-theme-x', x);
        document.body.style.setProperty('--ipmi-theme-y', y);
        document.body.style.setProperty('--login-theme-x', x);
        document.body.style.setProperty('--login-theme-y', y);
    }

    function startThemeMotion(button) {
        if (!document.body || prefersReducedMotion()) return false;
        installThemeMotionStyles();
        setThemeMotionPoint(button);
        root.classList.remove(motionClass, loginMotionClass);
        void root.offsetWidth;
        root.classList.add(motionClass);
        if (document.querySelector('.login-shell')) root.classList.add(loginMotionClass);

        clearTimeout(themeMotionTimer);
        themeMotionTimer = setTimeout(() => {
            root.classList.remove(motionClass, loginMotionClass);
        }, themeMotionTotalMs);
        return true;
    }

    function toggleTheme(button) {
        const current = root.getAttribute('data-bs-theme') || 'light';
        const nextTheme = current === 'dark' ? 'light' : 'dark';
        if (prefersReducedMotion()) {
            setTheme(nextTheme);
            return;
        }
        if (root.classList.contains(motionClass)) return;
        startThemeMotion(button);
        clearTimeout(themeSwitchTimer);
        themeSwitchTimer = setTimeout(() => {
            setTheme(nextTheme);
        }, themeSwitchDelayMs);
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

    function updateColorSchemeMeta() {
        let meta = document.querySelector('meta[name="color-scheme"]');
        if (!meta) {
            meta = document.createElement('meta');
            meta.setAttribute('name', 'color-scheme');
            document.head.appendChild(meta);
        }
        meta.setAttribute('content', 'only light');
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
        button.addEventListener('click', (event) => {
            event.preventDefault();
            toggleTheme(button);
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
    installThemeMotionStyles();
    updateVisualViewportMetrics();

    window.IPMITheme = {
        get: () => root.getAttribute('data-bs-theme') || 'light',
        set: setTheme,
        toggle: () => toggleTheme(document.querySelector('.ipmi-theme-toggle')),
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
    window.addEventListener('resize', updateVisualViewportMetrics, { passive: true });
    if (window.visualViewport) {
        window.visualViewport.addEventListener('resize', updateVisualViewportMetrics, { passive: true });
    }
    window.addEventListener('ipmi:theme-change', () => {
        document.querySelectorAll('.ipmi-theme-toggle').forEach(syncButton);
    });
})();
