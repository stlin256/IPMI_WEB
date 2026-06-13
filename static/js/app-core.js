(function () {
    function qs(selector, root = document) {
        return root.querySelector(selector);
    }

    function setText(selector, value, root = document) {
        const node = typeof selector === 'string' ? qs(selector, root) : selector;
        if (!node) return;
        const nextValue = value == null ? '--' : String(value);
        if (node.textContent !== nextValue) node.textContent = nextValue;
    }

    function setClassName(selector, className, root = document) {
        const node = typeof selector === 'string' ? qs(selector, root) : selector;
        if (!node || node.className === className) return;
        node.className = className;
    }

    function setStyle(selector, property, value, root = document) {
        const node = typeof selector === 'string' ? qs(selector, root) : selector;
        if (!node) return;
        const nextValue = value == null ? '' : String(value);
        if (property.startsWith('--')) {
            if (node.style.getPropertyValue(property) !== nextValue) {
                node.style.setProperty(property, nextValue);
            }
            return;
        }
        if (node.style[property] !== nextValue) node.style[property] = nextValue;
    }

    let frameQueue = [];
    let frameId = 0;

    function withFrame(task) {
        return new Promise((resolve, reject) => {
            frameQueue.push({ task, resolve, reject });
            if (frameId) return;
            frameId = window.requestAnimationFrame(() => {
                const queue = frameQueue;
                frameQueue = [];
                frameId = 0;
                queue.forEach((item) => {
                    try {
                        item.resolve(item.task());
                    } catch (error) {
                        item.reject(error);
                    }
                });
            });
        });
    }

    function isAbort(error) {
        return error && error.name === 'AbortError';
    }

    async function fetchJson(url, options = {}) {
        const timeoutMs = options.timeoutMs || 15000;
        const controller = options.signal ? null : new AbortController();
        const signal = options.signal || controller.signal;
        let timer = null;

        if (controller && timeoutMs > 0) {
            timer = window.setTimeout(() => controller.abort(), timeoutMs);
        }

        try {
            const response = await fetch(url, {
                ...options,
                signal,
                headers: {
                    Accept: 'application/json',
                    ...(options.headers || {})
                }
            });
            if (!response.ok) {
                throw new Error(`HTTP ${response.status} ${response.statusText}`.trim());
            }
            return await response.json();
        } finally {
            if (timer) window.clearTimeout(timer);
        }
    }

    function poll(task, intervalMs, options = {}) {
        const visibleOnly = options.visibleOnly !== false;
        const immediate = options.immediate !== false;
        let timerId = null;
        let stopped = false;
        let running = false;

        const run = async () => {
            if (stopped || running) return;
            if (visibleOnly && document.hidden) return;

            running = true;
            try {
                await task();
            } catch (error) {
                if (!isAbort(error)) console.debug('Poll task failed:', error);
            } finally {
                running = false;
            }
        };

        const startTimer = () => {
            timerId = window.setInterval(run, intervalMs);
        };

        const handleVisibility = () => {
            if (!document.hidden) run();
        };

        if (immediate) run();
        startTimer();
        if (visibleOnly) document.addEventListener('visibilitychange', handleVisibility);

        return () => {
            stopped = true;
            if (timerId) window.clearInterval(timerId);
            if (visibleOnly) document.removeEventListener('visibilitychange', handleVisibility);
        };
    }

    function createAbortableLoader(task) {
        let controller = null;
        return async (...args) => {
            if (controller) controller.abort();
            const currentController = new AbortController();
            controller = currentController;
            try {
                return await task(currentController.signal, ...args);
            } finally {
                if (controller === currentController) controller = null;
            }
        };
    }

    function formatBytes(bytes, decimals = 1, suffix = '/s') {
        const value = Number(bytes);
        if (!value || value < 0) return `0 B${suffix}`;
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
        const amount = value / Math.pow(1024, index);
        return `${Number(amount.toFixed(Math.max(0, decimals)))} ${units[index]}${suffix}`;
    }

    async function updateLogDot() {
        const dot = qs('#log-dot');
        if (!dot) return;
        const data = await fetchJson('/api/log_status', { timeoutMs: 8000 });
        dot.classList.toggle('d-none', !data.unread);
    }

    function cssVar(name, fallback = '') {
        const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
        return value || fallback;
    }

    function prefersReducedMotion() {
        return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    }

    function shouldTransitionLink(anchor, event) {
        if (!anchor || event.defaultPrevented || event.button !== 0) return false;
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return false;
        if (anchor.target && anchor.target !== '_self') return false;
        if (anchor.hasAttribute('download')) return false;
        if (anchor.dataset.bsToggle || anchor.getAttribute('role') === 'button') return false;

        const rawHref = anchor.getAttribute('href') || '';
        if (!rawHref || rawHref.startsWith('#')) return false;
        if (/^(javascript:|mailto:|tel:)/i.test(rawHref)) return false;

        let url;
        try {
            url = new URL(anchor.href, window.location.href);
        } catch (_) {
            return false;
        }
        if (url.origin !== window.location.origin) return false;
        if (url.href === window.location.href) return false;
        if (url.pathname === window.location.pathname && url.search === window.location.search && url.hash) return false;
        return true;
    }

    function initPageMotion() {
        const root = document.documentElement;
        if (prefersReducedMotion()) {
            root.classList.add('ipmi-page-ready');
            return;
        }

        root.classList.add('ipmi-motion-enabled');
        const markReady = () => window.requestAnimationFrame(() => root.classList.add('ipmi-page-ready'));
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', markReady, { once: true });
        } else {
            markReady();
        }

        document.addEventListener('click', (event) => {
            const anchor = event.target.closest && event.target.closest('a[href]');
            if (!shouldTransitionLink(anchor, event)) return;
            event.preventDefault();
            root.classList.add('ipmi-page-leaving');
            window.setTimeout(() => {
                window.location.href = anchor.href;
            }, 120);
        }, true);

        window.addEventListener('pageshow', () => {
            root.classList.remove('ipmi-page-leaving');
            root.classList.add('ipmi-page-ready');
        });
    }

    window.IPMI = {
        qs,
        setText,
        setClassName,
        setStyle,
        withFrame,
        fetchJson,
        poll,
        createAbortableLoader,
        formatBytes,
        updateLogDot,
        cssVar,
        isAbort,
        prefersReducedMotion
    };

    initPageMotion();
})();
