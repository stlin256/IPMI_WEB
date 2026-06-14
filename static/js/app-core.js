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

    const pageCleanups = [];
    const pageTimers = new Set();
    const pageListeners = [];
    let trackingDepth = 0;

    const nativeSetTimeout = window.setTimeout.bind(window);
    const nativeClearTimeout = window.clearTimeout.bind(window);
    const nativeSetInterval = window.setInterval.bind(window);
    const nativeClearInterval = window.clearInterval.bind(window);
    const nativeAddEventListener = EventTarget.prototype.addEventListener;
    const nativeRemoveEventListener = EventTarget.prototype.removeEventListener;
    const nativeDocumentAddEventListener = document.addEventListener.bind(document);
    const nativeFetch = window.fetch.bind(window);
    const jsonCache = new Map();
    const defaultJsonCacheTtlMs = 6000;

    function isTrackingPageResources() {
        return trackingDepth > 0;
    }

    function cloneJson(data) {
        if (data == null || typeof data !== 'object') return data;
        try {
            if (typeof structuredClone === 'function') return structuredClone(data);
        } catch (_) {}
        return JSON.parse(JSON.stringify(data));
    }

    function requestUrl(input) {
        if (typeof input === 'string') return input;
        if (input && typeof input.url === 'string') return input.url;
        return '';
    }

    function requestMethod(input, options = {}) {
        if (options.method) return String(options.method).toUpperCase();
        if (input && typeof input.method === 'string') return input.method.toUpperCase();
        return 'GET';
    }

    function normalizeApiUrl(url) {
        let parsed;
        try {
            parsed = new URL(url, window.location.origin);
        } catch (_) {
            return '';
        }
        if (parsed.origin !== window.location.origin || !parsed.pathname.startsWith('/api/')) return '';
        parsed.searchParams.delete('t');
        parsed.searchParams.delete('_');
        const params = Array.from(parsed.searchParams.entries()).sort(([aKey, aVal], [bKey, bVal]) => {
            if (aKey === bKey) return aVal.localeCompare(bVal);
            return aKey.localeCompare(bKey);
        });
        parsed.search = '';
        params.forEach(([key, value]) => parsed.searchParams.append(key, value));
        return `${parsed.pathname}${parsed.search}`;
    }

    function isCacheableApiRequest(input, options = {}) {
        if (requestMethod(input, options) !== 'GET') return false;
        if (options.body) return false;
        if (options.cache === 'reload' || options.cache === 'no-store') return false;
        return Boolean(normalizeApiUrl(requestUrl(input)));
    }

    function getCachedJson(url) {
        const key = normalizeApiUrl(url);
        if (!key) return null;
        const entry = jsonCache.get(key);
        if (!entry) return null;
        if (entry.expiresAt <= Date.now()) {
            jsonCache.delete(key);
            return null;
        }
        return entry;
    }

    function seedJsonCache(url, data, ttlMs = defaultJsonCacheTtlMs) {
        const key = normalizeApiUrl(url);
        if (!key) return null;
        const entry = {
            data: cloneJson(data),
            expiresAt: Date.now() + ttlMs
        };
        jsonCache.set(key, entry);
        return entry;
    }

    function jsonResponse(data) {
        return new Response(JSON.stringify(cloneJson(data)), {
            status: 200,
            statusText: 'OK',
            headers: {
                'Content-Type': 'application/json',
                'X-IPMI-JSON-Cache': 'hit'
            }
        });
    }

    function runWithPageTracking(task) {
        trackingDepth += 1;
        try {
            const result = task();
            if (result && typeof result.then === 'function') {
                return result.finally(() => {
                    trackingDepth -= 1;
                });
            }
            trackingDepth -= 1;
            return result;
        } catch (error) {
            trackingDepth -= 1;
            throw error;
        }
    }

    function startPageTracking() {
        trackingDepth += 1;
        let stopped = false;
        return () => {
            if (stopped) return;
            stopped = true;
            trackingDepth -= 1;
        };
    }

    function addPageTimer(timer) {
        if (isTrackingPageResources()) pageTimers.add(timer);
    }

    window.setTimeout = function trackedSetTimeout(handler, timeout, ...args) {
        const timer = nativeSetTimeout(handler, timeout, ...args);
        addPageTimer({ type: 'timeout', id: timer });
        return timer;
    };

    window.clearTimeout = function trackedClearTimeout(timerId) {
        pageTimers.forEach((timer) => {
            if (timer.id === timerId) pageTimers.delete(timer);
        });
        return nativeClearTimeout(timerId);
    };

    window.setInterval = function trackedSetInterval(handler, timeout, ...args) {
        const timer = nativeSetInterval(handler, timeout, ...args);
        addPageTimer({ type: 'interval', id: timer });
        return timer;
    };

    window.clearInterval = function trackedClearInterval(timerId) {
        pageTimers.forEach((timer) => {
            if (timer.id === timerId) pageTimers.delete(timer);
        });
        return nativeClearInterval(timerId);
    };

    EventTarget.prototype.addEventListener = function trackedAddEventListener(type, listener, options) {
        if (isTrackingPageResources() && listener) {
            pageListeners.push({ target: this, type, listener, options });
        }
        return nativeAddEventListener.call(this, type, listener, options);
    };

    EventTarget.prototype.removeEventListener = function trackedRemoveEventListener(type, listener, options) {
        for (let i = pageListeners.length - 1; i >= 0; i -= 1) {
            const item = pageListeners[i];
            if (item.target === this && item.type === type && item.listener === listener) {
                pageListeners.splice(i, 1);
            }
        }
        return nativeRemoveEventListener.call(this, type, listener, options);
    };

    document.addEventListener = function trackedDocumentAddEventListener(type, listener, options) {
        if (type === 'DOMContentLoaded' && document.readyState !== 'loading' && typeof listener === 'function') {
            const timer = nativeSetTimeout(() => runWithPageTracking(() => listener.call(document, new Event('DOMContentLoaded'))), 0);
            addPageTimer({ type: 'timeout', id: timer });
            return undefined;
        }
        if (type === 'DOMContentLoaded' && typeof listener === 'function') {
            const wrapped = function wrappedDOMContentLoaded(event) {
                return runWithPageTracking(() => listener.call(this, event));
            };
            return nativeDocumentAddEventListener(type, wrapped, options);
        }
        return nativeDocumentAddEventListener(type, listener, options);
    };

    function addCleanup(cleanup) {
        if (typeof cleanup !== 'function') return cleanup;
        pageCleanups.push(cleanup);
        return cleanup;
    }

    function disposeBootstrap(root = document) {
        if (!window.bootstrap || !root.querySelectorAll) return;
        const componentMap = [
            ['Modal', '.modal'],
            ['Offcanvas', '.offcanvas'],
            ['Toast', '.toast'],
            ['Tooltip', '[data-bs-toggle="tooltip"]'],
            ['Popover', '[data-bs-toggle="popover"]'],
            ['Collapse', '.collapse']
        ];
        componentMap.forEach(([name, selector]) => {
            const Component = window.bootstrap[name];
            if (!Component || typeof Component.getInstance !== 'function') return;
            root.querySelectorAll(selector).forEach((node) => {
                const instance = Component.getInstance(node);
                if (instance && typeof instance.dispose === 'function') {
                    try { instance.dispose(); } catch (_) {}
                }
            });
        });
        document.querySelectorAll('.modal-backdrop, .offcanvas-backdrop').forEach((node) => node.remove());
        document.body.classList.remove('modal-open');
        document.body.style.removeProperty('overflow');
        document.body.style.removeProperty('padding-right');
    }

    function destroyPage() {
        while (pageCleanups.length) {
            const cleanup = pageCleanups.pop();
            try { cleanup(); } catch (error) { console.debug('Page cleanup failed:', error); }
        }

        pageTimers.forEach((timer) => {
            if (timer.type === 'interval') nativeClearInterval(timer.id);
            else nativeClearTimeout(timer.id);
        });
        pageTimers.clear();

        while (pageListeners.length) {
            const { target, type, listener, options } = pageListeners.pop();
            try { nativeRemoveEventListener.call(target, type, listener, options); } catch (_) {}
        }

        if (window.IPMICharts && typeof window.IPMICharts.destroyAll === 'function') {
            window.IPMICharts.destroyAll();
        }
        disposeBootstrap(document);
    }

    async function networkJson(url, options = {}) {
        const timeoutMs = options.timeoutMs || 15000;
        const controller = options.signal ? null : new AbortController();
        const signal = options.signal || controller.signal;
        let timer = null;

        if (controller && timeoutMs > 0) {
            timer = nativeSetTimeout(() => controller.abort(), timeoutMs);
        }

        try {
            const response = await nativeFetch(url, {
                ...options,
                signal,
                credentials: options.credentials || 'same-origin',
                headers: {
                    Accept: 'application/json',
                    ...(options.headers || {})
                }
            });
            if (!response.ok) {
                throw new Error(`HTTP ${response.status} ${response.statusText}`.trim());
            }
            const data = await response.json();
            if (requestMethod(url, options) === 'GET') {
                seedJsonCache(url, data, options.cacheTtlMs || defaultJsonCacheTtlMs);
            }
            return data;
        } finally {
            if (timer) nativeClearTimeout(timer);
        }
    }

    async function fetchJson(url, options = {}) {
        const canUseCache = isCacheableApiRequest(url, options);
        if (canUseCache) {
            const cached = getCachedJson(url);
            if (cached && cached.data !== undefined) return cloneJson(cached.data);
            if (cached && cached.promise) return cloneJson(await cached.promise);
        }
        return networkJson(url, options);
    }

    function prefetchJson(url, options = {}) {
        const key = normalizeApiUrl(url);
        if (!key) return Promise.resolve(null);

        const cached = getCachedJson(url);
        if (cached && cached.data !== undefined) return Promise.resolve(cloneJson(cached.data));
        if (cached && cached.promise) return cached.promise.then(cloneJson);

        const timeoutMs = options.timeoutMs || 12000;
        const ttlMs = options.cacheTtlMs || defaultJsonCacheTtlMs;
        const controller = options.signal ? null : new AbortController();
        const signal = options.signal || controller.signal;
        let timer = null;

        if (controller && timeoutMs > 0) {
            timer = nativeSetTimeout(() => controller.abort(), timeoutMs);
        }

        const promise = nativeFetch(url, {
            signal,
            credentials: 'same-origin',
            headers: {
                Accept: 'application/json',
                ...(options.headers || {})
            }
        }).then((response) => {
            if (!response.ok) throw new Error(`HTTP ${response.status} ${response.statusText}`.trim());
            return response.json();
        }).then((data) => {
            seedJsonCache(url, data, ttlMs);
            return cloneJson(data);
        }).catch((error) => {
            const current = jsonCache.get(key);
            if (current && current.promise === promise) jsonCache.delete(key);
            throw error;
        }).finally(() => {
            if (timer) nativeClearTimeout(timer);
        });

        jsonCache.set(key, {
            promise,
            expiresAt: Date.now() + timeoutMs + ttlMs
        });
        return promise;
    }

    window.fetch = function cachedFetch(input, options = {}) {
        if (isCacheableApiRequest(input, options)) {
            const cached = getCachedJson(requestUrl(input));
            if (cached && cached.data !== undefined) return Promise.resolve(jsonResponse(cached.data));
            if (cached && cached.promise) return cached.promise.then(jsonResponse);
        }

        const responsePromise = nativeFetch(input, options);
        if (!isCacheableApiRequest(input, options)) return responsePromise;

        return responsePromise.then((response) => {
            const contentType = response.headers ? response.headers.get('content-type') || '' : '';
            if (response.ok && contentType.includes('application/json')) {
                response.clone().json()
                    .then((data) => seedJsonCache(requestUrl(input), data))
                    .catch(() => {});
            }
            return response;
        });
    };

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
            timerId = nativeSetInterval(run, intervalMs);
        };

        const handleVisibility = () => {
            if (!document.hidden) run();
        };

        if (immediate) run();
        startTimer();
        if (visibleOnly) document.addEventListener('visibilitychange', handleVisibility);

        const stop = () => {
            stopped = true;
            if (timerId) nativeClearInterval(timerId);
            if (visibleOnly) document.removeEventListener('visibilitychange', handleVisibility);
        };

        addCleanup(stop);
        return stop;
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

        window.addEventListener('pageshow', () => {
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
        prefetchJson,
        seedJsonCache,
        poll,
        createAbortableLoader,
        formatBytes,
        updateLogDot,
        cssVar,
        isAbort,
        prefersReducedMotion,
        addCleanup,
        destroyPage,
        disposeBootstrap,
        runWithPageTracking,
        startPageTracking
    };

    initPageMotion();
})();
