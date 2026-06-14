(function () {
    const routes = new Set(['/hardware', '/resources', '/gpu', '/history', '/logs']);
    const prefetchCache = new Map();
    const scriptCache = new Set(Array.from(document.scripts).map((script) => script.src).filter(Boolean));
    const managedHeadSelector = 'style[data-ipmi-pjax-head]';
    let activeController = null;
    let currentPath = window.location.pathname;

    function normalizePath(url) {
        return url.pathname.replace(/\/+$/, '') || '/';
    }

    function isManagedLink(link) {
        if (!link || link.target || link.hasAttribute('download')) return false;
        if (link.dataset.pjax === 'false') return false;

        let url;
        try {
            url = new URL(link.href, window.location.href);
        } catch (_) {
            return false;
        }
        if (url.origin !== window.location.origin) return false;
        return routes.has(normalizePath(url));
    }

    function parsePage(html, url) {
        const doc = new DOMParser().parseFromString(html, 'text/html');
        if (!doc.body) throw new Error(`No body element found in ${url}`);

        const body = doc.body.cloneNode(true);
        body.querySelectorAll('script').forEach((script) => script.remove());

        return {
            title: doc.title,
            bodyHtml: body.innerHTML,
            bodyClass: doc.body ? doc.body.className : '',
            htmlLang: doc.documentElement.lang || document.documentElement.lang,
            headStyles: Array.from(doc.head.querySelectorAll('style')).map((style) => {
                const clone = style.cloneNode(true);
                clone.dataset.ipmiPjaxHead = 'page';
                return clone.outerHTML;
            }),
            scripts: Array.from(doc.querySelectorAll('script')).map((script) => {
                const src = script.getAttribute('src');
                if (src) return { src: new URL(src, window.location.origin).href };
                return { code: script.textContent || '' };
            })
        };
    }

    function routeDataUrls(path) {
        const hardwareHours = localStorage.getItem('hw_hist_time_range') || '24';
        const historyHours = localStorage.getItem('hist_time_range') || '1';
        const energyStart = localStorage.getItem('energy_start_ts') || '0';
        const urlSets = {
            '/hardware': [
                '/api/status_hardware',
                '/api/history_custom?hours=' + encodeURIComponent(hardwareHours) + '&energy=0',
                '/api/config',
                '/api/dashboard_options',
                '/api/log_status',
                '/api/update_notice'
            ],
            '/resources': [
                '/api/status_resources',
                '/api/history',
                '/api/log_status'
            ],
            '/gpu': [
                '/api/status_gpu',
                '/api/config/gpu',
                '/api/log_status'
            ],
            '/history': [
                '/api/dashboard_options',
                '/api/history_custom?hours=' + encodeURIComponent(historyHours) + '&energy_start=' + encodeURIComponent(energyStart),
                '/api/log_status'
            ],
            '/logs': [
                '/api/log_delay_config',
                '/api/audit_logs?limit=100&offset=0',
                '/api/recording_stats'
            ]
        };
        return urlSets[path] || [];
    }

    async function prefetchRouteData(path, options = {}) {
        if (!window.IPMI || typeof window.IPMI.prefetchJson !== 'function') return;
        const urls = routeDataUrls(path);
        if (!urls.length) return;
        const tasks = urls.map((url) => {
            return window.IPMI.prefetchJson(url, {
                signal: options.signal,
                timeoutMs: options.timeoutMs || 12000,
                cacheTtlMs: options.cacheTtlMs || 15000
            });
        });
        await Promise.allSettled(tasks);
    }

    function waitForWarmData(path, signal) {
        const dataPromise = prefetchRouteData(path, {
            signal,
            timeoutMs: 8000,
            cacheTtlMs: 15000
        });
        const timeoutPromise = new Promise((resolve) => {
            setTimeout(resolve, 2200);
        });
        return Promise.race([dataPromise, timeoutPromise]);
    }

    async function fetchPage(path, options = {}) {
        const cached = prefetchCache.get(path);
        if (cached && !options.force) return cached;

        const response = await fetch(path, {
            signal: options.signal,
            headers: {
                Accept: 'text/html',
                'X-IPMI-PJAX': '1'
            },
            credentials: 'same-origin'
        });

        if (response.redirected || response.url.includes('/login')) {
            window.location.href = response.url;
            throw new Error('Redirected to login');
        }
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const page = parsePage(await response.text(), path);
        prefetchCache.set(path, page);
        return page;
    }

    function updateNavigation(path) {
        document.querySelectorAll('.navbar .nav-link').forEach((link) => {
            let linkPath = '';
            try {
                linkPath = normalizePath(new URL(link.href, window.location.href));
            } catch (_) {}
            link.classList.toggle('active', linkPath === path);
        });
    }

    function copyBodyState(page) {
        document.body.className = page.bodyClass;
        if (page.htmlLang) document.documentElement.lang = page.htmlLang;
    }

    function topLevelNavbar(root) {
        return Array.from(root.children).find((node) => node.matches && node.matches('.navbar'));
    }

    function isStableMainNavbar(navbar) {
        return Boolean(
            navbar
            && navbar.querySelector('#log-dot')
            && navbar.querySelector('.navbar-nav.me-auto')
        );
    }

    function syncStableNavbar(currentNavbar, incomingNavbar) {
        const currentName = currentNavbar.querySelector('.navbar-brand .fw-bold');
        const incomingName = incomingNavbar.querySelector('.navbar-brand .fw-bold');
        if (currentName && incomingName && currentName.textContent !== incomingName.textContent) {
            currentName.textContent = incomingName.textContent;
        }
    }

    function replaceBodyHtml(page) {
        const template = document.createElement('template');
        template.innerHTML = page.bodyHtml;
        const currentNavbar = topLevelNavbar(document.body);
        const incomingNavbar = topLevelNavbar(template.content);

        if (isStableMainNavbar(currentNavbar) && isStableMainNavbar(incomingNavbar)) {
            syncStableNavbar(currentNavbar, incomingNavbar);
            incomingNavbar.remove();
            document.body.replaceChildren(currentNavbar, ...Array.from(template.content.childNodes));
            return;
        }

        document.body.innerHTML = page.bodyHtml;
    }

    function markInitialHeadStyles() {
        document.head.querySelectorAll('style:not([data-ipmi-pjax-head])').forEach((style) => {
            style.dataset.ipmiPjaxHead = 'initial';
        });
    }

    function syncHeadStyles(page) {
        document.head.querySelectorAll(managedHeadSelector).forEach((style) => style.remove());
        page.headStyles.forEach((styleHtml) => {
            document.head.insertAdjacentHTML('beforeend', styleHtml);
        });
    }

    function isPageScript(src) {
        return /\/static\/js\/pages\//.test(src);
    }

    function loadScript(src) {
        if (!isPageScript(src) && scriptCache.has(src)) return Promise.resolve();
        return new Promise((resolve, reject) => {
            const stopTracking = isPageScript(src) && window.IPMI && typeof window.IPMI.startPageTracking === 'function'
                ? window.IPMI.startPageTracking()
                : null;
            const script = document.createElement('script');
            script.src = src;
            script.onload = () => {
                if (stopTracking) stopTracking();
                if (!isPageScript(src)) scriptCache.add(src);
                resolve();
            };
            script.onerror = () => {
                if (stopTracking) stopTracking();
                reject(new Error(`Failed to load ${src}`));
            };
            document.body.appendChild(script);
        });
    }

    function exportFunctionNames(code) {
        const names = new Set();
        const pattern = /(?:^|\n)\s*(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/g;
        let match = pattern.exec(code);
        while (match) {
            names.add(match[1]);
            match = pattern.exec(code);
        }
        return Array.from(names).map((name) => {
            return `try { if (typeof ${name} === 'function') window.${name} = ${name}; } catch (_) {}`;
        }).join('\n');
    }

    function executeInlineScript(code) {
        const exportCode = exportFunctionNames(code);
        window.IPMI.runWithPageTracking(() => {
            const runner = new Function(`${code}\n${exportCode}`);
            runner.call(window);
        });
    }

    async function runPageScripts(page) {
        for (const script of page.scripts) {
            if (script.src) {
                await loadScript(script.src);
            } else if (script.code && script.code.trim()) {
                executeInlineScript(script.code);
            }
        }

        if (window.applyI18n) window.applyI18n(document);
        if (window.IPMITheme && typeof window.IPMITheme.mountToggle === 'function') {
            window.IPMITheme.mountToggle();
        }
    }

    function nextFrame() {
        return new Promise((resolve) => {
            window.requestAnimationFrame(() => resolve());
        });
    }

    async function settleHydratedPage() {
        await Promise.resolve();
        await nextFrame();
        await Promise.resolve();
        await nextFrame();
    }

    async function render(path, options = {}) {
        if (!routes.has(path)) {
            window.location.href = path;
            return;
        }

        if (activeController) activeController.abort();
        activeController = new AbortController();
        const controller = activeController;
        document.documentElement.classList.add('ipmi-pjax-loading');

        try {
            const pagePromise = fetchPage(path, { signal: controller.signal, force: options.force });
            const dataPromise = waitForWarmData(path, controller.signal);
            const page = await pagePromise;
            await dataPromise;
            if (controller.signal.aborted) return;

            if (window.IPMI && typeof window.IPMI.destroyPage === 'function') {
                window.IPMI.destroyPage();
            }
            if (window.IPMI && typeof window.IPMI.preparePageMotion === 'function') {
                window.IPMI.preparePageMotion();
            }

            copyBodyState(page);
            syncHeadStyles(page);
            replaceBodyHtml(page);
            document.title = page.title || document.title;
            updateNavigation(path);
            if (window.IPMI && typeof window.IPMI.primePageMotion === 'function') {
                window.IPMI.primePageMotion(document);
            }

            await runPageScripts(page);
            await settleHydratedPage();
            if (window.IPMI && typeof window.IPMI.finishPageMotion === 'function') {
                window.IPMI.finishPageMotion(document);
            }

            currentPath = path;

            if (!options.replace) {
                window.history.pushState({ pjax: true, path }, '', path);
            } else {
                window.history.replaceState({ pjax: true, path }, '', path);
            }

            prefetchNeighbors(path);
            window.scrollTo({ top: 0, behavior: 'auto' });
        } catch (error) {
            if (window.IPMI && window.IPMI.isAbort(error)) return;
            console.debug('PJAX render failed, falling back to full navigation:', error);
            window.location.href = path;
        } finally {
            if (activeController === controller) activeController = null;
            document.documentElement.classList.remove('ipmi-pjax-loading');
        }
    }

    function prefetch(path) {
        if (!routes.has(path)) return;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 12000);
        Promise.allSettled([
            prefetchCache.has(path) ? Promise.resolve(prefetchCache.get(path)) : fetchPage(path, { signal: controller.signal }),
            prefetchRouteData(path, { signal: controller.signal })
        ])
            .catch((error) => {
                if (!window.IPMI.isAbort(error)) console.debug('PJAX prefetch failed:', path, error);
            })
            .finally(() => clearTimeout(timeout));
    }

    function prefetchNeighbors(path) {
        if (!('requestIdleCallback' in window)) {
            setTimeout(() => {
                routes.forEach((route) => {
                    if (route !== path) prefetch(route);
                });
            }, 800);
            return;
        }
        window.requestIdleCallback(() => {
            routes.forEach((route) => {
                if (route !== path) prefetch(route);
            });
        }, { timeout: 2500 });
    }

    function handleClick(event) {
        if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
            return;
        }
        const link = event.target.closest('a');
        if (!isManagedLink(link)) return;
        const path = normalizePath(new URL(link.href, window.location.href));
        event.preventDefault();
        if (path === currentPath) return;
        render(path);
    }

    function handlePrefetch(event) {
        const link = event.target.closest('a');
        if (!isManagedLink(link)) return;
        const path = normalizePath(new URL(link.href, window.location.href));
        if (path !== currentPath) prefetch(path);
    }

    document.addEventListener('click', handleClick);
    document.addEventListener('pointerover', handlePrefetch);
    document.addEventListener('focusin', handlePrefetch);
    window.addEventListener('popstate', () => {
        const path = normalizePath(new URL(window.location.href));
        render(path, { replace: true });
    });

    window.IPMIPJAX = {
        prefetch,
        render,
        clearCache: () => prefetchCache.clear()
    };

    markInitialHeadStyles();
    window.history.replaceState({ pjax: true, path: currentPath }, '', window.location.href);
    if (routes.has(currentPath)) prefetchNeighbors(currentPath);
})();
