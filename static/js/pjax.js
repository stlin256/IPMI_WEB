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
            const page = await fetchPage(path, { signal: controller.signal, force: options.force });
            if (controller.signal.aborted) return;

            if (window.IPMI && typeof window.IPMI.destroyPage === 'function') {
                window.IPMI.destroyPage();
            }

            copyBodyState(page);
            syncHeadStyles(page);
            document.body.innerHTML = page.bodyHtml;
            document.title = page.title || document.title;
            updateNavigation(path);
            currentPath = path;

            if (!options.replace) {
                window.history.pushState({ pjax: true, path }, '', path);
            } else {
                window.history.replaceState({ pjax: true, path }, '', path);
            }

            await runPageScripts(page);
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
        if (!routes.has(path) || prefetchCache.has(path)) return;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000);
        fetchPage(path, { signal: controller.signal })
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
