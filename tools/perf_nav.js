#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

function loadPlaywright() {
    try {
        return require('playwright');
    } catch (error) {
        const tempModule = path.join(os.tmpdir(), 'ipmi-web-playwright', 'node_modules', 'playwright');
        try {
            return require(tempModule);
        } catch (_) {
            throw new Error(
                'Playwright is required. Install it with: npm install --prefix "%TEMP%\\ipmi-web-playwright" playwright@1.60.0'
            );
        }
    }
}

function percentile(values, p) {
    const sorted = [...values].sort((a, b) => a - b);
    if (!sorted.length) return 0;
    const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
    return sorted[index];
}

function summarize(samples) {
    const metrics = ['wallMs', 'domContentLoadedMs', 'loadMs', 'transferKb', 'resourceCount', 'sameDocument'];
    const summary = {};
    for (const metric of metrics) {
        const values = samples.map((sample) => sample[metric]).filter((value) => Number.isFinite(value));
        if (!values.length) continue;
        summary[metric] = {
            min: Math.round(Math.min(...values)),
            median: Math.round(percentile(values, 50)),
            p95: Math.round(percentile(values, 95)),
            max: Math.round(Math.max(...values))
        };
    }
    return summary;
}

function parseArgs(argv) {
    const args = {
        baseUrl: process.env.IPMI_PERF_BASE_URL || 'https://realpics.cn:9001',
        password: process.env.IPMI_PERF_PASSWORD || '',
        runs: Number(process.env.IPMI_PERF_RUNS || 5),
        chromePath: process.env.IPMI_PERF_CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe',
        output: process.env.IPMI_PERF_OUTPUT || '',
        mode: process.env.IPMI_PERF_MODE || 'document',
        routes: ['/hardware', '/resources', '/gpu', '/history', '/logs']
    };

    for (let i = 0; i < argv.length; i += 1) {
        const key = argv[i];
        const value = argv[i + 1];
        if (key === '--base-url') {
            args.baseUrl = value;
            i += 1;
        } else if (key === '--password') {
            args.password = value;
            i += 1;
        } else if (key === '--runs') {
            args.runs = Number(value);
            i += 1;
        } else if (key === '--chrome') {
            args.chromePath = value;
            i += 1;
        } else if (key === '--output') {
            args.output = value;
            i += 1;
        } else if (key === '--mode') {
            args.mode = value;
            i += 1;
        } else if (key === '--routes') {
            args.routes = value.split(',').map((route) => route.trim()).filter(Boolean);
            i += 1;
        }
    }

    if (!args.password) throw new Error('Missing password. Set IPMI_PERF_PASSWORD or pass --password.');
    if (!Number.isFinite(args.runs) || args.runs < 1) throw new Error('Runs must be a positive number.');
    if (!['document', 'click'].includes(args.mode)) throw new Error('Mode must be document or click.');
    return args;
}

async function navigationTiming(page) {
    return page.evaluate(() => {
        const nav = performance.getEntriesByType('navigation')[0];
        const resources = performance.getEntriesByType('resource');
        const transferBytes = resources.reduce((total, entry) => total + (entry.transferSize || 0), 0);
        return {
            responseStartMs: nav ? nav.responseStart : 0,
            domContentLoadedMs: nav ? nav.domContentLoadedEventEnd : 0,
            loadMs: nav ? nav.loadEventEnd : 0,
            transferKb: transferBytes / 1024,
            resourceCount: resources.length
        };
    });
}

async function clickTiming(page, route) {
    await page.evaluate(() => {
        window.__ipmiPerfMarker = Math.random().toString(36);
        performance.clearResourceTimings();
    });
    const marker = await page.evaluate(() => window.__ipmiPerfMarker);
    const start = performance.now();

    const link = await routeClickLocator(page, route);
    await link.click();
    await page.waitForURL(`**${route}`, { timeout: 45000 });
    await waitForRouteReady(page, route);
    await page.waitForTimeout(250);
    await assertRouteLayout(page, route);

    const timing = await page.evaluate((expectedMarker) => {
        const resources = performance.getEntriesByType('resource');
        const transferBytes = resources.reduce((total, entry) => total + (entry.transferSize || 0), 0);
        return {
            sameDocument: window.__ipmiPerfMarker === expectedMarker ? 1 : 0,
            transferKb: transferBytes / 1024,
            resourceCount: resources.length
        };
    }, marker);

    return {
        wallMs: Math.round(performance.now() - start),
        sameDocument: timing.sameDocument,
        transferKb: Math.round(timing.transferKb),
        resourceCount: timing.resourceCount
    };
}

async function routeClickLocator(page, route) {
    const selectors = {
        '/hardware': [
            'a.nav-link[href="/hardware"]',
            'a.navbar-brand[href="/hardware"]',
            'a.btn[href="/hardware"]'
        ],
        '/resources': ['a.nav-link[href="/resources"]'],
        '/gpu': ['a.nav-link[href="/gpu"]'],
        '/history': ['a.nav-link[href="/history"]'],
        '/logs': ['a.navbar-brand[href="/logs"]']
    };

    for (const selector of selectors[route] || [`a[href="${route}"]`]) {
        const locator = page.locator(selector);
        const count = await locator.count();
        if (count === 1) return locator;
        if (count > 1) throw new Error(`Ambiguous click target for ${route}: ${selector} matched ${count}`);
    }
    throw new Error(`No click target found for ${route}`);
}

async function waitForRouteReady(page, route) {
    const selectors = {
        '/hardware': '.hw-shell',
        '/resources': '.res-shell',
        '/gpu': '.gpu-shell',
        '/history': '.history-shell',
        '/logs': '.cli-container'
    };
    const selector = selectors[route];
    if (selector) await page.waitForSelector(selector, { timeout: 30000 });
}

async function assertRouteLayout(page, route) {
    const result = await page.evaluate((currentRoute) => {
        const issues = [];
        const managedStyles = document.head.querySelectorAll('style[data-ipmi-pjax-head]').length;
        if (managedStyles < 1) issues.push('missing managed page style');

        if (currentRoute === '/resources') {
            const grid = document.querySelector('.res-signal-grid');
            const gauge = document.querySelector('#gaugeCpu');
            const gridDisplay = grid ? getComputedStyle(grid).display : '';
            const gaugeBox = gauge ? gauge.getBoundingClientRect() : null;
            if (gridDisplay !== 'grid') issues.push(`resource grid display=${gridDisplay || 'missing'}`);
            if (!gaugeBox || gaugeBox.height < 40 || gaugeBox.height > 400) {
                issues.push(`resource gauge height=${gaugeBox ? Math.round(gaugeBox.height) : 'missing'}`);
            }
            if (document.documentElement.scrollHeight > 5000) {
                issues.push(`resource page height=${document.documentElement.scrollHeight}`);
            }
        }

        return { issues };
    }, route);

    if (result.issues.length) {
        throw new Error(`Layout check failed for ${route}: ${result.issues.join(', ')}`);
    }
}

async function main() {
    const args = parseArgs(process.argv.slice(2));
    const { chromium } = loadPlaywright();
    const baseUrl = args.baseUrl.replace(/\/+$/, '');

    const browser = await chromium.launch({
        headless: true,
        executablePath: args.chromePath
    });
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();

    await page.goto(`${baseUrl}/login`, { waitUntil: 'load', timeout: 30000 });
    await page.locator('input[name=password]').fill(args.password);
    await Promise.all([
        page.waitForNavigation({ waitUntil: 'load', timeout: 30000 }),
        page.locator('#login-btn').click()
    ]);

    const startedAt = new Date().toISOString();
    const results = {
        baseUrl,
        startedAt,
        mode: args.mode,
        runs: args.runs,
        routes: {}
    };

    if (args.mode === 'document') {
        for (const route of args.routes) {
            const samples = [];
            for (let run = 1; run <= args.runs; run += 1) {
                const url = `${baseUrl}${route}`;
                const start = performance.now();
                await page.goto(url, { waitUntil: 'load', timeout: 45000 });
                await page.waitForTimeout(250);
                const timing = await navigationTiming(page);
                samples.push({
                    run,
                    wallMs: Math.round(performance.now() - start),
                    responseStartMs: Math.round(timing.responseStartMs),
                    domContentLoadedMs: Math.round(timing.domContentLoadedMs),
                    loadMs: Math.round(timing.loadMs),
                    transferKb: Math.round(timing.transferKb),
                    resourceCount: timing.resourceCount
                });
                process.stderr.write(`${route} run ${run}/${args.runs}: ${samples[samples.length - 1].wallMs} ms\n`);
            }
            results.routes[route] = {
                samples,
                summary: summarize(samples)
            };
        }
    } else {
        await page.goto(`${baseUrl}/hardware`, { waitUntil: 'load', timeout: 45000 });
        await page.waitForTimeout(500);

        for (const route of args.routes.filter((item) => item !== '/hardware')) {
            const samples = [];
            for (let run = 1; run <= args.runs; run += 1) {
                if (page.url().endsWith(route)) {
                    await page.goto(`${baseUrl}/hardware`, { waitUntil: 'load', timeout: 45000 });
                    await page.waitForTimeout(500);
                }
                const sample = await clickTiming(page, route);
                sample.run = run;
                samples.push(sample);
                process.stderr.write(`${route} click ${run}/${args.runs}: ${sample.wallMs} ms, sameDocument=${sample.sameDocument}\n`);
            }
            results.routes[route] = {
                samples,
                summary: summarize(samples)
            };
        }

        const samples = [];
        for (let run = 1; run <= args.runs; run += 1) {
            if (!page.url().endsWith('/logs')) {
                await page.goto(`${baseUrl}/logs`, { waitUntil: 'load', timeout: 45000 });
                await page.waitForTimeout(500);
            }
            const sample = await clickTiming(page, '/hardware');
            sample.run = run;
            samples.push(sample);
            process.stderr.write(`/hardware click ${run}/${args.runs}: ${sample.wallMs} ms, sameDocument=${sample.sameDocument}\n`);
        }
        results.routes['/hardware'] = {
            samples,
            summary: summarize(samples)
        };
    }

    await browser.close();

    const json = `${JSON.stringify(results, null, 2)}\n`;
    if (args.output) {
        fs.writeFileSync(args.output, json);
    } else {
        process.stdout.write(json);
    }
}

main().catch((error) => {
    console.error(error.stack || error.message);
    process.exit(1);
});
