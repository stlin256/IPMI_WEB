# Frontend Modernization Plan

## Current State

- Rendering model: Flask/Jinja server-rendered templates with local Bootstrap, Font Awesome and Chart.js assets.
- Main surfaces: login, hardware dashboard, resource dashboard, GPU dashboard, history explorer and logs/settings.
- Frontend debt: each template repeats navigation, theme variables, card styling, mobile breakpoints and chart colors.
- Runtime behavior: frequent polling, many inline scripts, some DOM updates are already optimized, but chart/theme configuration is fragmented.
- Theme state: pages now start with `data-bs-theme="light"` and preserve a saved light/dark user preference through the shared theme script. Some older template-level dark utility classes remain, with light-mode adaptation centralized in `app-modern.css`.
- Navigation state: authenticated pages now use `static/js/pjax.js` for prefetched same-document transitions across hardware, resources, GPU, history and logs/settings. `app-core.js` owns page cleanup for timers, event listeners, Bootstrap components and Chart.js instances before the next page body is mounted.

## Refactor Direction

1. Build a shared shell layer for tokens, theme, navigation, footer, common cards, forms, tables and responsive containers.
2. Move page-level CSS and JavaScript out of templates incrementally, starting with low-risk shared helpers.
3. Keep the Flask/Jinja architecture for now; avoid introducing a bundler until shared modules and page contracts are stable.
4. Use progressive enhancement: every page should render useful information before polling completes.
5. Keep Chart.js, but centralize defaults, colors, resize handling and reduced-motion behavior.
6. Keep PJAX as progressive enhancement: direct URL loads, refreshes and login/logout remain ordinary Flask page requests.

## Performance Targets

- Avoid full DOM replacement for high-frequency panels; preserve the existing incremental update approach.
- Use `AbortController` for user-triggered data reloads and expensive analysis requests.
- Standardize chart updates with `update('none')` for polling refreshes and animated updates only for explicit user actions.
- Defer non-critical work behind `requestIdleCallback` where available, especially settings/about panels and secondary charts.
- Respect `prefers-reduced-motion` and avoid unnecessary animations on low-power clients.
- Prefetch likely next pages during idle time or link hover, then switch only the active document body while preserving URL, title and browser history.

## Visual And Responsive Targets

- Support persistent light/dark theme switching, with light as the default and dark retained as an operator preference.
- Use neutral system colors plus blue, teal, green, amber and red semantic accents.
- Keep operational screens dense and scannable; avoid decorative layouts that reduce data density.
- Prefer 8px-radius cards and stable chart/container dimensions to prevent polling layout shifts.
- Support desktop, tablet and mobile with horizontal overflow only for explicit controls such as metric toggles.

## Commit Plan

1. Shared theme foundation and modernization plan.
2. Extract shared shell/navigation/footer macros or includes.
3. Extract common chart utilities and theme-aware Chart.js defaults.
4. Migrate resource and GPU dashboards first because their page scripts are smaller.
5. Migrate hardware and history dashboards after shared chart utilities are proven.
6. Split logs/settings last because it carries the widest modal and form surface.
7. Continue moving inline Hardware, History and Logs scripts into page modules so PJAX lifecycle ownership becomes explicit instead of compatibility-driven.
