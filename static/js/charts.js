(function () {
    function hasChart() {
        return typeof window.Chart !== 'undefined';
    }

    function colors() {
        if (window.IPMITheme && typeof window.IPMITheme.chart === 'function') {
            return window.IPMITheme.chart();
        }
        const styles = getComputedStyle(document.documentElement);
        return {
            text: styles.getPropertyValue('--text-main').trim() || '#e6edf3',
            muted: styles.getPropertyValue('--text-muted').trim() || '#8b949e',
            grid: styles.getPropertyValue('--border-color').trim() || '#30363d',
            panel: styles.getPropertyValue('--bg-card').trim() || '#161b22'
        };
    }

    function applyDefaults() {
        if (!hasChart()) return;
        const theme = colors();
        Chart.defaults.color = theme.text;
        Chart.defaults.borderColor = theme.grid;
        Chart.defaults.font.family = '"Segoe UI", system-ui, sans-serif';
        Chart.defaults.plugins.tooltip.backgroundColor = theme.panel;
        Chart.defaults.plugins.tooltip.titleColor = theme.text;
        Chart.defaults.plugins.tooltip.bodyColor = theme.text;
        Chart.defaults.plugins.tooltip.borderColor = theme.grid;
        Chart.defaults.plugins.tooltip.borderWidth = 1;
    }

    function tuneScale(scale, theme) {
        if (!scale) return;
        if (scale.grid) scale.grid.color = theme.grid;
        if (scale.ticks) scale.ticks.color = theme.muted;
        if (scale.title) scale.title.color = theme.muted;
    }

    function tuneChart(chart) {
        if (!chart || !chart.options) return;
        const theme = colors();
        const plugins = chart.options.plugins || {};

        if (plugins.legend && plugins.legend.labels) {
            plugins.legend.labels.color = theme.text;
        }
        if (plugins.tooltip) {
            plugins.tooltip.backgroundColor = theme.panel;
            plugins.tooltip.titleColor = theme.text;
            plugins.tooltip.bodyColor = theme.text;
            plugins.tooltip.borderColor = theme.grid;
            plugins.tooltip.borderWidth = 1;
        }
        Object.values(chart.options.scales || {}).forEach((scale) => tuneScale(scale, theme));
        chart.update('none');
    }

    function allCharts() {
        if (!hasChart() || !Chart.instances) return [];
        if (Chart.instances instanceof Map) return Array.from(Chart.instances.values());
        return Object.values(Chart.instances);
    }

    function refreshAll() {
        applyDefaults();
        allCharts().forEach(tuneChart);
    }

    function destroyAll() {
        allCharts().forEach((chart) => {
            try { chart.destroy(); } catch (_) {}
        });
    }

    window.IPMICharts = {
        colors,
        applyDefaults,
        tuneChart,
        refreshAll,
        destroyAll
    };

    applyDefaults();
    window.addEventListener('ipmi:theme-change', () => {
        window.requestAnimationFrame(refreshAll);
    });
})();
