(function () {
    function chartPalette() {
        return {
            cpu: window.IPMI.cssVar('--accent-blue', '#526f83'),
            memory: window.IPMI.cssVar('--accent-magenta', '#83555d'),
            netIn: window.IPMI.cssVar('--accent-green', '#6e7d52'),
            netOut: window.IPMI.cssVar('--accent-cyan', '#637f75'),
            diskRead: window.IPMI.cssVar('--accent-yellow', '#a5792e'),
            diskWrite: window.IPMI.cssVar('--accent-red', '#a94e3f')
        };
    }

    function colorMix(hexColor, alpha) {
        const hex = String(hexColor || '').trim().replace('#', '');
        if (!/^[0-9a-f]{6}$/i.test(hex)) return `rgba(127, 127, 127, ${alpha})`;
        const r = parseInt(hex.slice(0, 2), 16);
        const g = parseInt(hex.slice(2, 4), 16);
        const b = parseInt(hex.slice(4, 6), 16);
        return `rgba(${r}, ${g}, ${b}, ${alpha})`;
    }

    let cpuMemChart;
    let netChart;
    let diskChart;
    let gaugeCpuChart;
    let gaugeMemChart;

    function chartColors() {
        return window.IPMICharts ? window.IPMICharts.colors() : {
            text: '#e6edf3',
            muted: '#8b949e',
            grid: '#30363d',
            panel: '#161b22'
        };
    }

    function commonChartOptions() {
        const theme = chartColors();
        return {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            spanGaps: false,
            elements: {
                point: { radius: 0, hitRadius: 10, hoverRadius: 4 },
                line: { borderWidth: 2.5, tension: 0.4 }
            },
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: {
                    position: 'top',
                    align: 'end',
                    labels: {
                        color: theme.text,
                        font: { size: 12, weight: 'bold' },
                        boxWidth: 10,
                        padding: 15,
                        usePointStyle: true
                    }
                },
                tooltip: {
                    backgroundColor: theme.panel,
                    titleColor: theme.text,
                    bodyColor: theme.text,
                    borderColor: theme.grid,
                    borderWidth: 1,
                    titleFont: { weight: 'bold' },
                    bodyFont: { family: "'SF Mono', monospace" }
                }
            },
            scales: {
                x: {
                    grid: { color: theme.grid, drawBorder: false },
                    ticks: { color: theme.muted, maxTicksLimit: 6 }
                },
                y: {
                    grid: { color: theme.grid, drawBorder: false },
                    ticks: { color: theme.muted, font: { family: "'SF Mono', monospace" } },
                    beginAtZero: true
                }
            }
        };
    }

    function sparklineOptions() {
        const theme = chartColors();
        return {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            elements: {
                point: { radius: 0, hitRadius: 8, hoverRadius: 3 },
                line: { borderWidth: 2, tension: 0.45 }
            },
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: theme.panel,
                    titleColor: theme.text,
                    bodyColor: theme.text,
                    borderColor: theme.grid,
                    borderWidth: 1,
                    displayColors: false,
                    bodyFont: { family: "'SF Mono', monospace" }
                }
            },
            scales: {
                x: { display: false },
                y: {
                    display: false,
                    beginAtZero: true,
                    grid: { display: false, drawBorder: false }
                }
            }
        };
    }

    function clampPercent(value) {
        const numeric = Number(value) || 0;
        return Math.max(0, Math.min(100, numeric));
    }

    function initGauges() {
        const gaugeConfig = (color) => ({
            type: 'doughnut',
            data: {
                labels: ['Used', 'Free'],
                datasets: [{
                    data: [0, 100],
                    backgroundColor: [color, window.IPMI.cssVar('--bg-elevated', '#21262d')],
                    borderWidth: 0,
                    circumference: 360,
                    cutout: '85%',
                    borderRadius: 20
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                plugins: { legend: { display: false }, tooltip: { enabled: false } }
            }
        });

        const palette = chartPalette();
        gaugeCpuChart = new Chart(document.getElementById('gaugeCpu'), gaugeConfig(palette.cpu));
        gaugeMemChart = new Chart(document.getElementById('gaugeMem'), gaugeConfig(palette.memory));
    }

    function updateGauge(chart, value) {
        if (!chart) return;
        const percent = clampPercent(value);
        chart.data.datasets[0].data = [percent, 100 - percent];
        chart.data.datasets[0].backgroundColor[1] = window.IPMI.cssVar('--bg-elevated', '#21262d');
        chart.update('none');
    }

    function initCharts() {
        const options = commonChartOptions();

        cpuMemChart = new Chart(document.getElementById('cpuMemChart'), {
            type: 'line',
            data: { labels: [], datasets: [] },
            options: {
                ...options,
                scales: {
                    ...options.scales,
                    y: {
                        ...options.scales.y,
                        max: 100,
                        ticks: { ...options.scales.y.ticks, callback: (value) => `${value}%` }
                    }
                }
            }
        });

        netChart = new Chart(document.getElementById('netChart'), {
            type: 'line',
            data: { labels: [], datasets: [] },
            options: sparklineOptions()
        });

        diskChart = new Chart(document.getElementById('diskChart'), {
            type: 'line',
            data: { labels: [], datasets: [] },
            options: sparklineOptions()
        });
    }

    async function refreshData() {
        const data = await window.IPMI.fetchJson(`/api/status_resources?t=${Date.now()}`, { timeoutMs: 8000 });
        if (data.cpu === undefined) return;

        window.IPMI.setText('#val-cpu', data.cpu);
        window.IPMI.setText('#val-mem', data.mem_percent);
        const diskRead = window.IPMI.formatBytes(data.disk_r);
        const diskWrite = window.IPMI.formatBytes(data.disk_w);
        const netIn = window.IPMI.formatBytes(data.net_in);
        const netOut = window.IPMI.formatBytes(data.net_out);
        window.IPMI.setText('#str-disk-r', diskRead);
        window.IPMI.setText('#str-disk-w', diskWrite);
        window.IPMI.setText('#str-net-in', netIn);
        window.IPMI.setText('#str-net-out', netOut);

        window.IPMI.setText('#res-chip-cpu', `${data.cpu}%`);
        window.IPMI.setText('#res-chip-cpu-power', data.cpu_power_w !== undefined ? data.cpu_power_w : '--');
        window.IPMI.setText('#res-chip-mem', `${data.mem_percent}%`);
        window.IPMI.setText('#res-chip-mem-used', data.mem_used);
        window.IPMI.setText('#res-chip-mem-total', data.mem_total);

        updateGauge(gaugeCpuChart, data.cpu);
        updateGauge(gaugeMemChart, data.mem_percent);
    }

    const loadHistory = window.IPMI.createAbortableLoader(async (signal) => {
        const data = await window.IPMI.fetchJson('/api/history', { signal, timeoutMs: 20000 });
        const palette = chartPalette();

        cpuMemChart.data.labels = data.times;
        cpuMemChart.data.datasets = [
            { label: 'CPU %', data: data.res.cpu, borderColor: palette.cpu, backgroundColor: colorMix(palette.cpu, 0.11), borderWidth: 2, fill: true, tension: 0.3 },
            { label: 'RAM %', data: data.res.mem, borderColor: palette.memory, backgroundColor: colorMix(palette.memory, 0.08), borderWidth: 2, fill: true, tension: 0.3 }
        ];
        cpuMemChart.update('none');

        netChart.data.labels = data.times;
        netChart.data.datasets = [
            { label: 'In', data: data.res.net_in, borderColor: palette.netIn, backgroundColor: colorMix(palette.netIn, 0.08), fill: true, borderWidth: 2, tension: 0.45, pointRadius: 0 },
            { label: 'Out', data: data.res.net_out, borderColor: palette.netOut, backgroundColor: colorMix(palette.netOut, 0.04), fill: true, borderWidth: 2, borderDash: [4, 4], tension: 0.45, pointRadius: 0 }
        ];
        netChart.update('none');

        diskChart.data.labels = data.times;
        diskChart.data.datasets = [
            { label: 'Read', data: data.res.disk_r, borderColor: palette.diskRead, backgroundColor: colorMix(palette.diskRead, 0.08), fill: true, borderWidth: 2, tension: 0.45, pointRadius: 0 },
            { label: 'Write', data: data.res.disk_w, borderColor: palette.diskWrite, backgroundColor: colorMix(palette.diskWrite, 0.04), fill: true, borderWidth: 2, borderDash: [4, 4], tension: 0.45, pointRadius: 0 }
        ];
        diskChart.update('none');
    });

    function rethemeCharts() {
        const palette = chartPalette();
        if (gaugeCpuChart) gaugeCpuChart.data.datasets[0].backgroundColor[0] = palette.cpu;
        if (gaugeMemChart) gaugeMemChart.data.datasets[0].backgroundColor[0] = palette.memory;
        updateGauge(gaugeCpuChart, gaugeCpuChart?.data.datasets[0].data[0] || 0);
        updateGauge(gaugeMemChart, gaugeMemChart?.data.datasets[0].data[0] || 0);
        if (window.IPMICharts) window.IPMICharts.refreshAll();
    }

    function init() {
        initGauges();
        initCharts();

        window.IPMI.poll(refreshData, 1000, { visibleOnly: true });
        window.IPMI.poll(loadHistory, 60000, { visibleOnly: true });
        window.IPMI.poll(window.IPMI.updateLogDot, 5000, { visibleOnly: true });
        window.addEventListener('ipmi:theme-change', rethemeCharts);
    }

    document.addEventListener('DOMContentLoaded', init);
})();
