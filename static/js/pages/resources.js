(function () {
    const chartPalette = {
        cpu: '#1f6feb',
        memory: '#a371f7',
        netIn: '#2ea043',
        netOut: '#388bfd',
        diskRead: '#d29922',
        diskWrite: '#f85149'
    };

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

        gaugeCpuChart = new Chart(document.getElementById('gaugeCpu'), gaugeConfig(chartPalette.cpu));
        gaugeMemChart = new Chart(document.getElementById('gaugeMem'), gaugeConfig(chartPalette.memory));
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
            options: {
                ...options,
                plugins: { ...options.plugins, legend: { display: false } },
                scales: { x: { display: false }, y: { ...options.scales.y, ticks: { ...options.scales.y.ticks, maxTicksLimit: 4 } } }
            }
        });

        diskChart = new Chart(document.getElementById('diskChart'), {
            type: 'bar',
            data: { labels: [], datasets: [] },
            options: {
                ...options,
                plugins: { ...options.plugins, legend: { display: false } },
                scales: { x: { display: false }, y: { ...options.scales.y, ticks: { ...options.scales.y.ticks, maxTicksLimit: 4 } } }
            }
        });
    }

    async function refreshData() {
        const data = await window.IPMI.fetchJson(`/api/status_resources?t=${Date.now()}`, { timeoutMs: 8000 });
        if (data.cpu === undefined) return;

        window.IPMI.setText('#val-cpu', data.cpu);
        window.IPMI.setText('#val-mem', data.mem_percent);
        window.IPMI.setText('#val-cpu-power', data.cpu_power_w !== undefined ? data.cpu_power_w : '--');
        window.IPMI.setText('#val-mem-used', data.mem_used);
        window.IPMI.setText('#val-mem-total', data.mem_total);
        window.IPMI.setText('#str-disk-r', window.IPMI.formatBytes(data.disk_r));
        window.IPMI.setText('#str-disk-w', window.IPMI.formatBytes(data.disk_w));
        window.IPMI.setText('#str-net-in', window.IPMI.formatBytes(data.net_in));
        window.IPMI.setText('#str-net-out', window.IPMI.formatBytes(data.net_out));

        updateGauge(gaugeCpuChart, data.cpu);
        updateGauge(gaugeMemChart, data.mem_percent);
    }

    const loadHistory = window.IPMI.createAbortableLoader(async (signal) => {
        const data = await window.IPMI.fetchJson('/api/history', { signal, timeoutMs: 20000 });

        cpuMemChart.data.labels = data.times;
        cpuMemChart.data.datasets = [
            { label: 'CPU %', data: data.res.cpu, borderColor: chartPalette.cpu, backgroundColor: 'rgba(31, 111, 235, 0.1)', borderWidth: 2, fill: true, tension: 0.3 },
            { label: 'RAM %', data: data.res.mem, borderColor: chartPalette.memory, backgroundColor: 'rgba(163, 113, 247, 0.05)', borderWidth: 2, fill: true, tension: 0.3 }
        ];
        cpuMemChart.update('none');

        netChart.data.labels = data.times;
        netChart.data.datasets = [
            { label: 'In', data: data.res.net_in, borderColor: chartPalette.netIn, borderWidth: 1.5, tension: 0.3, pointRadius: 0 },
            { label: 'Out', data: data.res.net_out, borderColor: chartPalette.netOut, borderWidth: 1.5, borderDash: [3, 3], tension: 0.3, pointRadius: 0 }
        ];
        netChart.update('none');

        diskChart.data.labels = data.times;
        diskChart.data.datasets = [
            { label: 'Read', data: data.res.disk_r, backgroundColor: chartPalette.diskRead, barPercentage: 0.7 },
            { label: 'Write', data: data.res.disk_w, backgroundColor: chartPalette.diskWrite, barPercentage: 0.7 }
        ];
        diskChart.update('none');
    });

    function rethemeCharts() {
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
