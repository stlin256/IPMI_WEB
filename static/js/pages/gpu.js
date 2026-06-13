(function () {
    const gpuCharts = {};
    let lastGpuCount = -1;
    let gpuNoticeModal = null;

    function escapeHtml(value) {
        return String(value ?? '').replace(/[&<>"']/g, (char) => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        }[char]));
    }

    function percent(value) {
        const numeric = Number(value) || 0;
        return Math.max(0, Math.min(100, numeric));
    }

    function colorWithAlpha(hexColor, alpha) {
        const hex = String(hexColor || '').trim().replace('#', '');
        if (!/^[0-9a-f]{6}$/i.test(hex)) return `rgba(127, 127, 127, ${alpha})`;
        const r = parseInt(hex.slice(0, 2), 16);
        const g = parseInt(hex.slice(2, 4), 16);
        const b = parseInt(hex.slice(4, 6), 16);
        return `rgba(${r}, ${g}, ${b}, ${alpha})`;
    }

    function tx(key, fallback, params = {}) {
        const translated = t(key, params);
        return translated === key ? fallback : translated;
    }

    function setStatus(text, className) {
        const statusBadge = document.getElementById('agent-status');
        if (!statusBadge) return;
        statusBadge.textContent = text;
        statusBadge.className = className;
    }

    function showGpuNotice(message, title = tx('gpu.configErrorTitle', 'Configuration not saved')) {
        const modalEl = document.getElementById('gpuNoticeModal');
        if (!modalEl) return;
        window.IPMI.setText('#gpu-notice-title', title);
        window.IPMI.setText('#gpu-notice-message', message);
        if (!gpuNoticeModal) gpuNoticeModal = new bootstrap.Modal(modalEl);
        gpuNoticeModal.show();
    }

    function updateSummary(gpus) {
        if (!gpus || gpus.length === 0) {
            window.IPMI.setText('#gpu-stat-count', '0');
            window.IPMI.setText('#gpu-stat-load', '--%');
            window.IPMI.setText('#gpu-stat-temp', '--°C');
            window.IPMI.setText('#gpu-stat-power', '--W');
            return;
        }

        const avgLoad = Math.round(gpus.reduce((sum, gpu) => sum + (Number(gpu.util_gpu) || 0), 0) / gpus.length);
        const peakTemp = Math.max(...gpus.map((gpu) => Number(gpu.temp) || 0));
        const totalPower = Math.round(gpus.reduce((sum, gpu) => sum + (Number(gpu.power_draw) || 0), 0));

        window.IPMI.setText('#gpu-stat-count', gpus.length);
        window.IPMI.setText('#gpu-stat-load', `${avgLoad}%`);
        window.IPMI.setText('#gpu-stat-temp', `${peakTemp}°C`);
        window.IPMI.setText('#gpu-stat-power', `${totalPower}W`);
    }

    async function loadGpuConfig() {
        const data = await window.IPMI.fetchJson('/api/config/gpu', { timeoutMs: 10000 });
        window.IPMI.qs('#config-host').value = data.gpu_agent_host || '';
        window.IPMI.qs('#config-port').value = data.gpu_agent_port || '';
        window.IPMI.qs('#config-enabled').checked = data.gpu_agent_enabled === 'true';
    }

    async function saveGpuConfig() {
        const payload = {
            gpu_agent_host: window.IPMI.qs('#config-host').value,
            gpu_agent_port: parseInt(window.IPMI.qs('#config-port').value, 10),
            gpu_agent_enabled: window.IPMI.qs('#config-enabled').checked
        };

        try {
            const data = await window.IPMI.fetchJson('/api/config/gpu', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
                timeoutMs: 15000
            });

            if (data.status === 'success') {
                const modal = bootstrap.Modal.getInstance(document.getElementById('gpuConfigModal'));
                if (modal) modal.hide();
                await refreshGpuData();
                return;
            }
            showGpuNotice(tx('gpu.saveFailed', 'Save failed: {message}', { message: data.message || t('logs.unknown') }));
        } catch (error) {
            showGpuNotice(tx('gpu.saveFailed', 'Save failed: {message}', { message: error.message || t('logs.unknown') }));
        }
    }

    function destroyCharts() {
        Object.values(gpuCharts).forEach((chart) => chart.destroy());
        Object.keys(gpuCharts).forEach((key) => delete gpuCharts[key]);
    }

    function renderGpuCards(gpus) {
        const container = document.getElementById('gpu-container');
        destroyCharts();
        container.innerHTML = gpus.map((gpu, index) => `
            <div class="col-12 col-md-6 col-xl-4">
                <div class="card gpu-card h-100">
                    <div class="gpu-card-head">
                        <div class="gpu-name">
                            <div class="gpu-index">GPU #${index}</div>
                            <div><i class="fas fa-microchip me-2 text-primary"></i><span id="gpu-${index}-name">${escapeHtml(gpu.name)}</span></div>
                        </div>
                        <span class="badge temp-badge" id="gpu-${index}-temp-badge">--&deg;C</span>
                    </div>
                    <div class="gpu-card-body">
                        <div class="gpu-meter">
                            <div class="gpu-meter-top">
                                <span class="gpu-label">${t('gpu.load')}</span>
                                <span class="gpu-value" id="gpu-${index}-util-val">--%</span>
                            </div>
                            <div class="progress">
                                <div class="progress-bar bg-primary" id="gpu-${index}-util-bar" style="width: 0%"></div>
                            </div>
                        </div>
                        <div class="gpu-meter">
                            <div class="gpu-meter-top">
                                <span class="gpu-label">${t('gpu.memoryActivity')}</span>
                                <span class="gpu-value" id="gpu-${index}-mem-util-val">--%</span>
                            </div>
                            <div class="progress">
                                <div class="progress-bar bg-info" id="gpu-${index}-mem-util-bar" style="width: 0%"></div>
                            </div>
                            <div class="text-end mt-1 text-muted font-monospace fw-bold" style="font-size: 0.95rem;" id="gpu-${index}-mem-text">-- / -- MB</div>
                        </div>
                        <div class="gpu-meter mb-0">
                            <div class="gpu-meter-top">
                                <span class="gpu-label">${t('gpu.power')}</span>
                                <span class="gpu-value" id="gpu-${index}-pwr-val">--W</span>
                            </div>
                            <div class="progress">
                                <div class="progress-bar bg-warning" id="gpu-${index}-pwr-bar" style="width: 0%"></div>
                            </div>
                        </div>
                    </div>
                    <div class="info-grid">
                        <div class="info-item"><span class="info-label">${t('gpu.coreClock')}</span><span class="info-value" id="gpu-${index}-core-clock">-- MHz</span></div>
                        <div class="info-item"><span class="info-label">${t('gpu.memoryClock')}</span><span class="info-value" id="gpu-${index}-mem-clock">-- MHz</span></div>
                        <div class="info-item"><span class="info-label">${t('gpu.fanSpeed')}</span><span class="info-value" id="gpu-${index}-fan">--%</span></div>
                        <div class="info-item"><span class="info-label">${t('gpu.eccErrors')}</span><span class="info-value" id="gpu-${index}-ecc">0</span></div>
                    </div>
                    <div class="gpu-chart-panel">
                        <canvas id="gpu-chart-${index}"></canvas>
                    </div>
                </div>
            </div>
        `).join('');
    }

    function updateGpuCard(gpu, index) {
        const tempEl = document.getElementById(`gpu-${index}-temp-badge`);
        if (tempEl) {
            tempEl.textContent = `${gpu.temp}°C`;
            tempEl.className = `badge temp-badge ${gpu.temp >= 70 ? 'bg-danger' : (gpu.temp >= 50 ? 'bg-warning' : 'bg-success')}`;
        }

        window.IPMI.setText(`#gpu-${index}-util-val`, `${gpu.util_gpu}%`);
        window.IPMI.qs(`#gpu-${index}-util-bar`).style.width = `${percent(gpu.util_gpu)}%`;
        window.IPMI.setText(`#gpu-${index}-mem-util-val`, `${gpu.util_mem}%`);
        window.IPMI.qs(`#gpu-${index}-mem-util-bar`).style.width = `${percent(gpu.util_mem)}%`;
        window.IPMI.setText(`#gpu-${index}-mem-text`, `${gpu.memory_used} / ${gpu.memory_total} MB`);
        window.IPMI.setText(`#gpu-${index}-pwr-val`, `${gpu.power_draw}W / ${gpu.power_limit}W`);

        const powerLimit = Number(gpu.power_limit) || 0;
        const powerPercent = powerLimit > 0 ? percent(Number(gpu.power_draw) / powerLimit * 100) : 0;
        window.IPMI.qs(`#gpu-${index}-pwr-bar`).style.width = `${powerPercent.toFixed(1)}%`;

        const fanSpeed = gpu.fan_speed !== null ? gpu.fan_speed : 'N/A';
        window.IPMI.setText(`#gpu-${index}-core-clock`, `${gpu.clock_core} MHz`);
        window.IPMI.setText(`#gpu-${index}-mem-clock`, `${gpu.clock_mem} MHz`);
        window.IPMI.setText(`#gpu-${index}-fan`, `${fanSpeed}${gpu.fan_speed !== null ? '%' : ''}`);

        const eccEl = document.getElementById(`gpu-${index}-ecc`);
        if (eccEl) {
            eccEl.textContent = gpu.ecc_errors;
            eccEl.className = `info-value ${gpu.ecc_errors > 0 ? 'text-danger' : ''}`;
        }
    }

    async function refreshGpuData() {
        try {
            const data = await window.IPMI.fetchJson('/api/status_gpu', { timeoutMs: 10000 });
            const container = document.getElementById('gpu-container');
            const offlineMsg = document.getElementById('offline-msg');
            window.IPMI.setText('#last-update', new Date().toLocaleTimeString());

            if (!data.online) {
                setStatus(tx('gpu.offline', 'Offline'), 'gpu-status-pill text-danger');
                container.classList.add('agent-offline');
                offlineMsg.style.display = 'block';
                updateSummary([]);
                return;
            }

            setStatus(tx('gpu.online', 'Online'), 'gpu-status-pill text-success');
            container.classList.remove('agent-offline');
            offlineMsg.style.display = 'none';

            if (!data.gpus || data.gpus.length === 0) {
                destroyCharts();
                container.innerHTML = `<div class="col-12 text-center text-muted py-5">${tx('gpu.notFound', 'No GPU devices found')}</div>`;
                lastGpuCount = 0;
                updateSummary([]);
                return;
            }

            updateSummary(data.gpus);

            if (data.gpus.length !== lastGpuCount) {
                renderGpuCards(data.gpus);
                lastGpuCount = data.gpus.length;
                data.gpus.forEach((_gpu, index) => {
                    renderGpuTrend(index).catch((error) => console.debug('GPU trend load failed:', error));
                });
            }

            data.gpus.forEach(updateGpuCard);
        } catch (error) {
            if (!window.IPMI.isAbort(error)) {
                console.error('GPU Status Error:', error);
                setStatus(tx('gpu.error', 'Error'), 'gpu-status-pill text-warning');
            }
        }
    }

    async function renderGpuTrend(index) {
        const canvas = document.getElementById(`gpu-chart-${index}`);
        if (!canvas) return;

        const data = await window.IPMI.fetchJson(`/api/history_gpu?hours=1&index=${index}`, { timeoutMs: 20000 });
        const palette = {
            load: window.IPMI.cssVar('--accent-blue', '#526f83'),
            memory: window.IPMI.cssVar('--accent-magenta', '#83555d'),
            temp: window.IPMI.cssVar('--accent-red', '#a94e3f'),
            clock: window.IPMI.cssVar('--accent-green', '#6e7d52')
        };
        const datasets = [
            {
                label: 'GPU Load %',
                data: data.util_gpu,
                borderColor: palette.load,
                borderWidth: 2,
                pointRadius: 0,
                fill: true,
                backgroundColor: colorWithAlpha(palette.load, 0.11),
                tension: 0.4
            },
            {
                label: 'Mem Util %',
                data: data.util_mem,
                borderColor: palette.memory,
                borderWidth: 1.5,
                pointRadius: 0,
                tension: 0.4
            },
            {
                label: 'Temp °C',
                data: data.temp,
                borderColor: palette.temp,
                borderWidth: 1,
                pointRadius: 0,
                tension: 0.4
            },
            {
                label: 'Core Clock MHz',
                data: data.clock_core,
                borderColor: palette.clock,
                borderWidth: 1.5,
                pointRadius: 0,
                tension: 0.4,
                yAxisID: 'yClock'
            }
        ];

        if (gpuCharts[index]) {
            gpuCharts[index].data.labels = data.times;
            gpuCharts[index].data.datasets = datasets;
            gpuCharts[index].update('none');
            return;
        }

        const theme = window.IPMICharts ? window.IPMICharts.colors() : { grid: '#30363d' };
        gpuCharts[index] = new Chart(canvas.getContext('2d'), {
            type: 'line',
            data: { labels: data.times, datasets },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? false : {
                    duration: 450,
                    easing: 'easeOutQuart'
                },
                plugins: { legend: { display: false }, tooltip: { enabled: true, mode: 'index', intersect: false } },
                scales: {
                    x: { display: false },
                    y: { display: true, min: 0, max: 100, grid: { color: theme.grid }, ticks: { display: false } },
                    yClock: { display: false, position: 'right', min: 0, grid: { drawOnChartArea: false } }
                }
            }
        });
    }

    function refreshGpuTrends() {
        return Promise.all(Object.keys(gpuCharts).map((index) => renderGpuTrend(index)));
    }

    function init() {
        const refreshButton = document.getElementById('btn-refresh-gpu');
        if (refreshButton) {
            refreshButton.addEventListener('click', () => {
                refreshButton.classList.add('disabled');
                refreshGpuData().finally(() => refreshButton.classList.remove('disabled'));
            });
        }
        loadGpuConfig().catch((error) => console.debug('GPU config load failed:', error));
        window.IPMI.poll(window.IPMI.updateLogDot, 5000, { visibleOnly: true });
        window.IPMI.poll(refreshGpuData, 1000, { visibleOnly: true });
        window.IPMI.poll(refreshGpuTrends, 60000, { immediate: false, visibleOnly: true });
        window.addEventListener('ipmi:theme-change', () => {
            if (window.IPMICharts) window.IPMICharts.refreshAll();
        });
    }

    window.saveGpuConfig = saveGpuConfig;
    window.refreshGpuData = refreshGpuData;
    document.addEventListener('DOMContentLoaded', init);
})();
