(function () {
    const gpuCharts = {};
    let lastCardSignature = '';
    let gpuNoticeModal = null;
    let gpuConfigAgents = [];
    let currentTrendTargets = {};

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

    function parseConfigBool(value, defaultValue = false) {
        if (typeof value === 'boolean') return value;
        if (value === undefined || value === null || value === '') return defaultValue;
        return ['1', 'true', 'yes', 'on'].includes(String(value).trim().toLowerCase());
    }

    function setStatus(text, className) {
        const statusBadge = document.getElementById('agent-status');
        if (!statusBadge) return;
        window.IPMI.setText(statusBadge, text);
        window.IPMI.setClassName(statusBadge, className);
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

    function createAgentId() {
        return `agent-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
    }

    function normalizeConfigAgent(agent = {}, index = 0) {
        const port = parseInt(agent.port ?? agent.gpu_agent_port ?? 9999, 10);
        const slot = parseInt(agent.slot ?? index, 10);
        return {
            id: String(agent.id || createAgentId()).trim(),
            host: String(agent.host ?? agent.gpu_agent_host ?? '').trim(),
            port: Number.isFinite(port) ? port : 9999,
            enabled: parseConfigBool(agent.enabled ?? agent.gpu_agent_enabled, false),
            note: String(agent.note || '').trim(),
            slot: Number.isFinite(slot) ? slot : index
        };
    }

    function normalizeConfigAgents(agents) {
        const source = Array.isArray(agents) && agents.length ? agents : [{ id: 'legacy-default', host: '127.0.0.1', port: 9999, enabled: false, note: '', slot: 0 }];
        return source.map(normalizeConfigAgent);
    }

    function agentEndpoint(agent) {
        if (!agent) return '';
        const host = agent.host || '';
        const port = agent.port || '';
        return port ? `${host}:${port}` : host;
    }

    function agentDisplayLabel(agent) {
        if (!agent) return '';
        return agent.note || agent.label || agentEndpoint(agent);
    }

    function nextAgentSlot() {
        const slots = gpuConfigAgents.map((agent) => Number(agent.slot)).filter(Number.isFinite);
        return slots.length ? Math.max(...slots) + 1 : 0;
    }

    function renderAgentConfigRows() {
        const list = document.getElementById('gpu-agent-list');
        if (!list) return;
        list.innerHTML = gpuConfigAgents.map((agent, index) => {
            const enabledId = `gpu-agent-enabled-${escapeHtml(agent.id).replace(/[^A-Za-z0-9_-]/g, '-')}`;
            const removeDisabled = gpuConfigAgents.length <= 1 ? 'disabled' : '';
            return `
                <div class="gpu-agent-row" data-agent-index="${index}">
                    <div class="gpu-agent-row-head">
                        <div class="gpu-agent-row-title">
                            <i class="fas fa-satellite-dish text-primary"></i>
                            <span>Agent #${index + 1}</span>
                        </div>
                        <div class="gpu-agent-row-actions">
                            <div class="form-check form-switch mb-0">
                                <input class="form-check-input gpu-agent-enabled" type="checkbox" id="${enabledId}" ${agent.enabled ? 'checked' : ''}>
                                <label class="form-check-label" for="${enabledId}">${tx('gpu.enabledShort', 'Enabled')}</label>
                            </div>
                            <button type="button" class="btn btn-outline-danger btn-sm" data-action="remove-agent" ${removeDisabled} title="${tx('gpu.removeAgent', 'Remove agent')}">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </div>
                    <div class="gpu-agent-row-grid">
                        <div>
                            <label class="form-label text-muted">${t('gpu.host')}</label>
                            <input type="text" class="form-control gpu-agent-host" value="${escapeHtml(agent.host)}" placeholder="127.0.0.1">
                        </div>
                        <div>
                            <label class="form-label text-muted">${t('gpu.port')}</label>
                            <input type="number" class="form-control gpu-agent-port" value="${escapeHtml(agent.port)}" min="1" max="65535" placeholder="9999">
                        </div>
                        <div class="gpu-agent-note-field">
                            <label class="form-label text-muted">${tx('gpu.note', 'Note')}</label>
                            <input type="text" class="form-control gpu-agent-note" value="${escapeHtml(agent.note)}" maxlength="120" placeholder="${tx('gpu.notePlaceholder', 'Rack / node / purpose')}">
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    }

    async function loadGpuConfig() {
        const data = await window.IPMI.fetchJson('/api/config/gpu', { timeoutMs: 10000 });
        const agents = Array.isArray(data.gpu_agents)
            ? data.gpu_agents
            : [{
                id: 'legacy-default',
                host: data.gpu_agent_host || '',
                port: data.gpu_agent_port || 9999,
                enabled: data.gpu_agent_enabled === 'true',
                note: '',
                slot: 0
            }];
        gpuConfigAgents = normalizeConfigAgents(agents);
        renderAgentConfigRows();
    }

    function collectGpuConfigAgents() {
        const rows = Array.from(document.querySelectorAll('#gpu-agent-list .gpu-agent-row'));
        return rows.map((row, index) => {
            const current = gpuConfigAgents[index] || {};
            const port = parseInt(row.querySelector('.gpu-agent-port')?.value, 10);
            const slot = parseInt(current.slot ?? index, 10);
            return {
                id: current.id || createAgentId(),
                host: String(row.querySelector('.gpu-agent-host')?.value || '').trim(),
                port,
                enabled: Boolean(row.querySelector('.gpu-agent-enabled')?.checked),
                note: String(row.querySelector('.gpu-agent-note')?.value || '').trim(),
                slot: Number.isFinite(slot) ? slot : index
            };
        });
    }

    function validateAgents(agents) {
        return agents.length > 0 && agents.every((agent) => (
            agent.host &&
            Number.isInteger(agent.port) &&
            agent.port >= 1 &&
            agent.port <= 65535
        ));
    }

    async function saveGpuConfig() {
        const agents = collectGpuConfigAgents();
        if (!validateAgents(agents)) {
            showGpuNotice(tx('gpu.agentInvalid', 'Fill each agent host and a port from 1 to 65535.'));
            return;
        }

        try {
            const data = await window.IPMI.fetchJson('/api/config/gpu', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ gpu_agents: agents }),
                timeoutMs: 15000
            });

            if (data.status === 'success') {
                gpuConfigAgents = normalizeConfigAgents(data.gpu_agents || agents);
                renderAgentConfigRows();
                const modal = bootstrap.Modal.getInstance(document.getElementById('gpuConfigModal'));
                if (modal) modal.hide();
                lastCardSignature = '';
                await refreshGpuData();
                return;
            }
            showGpuNotice(tx('gpu.saveFailed', 'Save failed: {message}', { message: data.message || data.error || t('logs.unknown') }));
        } catch (error) {
            showGpuNotice(tx('gpu.saveFailed', 'Save failed: {message}', { message: error.message || t('logs.unknown') }));
        }
    }

    function destroyCharts() {
        Object.values(gpuCharts).forEach((chart) => chart.destroy());
        Object.keys(gpuCharts).forEach((key) => delete gpuCharts[key]);
    }

    function gpuCardKey(gpu, fallbackIndex = 0) {
        return String(gpu?.card_key || `${gpu?.agent_id || 'local'}:${gpu?.index ?? fallbackIndex}`);
    }

    function buildDisplayCards(data) {
        const cards = [];
        const seen = new Set();

        (data.gpus || []).forEach((gpu, index) => {
            const key = gpuCardKey(gpu, index);
            seen.add(key);
            cards.push({
                kind: 'gpu',
                gpu,
                offline: false,
                historyIndex: Number(gpu.history_index ?? gpu.index ?? index),
                key
            });
        });

        (data.agents || []).forEach((agent) => {
            if (!agent || !agent.enabled || agent.online) return;
            const staleGpus = Array.isArray(agent.gpus) ? agent.gpus : [];
            if (staleGpus.length) {
                staleGpus.forEach((gpu, index) => {
                    const key = gpuCardKey(gpu, index);
                    if (seen.has(key)) return;
                    seen.add(key);
                    cards.push({
                        kind: 'gpu',
                        gpu,
                        agent,
                        offline: true,
                        historyIndex: Number(gpu.history_index ?? gpu.index ?? index),
                        key
                    });
                });
                return;
            }
            cards.push({
                kind: 'agent',
                agent,
                offline: true,
                historyIndex: null,
                key: `agent:${agent.id || agentEndpoint(agent)}`
            });
        });

        return cards;
    }

    function cardSignature(cards) {
        return cards.map((card) => `${card.kind}:${card.key}:${card.offline ? 'offline' : 'online'}:${card.historyIndex ?? ''}`).join('|');
    }

    function renderGpuCard(card, index) {
        const offlineLabel = tx('gpu.agentOfflineShort', 'Agent Offline');
        const isGpuCard = card.kind === 'gpu';
        const gpu = card.gpu || {};
        const agent = card.agent || {
            label: gpu.agent_label,
            note: gpu.agent_note,
            host: gpu.agent_host,
            port: gpu.agent_port
        };
        const agentLabel = agentDisplayLabel(agent);
        const endpoint = agentEndpoint(agent);
        const title = isGpuCard ? (gpu.name || 'Unknown GPU') : agentLabel;
        const indexText = isGpuCard
            ? `${agentLabel ? `${escapeHtml(agentLabel)} · ` : ''}GPU #${escapeHtml(gpu.index ?? index)}`
            : offlineLabel;
        const offlineClass = card.offline ? ' is-agent-offline' : '';
        const badge = card.offline ? offlineLabel : '--&deg;C';

        if (!isGpuCard) {
            return `
                <div class="col-12 col-md-6 col-xl-4">
                    <div class="card gpu-card h-100${offlineClass}" data-offline-label="${escapeHtml(offlineLabel)}">
                        <div class="gpu-card-head">
                            <div class="gpu-name">
                                <div class="gpu-index">${escapeHtml(indexText)}</div>
                                <div><i class="fas fa-satellite-dish me-2 text-danger"></i>${escapeHtml(title || endpoint || offlineLabel)}</div>
                                <div class="gpu-agent-meta">${escapeHtml(endpoint)}</div>
                            </div>
                            <span class="badge temp-badge bg-secondary">${escapeHtml(offlineLabel)}</span>
                        </div>
                        <div class="gpu-agent-offline-body">
                            <i class="fas fa-plug-circle-xmark"></i>
                            <span>${escapeHtml(endpoint || title || offlineLabel)}</span>
                        </div>
                    </div>
                </div>
            `;
        }

        return `
            <div class="col-12 col-md-6 col-xl-4">
                <div class="card gpu-card h-100${offlineClass}" data-offline-label="${escapeHtml(offlineLabel)}">
                    <div class="gpu-card-head">
                        <div class="gpu-name">
                            <div class="gpu-index">${indexText}</div>
                            <div><i class="fas fa-microchip me-2 text-primary"></i><span id="gpu-${index}-name">${escapeHtml(title)}</span></div>
                            ${endpoint ? `<div class="gpu-agent-meta">${escapeHtml(endpoint)}</div>` : ''}
                        </div>
                        <span class="badge temp-badge ${card.offline ? 'bg-secondary' : ''}" id="gpu-${index}-temp-badge">${badge}</span>
                    </div>
                    <div class="gpu-card-body">
                        <div class="gpu-meter">
                            <div class="gpu-meter-top">
                                <span class="gpu-label">${t('gpu.load')}</span>
                                <span class="gpu-value" id="gpu-${index}-util-val">--%</span>
                            </div>
                            <div class="progress">
                                <div class="progress-bar bg-primary" id="gpu-${index}-util-bar" style="--ipmi-progress: 0"></div>
                            </div>
                        </div>
                        <div class="gpu-meter">
                            <div class="gpu-meter-top">
                                <span class="gpu-label">${t('gpu.memoryActivity')}</span>
                                <span class="gpu-value" id="gpu-${index}-mem-util-val">--%</span>
                            </div>
                            <div class="progress">
                                <div class="progress-bar bg-info" id="gpu-${index}-mem-util-bar" style="--ipmi-progress: 0"></div>
                            </div>
                            <div class="text-end mt-1 text-muted font-monospace fw-bold" style="font-size: 0.95rem;" id="gpu-${index}-mem-text">-- / -- MB</div>
                        </div>
                        <div class="gpu-meter mb-0">
                            <div class="gpu-meter-top">
                                <span class="gpu-label">${t('gpu.power')}</span>
                                <span class="gpu-value" id="gpu-${index}-pwr-val">--W</span>
                            </div>
                            <div class="progress">
                                <div class="progress-bar bg-warning" id="gpu-${index}-pwr-bar" style="--ipmi-progress: 0"></div>
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
        `;
    }

    function renderGpuCards(cards) {
        const container = document.getElementById('gpu-container');
        destroyCharts();
        currentTrendTargets = {};
        container.innerHTML = cards.map(renderGpuCard).join('');
        cards.forEach((card, index) => {
            if (card.kind === 'gpu' && !card.offline && Number.isFinite(card.historyIndex)) {
                currentTrendTargets[index] = card.historyIndex;
            }
        });
    }

    function metricText(value, suffix = '') {
        if (value === undefined || value === null || value === '') return `--${suffix}`;
        return `${value}${suffix}`;
    }

    function updateGpuCard(gpu, index) {
        const tempEl = document.getElementById(`gpu-${index}-temp-badge`);
        const temp = Number(gpu.temp);
        if (tempEl) {
            window.IPMI.setText(tempEl, Number.isFinite(temp) ? `${gpu.temp}°C` : '--°C');
            window.IPMI.setClassName(tempEl, `badge temp-badge ${temp >= 70 ? 'bg-danger' : (temp >= 50 ? 'bg-warning' : 'bg-success')}`);
        }

        window.IPMI.setText(`#gpu-${index}-util-val`, metricText(gpu.util_gpu, '%'));
        window.IPMI.setStyle(`#gpu-${index}-util-bar`, '--ipmi-progress', percent(gpu.util_gpu) / 100);
        window.IPMI.setText(`#gpu-${index}-mem-util-val`, metricText(gpu.util_mem, '%'));
        window.IPMI.setStyle(`#gpu-${index}-mem-util-bar`, '--ipmi-progress', percent(gpu.util_mem) / 100);
        window.IPMI.setText(`#gpu-${index}-mem-text`, `${gpu.memory_used ?? '--'} / ${gpu.memory_total ?? '--'} MB`);
        window.IPMI.setText(`#gpu-${index}-pwr-val`, `${gpu.power_draw ?? '--'}W / ${gpu.power_limit ?? '--'}W`);

        const powerLimit = Number(gpu.power_limit) || 0;
        const powerPercent = powerLimit > 0 ? percent(Number(gpu.power_draw) / powerLimit * 100) : 0;
        window.IPMI.setStyle(`#gpu-${index}-pwr-bar`, '--ipmi-progress', powerPercent.toFixed(3) / 100);

        const hasFanSpeed = gpu.fan_speed !== null && gpu.fan_speed !== undefined;
        const fanSpeed = hasFanSpeed ? gpu.fan_speed : 'N/A';
        window.IPMI.setText(`#gpu-${index}-core-clock`, metricText(gpu.clock_core, ' MHz'));
        window.IPMI.setText(`#gpu-${index}-mem-clock`, metricText(gpu.clock_mem, ' MHz'));
        window.IPMI.setText(`#gpu-${index}-fan`, `${fanSpeed}${hasFanSpeed ? '%' : ''}`);

        const eccEl = document.getElementById(`gpu-${index}-ecc`);
        if (eccEl) {
            const eccErrors = Number(gpu.ecc_errors) || 0;
            window.IPMI.setText(eccEl, eccErrors);
            window.IPMI.setClassName(eccEl, `info-value ${eccErrors > 0 ? 'text-danger' : ''}`);
        }
    }

    async function refreshGpuData() {
        try {
            const data = await window.IPMI.fetchJson('/api/status_gpu', { timeoutMs: 10000 });
            const container = document.getElementById('gpu-container');
            const offlineMsg = document.getElementById('offline-msg');
            let shouldLoadTrends = false;

            if (!data.online) {
                await window.IPMI.withFrame(() => {
                    window.IPMI.setText('#last-update', new Date().toLocaleTimeString());
                    setStatus(tx('gpu.offline', 'Offline'), 'gpu-status-pill text-danger');
                    container.classList.add('agent-offline');
                    window.IPMI.setStyle(offlineMsg, 'display', 'block');
                    updateSummary([]);
                });
                return;
            }

            const cards = buildDisplayCards(data);

            if ((!data.gpus || data.gpus.length === 0) && cards.length === 0) {
                await window.IPMI.withFrame(() => {
                    window.IPMI.setText('#last-update', new Date().toLocaleTimeString());
                    setStatus(tx('gpu.online', 'Online'), 'gpu-status-pill text-success');
                    container.classList.remove('agent-offline');
                    window.IPMI.setStyle(offlineMsg, 'display', 'none');
                    destroyCharts();
                    currentTrendTargets = {};
                    lastCardSignature = '';
                    container.innerHTML = `<div class="col-12 text-center text-muted py-5">${tx('gpu.notFound', 'No GPU devices found')}</div>`;
                    updateSummary([]);
                });
                return;
            }

            await window.IPMI.withFrame(() => {
                window.IPMI.setText('#last-update', new Date().toLocaleTimeString());
                setStatus(tx('gpu.online', 'Online'), 'gpu-status-pill text-success');
                container.classList.remove('agent-offline');
                window.IPMI.setStyle(offlineMsg, 'display', 'none');
                updateSummary(data.gpus || []);

                const signature = cardSignature(cards);
                if (signature !== lastCardSignature) {
                    renderGpuCards(cards);
                    lastCardSignature = signature;
                    shouldLoadTrends = true;
                }

                cards.forEach((card, index) => {
                    if (card.kind === 'gpu') updateGpuCard(card.gpu, index);
                });
            });

            if (shouldLoadTrends) {
                Object.entries(currentTrendTargets).forEach(([index, historyIndex]) => {
                    renderGpuTrend(index, historyIndex).catch((error) => console.debug('GPU trend load failed:', error));
                });
            }
        } catch (error) {
            if (!window.IPMI.isAbort(error)) {
                console.error('GPU Status Error:', error);
                setStatus(tx('gpu.error', 'Error'), 'gpu-status-pill text-warning');
            }
        }
    }

    async function renderGpuTrend(index, historyIndex = null) {
        const canvas = document.getElementById(`gpu-chart-${index}`);
        if (!canvas) return;

        const targetIndex = historyIndex ?? currentTrendTargets[index] ?? index;
        const data = await window.IPMI.fetchJson(`/api/history_gpu?hours=1&index=${encodeURIComponent(targetIndex)}`, { timeoutMs: 20000 });
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
                label: 'Core Clock',
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
                    duration: 220,
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
        return Promise.all(Object.entries(currentTrendTargets).map(([index, historyIndex]) => renderGpuTrend(index, historyIndex)));
    }

    function handleAgentListInput(event) {
        const row = event.target.closest('.gpu-agent-row');
        if (!row) return;
        const index = Number(row.dataset.agentIndex);
        if (!Number.isFinite(index) || !gpuConfigAgents[index]) return;
        gpuConfigAgents[index] = collectGpuConfigAgents()[index] || gpuConfigAgents[index];
    }

    function initConfigControls() {
        const addButton = document.getElementById('btn-add-gpu-agent');
        const list = document.getElementById('gpu-agent-list');
        const modalEl = document.getElementById('gpuConfigModal');

        if (addButton) {
            addButton.addEventListener('click', () => {
                gpuConfigAgents.push({
                    id: createAgentId(),
                    host: '',
                    port: 9999,
                    enabled: true,
                    note: '',
                    slot: nextAgentSlot()
                });
                renderAgentConfigRows();
            });
        }

        if (list) {
            list.addEventListener('input', handleAgentListInput);
            list.addEventListener('change', handleAgentListInput);
            list.addEventListener('click', (event) => {
                const removeButton = event.target.closest('[data-action="remove-agent"]');
                if (!removeButton) return;
                const row = removeButton.closest('.gpu-agent-row');
                const index = Number(row?.dataset.agentIndex);
                if (!Number.isFinite(index) || gpuConfigAgents.length <= 1) return;
                gpuConfigAgents.splice(index, 1);
                renderAgentConfigRows();
            });
        }

        if (modalEl) {
            modalEl.addEventListener('show.bs.modal', () => {
                loadGpuConfig().catch((error) => console.debug('GPU config load failed:', error));
            });
        }
    }

    function init() {
        const refreshButton = document.getElementById('btn-refresh-gpu');
        if (refreshButton) {
            refreshButton.addEventListener('click', () => {
                refreshButton.classList.add('disabled');
                refreshGpuData().finally(() => refreshButton.classList.remove('disabled'));
            });
        }
        initConfigControls();
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
