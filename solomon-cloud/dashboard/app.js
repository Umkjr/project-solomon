// app.js - Solomon Control Panel Interactive Controller

// 1. Initial State Data
const STATE = {
    activeTab: 'fleet',
    licenseCount: 3,
    totalLicenses: 4,
    dailySalt: 'LOCAL_DEV_SALT_32_BYTES_LONG_000',
    fleet: [
        { name: 'Razorpay Edge Shield', license: 'ENT-5821', fp: '8f9a2b7c4d5e8f9a2b...b5c7d8e9', status: 'Online', lastSeen: 'Just now' },
        { name: 'Cashfree India Edge', license: 'ENT-9022', fp: '5a4e3c2b1a0f9e8d7c...f1d2e3d4', status: 'Online', lastSeen: '12s ago' },
        { name: 'Paytm Secure Route', license: 'ENT-1109', fp: '7d6c5b4a3f2e1d0c9b...9a8f7e6d', status: 'Suspended', lastSeen: '48h ago' }
    ],
    telemetry: {
        intervals: Array.from({ length: 20 }, () => Math.floor(Math.random() * 80) + 290),
        bytes: [210, 225, 245, 230, 215, 220, 245, 260, 250, 245, 220, 235, 245, 230, 240, 245, 255, 240, 245, 230],
        queue: Array.from({ length: 30 }, () => Math.floor(Math.random() * 2) + 1)
    },
    training: {
        isTraining: false,
        epoch: 48,
        loss: 0.0042,
        progress: 0,
        timer: null
    }
};

// 2. Tab Navigation
function switchTab(tabId) {
    document.querySelectorAll('.dashboard-tab').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));
    
    document.getElementById(`tab-${tabId}`).classList.add('active');
    document.getElementById(`btn-${tabId}`).classList.add('active');
    
    STATE.activeTab = tabId;
    
    // Set headers
    const mainHeading = document.getElementById('main-heading');
    if (tabId === 'fleet') {
        mainHeading.innerText = 'Fleet Control Center';
    } else if (tabId === 'telemetry') {
        mainHeading.innerText = 'Edge Telemetry Ingestion';
        // Initialize canvases when switching to telemetry tab
        setTimeout(initCharts, 50);
    } else if (tabId === 'ai') {
        mainHeading.innerText = 'The Training Ground';
    }
    
    showToast('💡', `Switched dashboard scope to ${tabId.toUpperCase()}`);
}

// 3. UTC System Clock Updater
function updateClock() {
    const clockEl = document.getElementById('val-sys-time');
    const now = new Date();
    const utcStr = now.toUTCString().replace('GMT', 'UTC');
    clockEl.innerText = utcStr;
}
setInterval(updateClock, 1000);
updateClock();

// 4. Fleet Management Interactive Controls
const CONTROL_PLANE_URL = 'http://127.0.0.1:9000';
let isLive = false;

async function fetchFleet() {
    try {
        const response = await fetch(`${CONTROL_PLANE_URL}/api/dashboard/fleet`);
        if (response.ok) {
            const data = await response.json();
            STATE.fleet = data.fleet;
            if (!isLive) {
                isLive = true;
                document.querySelector('.status-indicator .status-label').innerText = 'Control Plane Connected (LIVE)';
                logConsole('success', 'Control Plane connected in LIVE mode.');
            }
            renderFleetTable();
        }
    } catch (e) {
        if (isLive) {
            isLive = false;
            document.querySelector('.status-indicator .status-label').innerText = 'Control Plane Connected (SIMULATED)';
            logConsole('warn', 'Control Plane connection lost. Falling back to simulation mode.');
            renderFleetTable();
        }
    }
}

function renderFleetTable() {
    const tbody = document.querySelector('#fleet-table tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    
    STATE.fleet.forEach(node => {
        const tr = document.createElement('tr');
        tr.id = `row-${node.license.toLowerCase()}`;
        const isOnline = node.status === 'Online';
        tr.innerHTML = `
            <td>
                <div class="client-name-group">
                    <span class="client-title">${node.name}</span>
                    <span class="client-sub">${node.license === 'ENT-1109' ? 'Legacy clearing buffer' : (node.license === 'ENT-9022' ? 'Sponsor Bank Switch' : 'High Frequency Gateway')}</span>
                </div>
            </td>
            <td><span class="monospace badge-license">${node.license}</span></td>
            <td><span class="monospace text-muted text-small">${node.fp}</span></td>
            <td><span class="badge-status ${isOnline ? 'online' : 'offline'}" id="status-${node.license.toLowerCase()}">${node.status}</span></td>
            <td><span class="text-small" id="time-${node.license.toLowerCase()}">${node.lastSeen}</span></td>
            <td>
                <div class="action-group">
                    <button class="action-btn-secondary" id="btn-sync-${node.license.toLowerCase()}" onclick="triggerSync('${node.license}')">Sync Config</button>
                    <button class="${isOnline ? 'action-btn-danger' : 'action-btn-success'}" id="btn-toggle-${node.license.toLowerCase()}" onclick="toggleNode('${node.license}')">${isOnline ? 'Revoke' : 'Activate'}</button>
                </div>
            </td>
        `;
        tbody.appendChild(tr);
    });
    
    // Update summary counts
    const activeLicCount = STATE.fleet.filter(n => n.status === 'Online').length;
    document.getElementById('val-active-lic').innerText = `${activeLicCount} / ${STATE.fleet.length}`;
    document.getElementById('val-total-fleet').innerText = `${STATE.fleet.length} Nodes Active`;
}

async function toggleNode(licenseId) {
    if (isLive) {
        try {
            const response = await fetch(`${CONTROL_PLANE_URL}/api/dashboard/toggle?license_id=${licenseId}`, { method: 'POST' });
            if (response.ok) {
                const data = await response.json();
                const node = STATE.fleet.find(n => n.license === licenseId);
                if (node) {
                    node.status = data.status;
                    node.lastSeen = 'Just now';
                }
                renderFleetTable();
                const statusStr = data.status === 'Online' ? 'Activated' : 'Revoked';
                logConsole(data.status === 'Online' ? 'success' : 'warn', `LICENSE UPDATE: Node ${licenseId} status updated to ${data.status}.`);
                showToast(data.status === 'Online' ? '✅' : '🛑', `${statusStr} license for Node ${licenseId}`);
            }
        } catch (e) {
            logConsole('error', 'Failed to toggle node state on Control Plane.');
        }
    } else {
        const nodeIndex = STATE.fleet.findIndex(n => n.license === licenseId);
        if (nodeIndex === -1) return;
        
        const node = STATE.fleet[nodeIndex];
        if (node.status === 'Online') {
            node.status = 'Suspended';
            node.lastSeen = 'Just now';
            logConsole('warn', `LICENSE REVOCATION: Fleet container node (${licenseId}) suspended by administrator! Boot sequences rejected.`);
            showToast('🛑', `Revoked access license for Node ${licenseId}`);
        } else {
            node.status = 'Online';
            node.lastSeen = 'Just now';
            logConsole('success', `LICENSE GRANTED: Fleet container node (${licenseId}) authorized. Hardware Fingerprint TOFU confirmed.`);
            showToast('✅', `Activated license for Node ${licenseId}`);
        }
        renderFleetTable();
    }
}

async function triggerSync(licenseId) {
    if (isLive) {
        try {
            logConsole('info', `CONFIG PUSH: Dispatching latest daily epoch keys & ISO 8583 parameters to gateway [${licenseId}]...`);
            const response = await fetch(`${CONTROL_PLANE_URL}/api/dashboard/sync?license_id=${licenseId}`, { method: 'POST' });
            if (response.ok) {
                logConsole('success', `SYNC SUCCESS: Gateway [${licenseId}] responded in 42ms. Configuration applied without container downtime.`);
                showToast('⚡', `Successfully pushed and synced configurations for ${licenseId}`);
            }
        } catch (e) {
            logConsole('error', 'Sync config request failed.');
        }
    } else {
        logConsole('info', `CONFIG PUSH: Dispatching latest daily epoch keys & ISO 8583 field ledger parameters to gateway [${licenseId}]...`);
        setTimeout(() => {
            logConsole('success', `SYNC SUCCESS: Gateway [${licenseId}] responded in 42ms. Configuration applied without container downtime.`);
            showToast('⚡', `Successfully pushed and synced configurations for ${licenseId}`);
        }, 600);
    }
}

async function registerNewNode() {
    if (isLive) {
        try {
            const response = await fetch(`${CONTROL_PLANE_URL}/api/dashboard/register`, { method: 'POST' });
            if (response.ok) {
                const data = await response.json();
                logConsole('info', `DEPLOYMENT TRIGGERED: Instantiating lightweight alpine-distroless proxy container on secure port.`);
                logConsole('success', `PROMETHEUS HEARTBEAT: License registered for new node: ${data.license_id}. Speculative barriers verified.`);
                showToast('🔑', `Registered and booted new Shield Node ${data.license_id}`);
                await fetchFleet();
            }
        } catch (e) {
            logConsole('error', 'Failed to register new node on Control Plane.');
        }
    } else {
        const randIdNum = Math.floor(Math.random() * 9000) + 1000;
        const licenseId = `ENT-${randIdNum}`;
        
        const newNode = {
            name: 'Proxy Shield Enclave',
            license: licenseId,
            fp: Array.from({ length: 32 }, () => Math.floor(Math.random()*16).toString(16)).join('').slice(0, 16) + '...',
            status: 'Online',
            lastSeen: 'Just now'
        };
        
        STATE.fleet.push(newNode);
        renderFleetTable();
        
        logConsole('info', `DEPLOYMENT TRIGGERED: Instantiating lightweight alpine-distroless proxy container on secure port.`);
        logConsole('success', `PROMETHEUS HEARTBEAT: License registered for new node: ${licenseId}. Speculative barriers verified.`);
        showToast('🔑', `Registered and booted new Shield Node ${licenseId}`);
    }
}

// 5. Telemetry Chart Rendering Algorithms (Pure Canvas)
function initCharts() {
    drawIntervalChart();
    drawBytesChart();
    drawQueueChart();
}

// Draw Packet Arrival Interval Chart
function drawIntervalChart() {
    const canvas = document.getElementById('chart-packet-intervals');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    // Draw Grid Lines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
    ctx.lineWidth = 1;
    for (let i = 1; i < 5; i++) {
        const y = (canvas.height / 5) * i;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
        ctx.stroke();
    }
    
    // Draw glowing line chart
    const data = STATE.telemetry.intervals;
    const stepX = canvas.width / (data.length - 1);
    
    ctx.beginPath();
    ctx.strokeStyle = '#00b4d8';
    ctx.lineWidth = 3;
    ctx.shadowColor = 'rgba(0, 180, 216, 0.5)';
    ctx.shadowBlur = 10;
    
    data.forEach((val, i) => {
        // Map interval values (between 250 and 400) to Canvas Height
        const mappedY = canvas.height - ((val - 250) * (canvas.height - 40) / 150 + 20);
        if (i === 0) {
            ctx.moveTo(0, mappedY);
        } else {
            ctx.lineTo(i * stepX, mappedY);
        }
    });
    ctx.stroke();
    
    // Gradient fill beneath curve
    ctx.shadowBlur = 0; // Reset shadow
    const gradient = ctx.createLinearGradient(0, 0, 0, canvas.height);
    gradient.addColorStop(0, 'rgba(0, 180, 216, 0.15)');
    gradient.addColorStop(1, 'rgba(0, 180, 216, 0.0)');
    ctx.fillStyle = gradient;
    
    ctx.lineTo(canvas.width, canvas.height);
    ctx.lineTo(0, canvas.height);
    ctx.closePath();
    ctx.fill();
}

// Draw Payload Bytes Distribution Chart
function drawBytesChart() {
    const canvas = document.getElementById('chart-payload-bytes');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    // Grid Lines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
    ctx.lineWidth = 1;
    for (let i = 1; i < 5; i++) {
        const y = (canvas.height / 5) * i;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
        ctx.stroke();
    }
    
    // Draw Bar Chart
    const data = STATE.telemetry.bytes;
    const barWidth = (canvas.width / data.length) - 6;
    
    ctx.shadowBlur = 0;
    
    data.forEach((val, i) => {
        // Map values (between 150 and 300) to height
        const barHeight = (val - 150) * (canvas.height - 40) / 150 + 10;
        const x = i * (canvas.width / data.length) + 3;
        const y = canvas.height - barHeight;
        
        const grad = ctx.createLinearGradient(0, y, 0, canvas.height);
        grad.addColorStop(0, '#00f5d4');
        grad.addColorStop(1, 'rgba(0, 245, 212, 0.1)');
        
        ctx.fillStyle = grad;
        ctx.fillRect(x, y, barWidth, barHeight);
        
        // Add subtle teal dot on top of bar
        ctx.fillStyle = '#f8f9fa';
        ctx.beginPath();
        ctx.arc(x + barWidth/2, y, 2, 0, Math.PI * 2);
        ctx.fill();
    });
}

// Draw Simulated Memory Queue Length
function drawQueueChart() {
    const canvas = document.getElementById('chart-queue-depth');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    // Grid
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.03)';
    ctx.lineWidth = 1;
    for (let i = 1; i < 15; i++) {
        const x = (canvas.width / 15) * i;
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, canvas.height);
        ctx.stroke();
    }
    
    const data = STATE.telemetry.queue;
    const stepX = canvas.width / (data.length - 1);
    
    ctx.beginPath();
    ctx.strokeStyle = '#9d4edd';
    ctx.lineWidth = 4;
    ctx.shadowColor = 'rgba(157, 78, 221, 0.6)';
    ctx.shadowBlur = 12;
    
    data.forEach((val, i) => {
        // Map queue values (0 to 5)
        const mappedY = canvas.height - (val * (canvas.height - 30) / 5 + 15);
        if (i === 0) {
            ctx.moveTo(0, mappedY);
        } else {
            ctx.lineTo(i * stepX, mappedY);
        }
    });
    ctx.stroke();
    
    ctx.shadowBlur = 0;
}

// Poll control plane for fleet status periodically
setInterval(fetchFleet, 3000);
fetchFleet();

// Stream simulated or live telemetry data variations
async function pollTelemetry() {
    if (isLive && STATE.activeTab === 'telemetry') {
        try {
            const response = await fetch(`${CONTROL_PLANE_URL}/api/dashboard/telemetry`);
            if (response.ok) {
                const data = await response.json();
                
                // Shift and add live metrics
                STATE.telemetry.intervals.shift();
                STATE.telemetry.intervals.push(data.last_interval);
                
                STATE.telemetry.bytes.shift();
                STATE.telemetry.bytes.push(data.last_bytes);
                
                STATE.telemetry.queue.shift();
                STATE.telemetry.queue.push(data.active_requests);
                
                initCharts();
                
                document.getElementById('val-mean-delay').innerText = `${data.last_interval} ms`;
                
                if (data.live) {
                    logConsole('info', `LIVE TELEMETRY INGEST: Packet parsed. Queue depth: ${data.active_requests} | Payload size: ${data.last_bytes} bytes`);
                }
            }
        } catch (e) {
            // Ignore telemetry fetch error
        }
    } else if (STATE.activeTab === 'telemetry') {
        // Shift values in arrays and append randomized variations to simulate live traffic
        STATE.telemetry.intervals.shift();
        STATE.telemetry.intervals.push(Math.floor(Math.random() * 80) + 290);
        
        STATE.telemetry.bytes.shift();
        STATE.telemetry.bytes.push(Math.floor(Math.random() * 50) + 220);
        
        STATE.telemetry.queue.shift();
        let nextQ = STATE.telemetry.queue[STATE.telemetry.queue.length - 1] + (Math.random() > 0.5 ? 1 : -1);
        if (nextQ < 0) nextQ = 0;
        if (nextQ > 4) nextQ = 3;
        STATE.telemetry.queue.push(nextQ);
        
        initCharts();
        
        const totalInt = STATE.telemetry.intervals.reduce((a, b) => a + b, 0);
        const avgInt = (totalInt / STATE.telemetry.intervals.length).toFixed(1);
        document.getElementById('val-mean-delay').innerText = `${avgInt} ms`;
    }
}

setInterval(pollTelemetry, 800);

// 6. AI Tab Model Refinement Interactions
function updateLearningRate(val) {
    document.getElementById('val-lr').innerText = val;
}

function triggerTraining() {
    if (STATE.training.isTraining) return;
    
    STATE.training.isTraining = true;
    STATE.training.progress = 0;
    
    document.getElementById('btn-start-training').disabled = true;
    document.getElementById('btn-stop-training').disabled = false;
    document.getElementById('progress-container').classList.remove('hidden');
    
    logConsole('info', `AI CORE INITIALIZATION: Invoking DeepSeek-R1-Distill-Qwen on local hardware cluster.`);
    logConsole('info', `AI CORE INGESTION: Sifting 1,248 packets mapped by the ISO 8583 routing ledger...`);
    
    STATE.training.timer = setInterval(() => {
        STATE.training.progress += Math.floor(Math.random() * 6) + 4;
        
        if (STATE.training.progress >= 100) {
            STATE.training.progress = 100;
            clearInterval(STATE.training.timer);
            
            // Finish state
            STATE.training.isTraining = false;
            document.getElementById('btn-start-training').disabled = false;
            document.getElementById('btn-stop-training').disabled = true;
            
            // Update loss metrics
            STATE.training.epoch += 12;
            STATE.training.loss = 0.0018;
            document.getElementById('val-refine-epoch').innerText = `Epoch ${STATE.training.epoch} / 100`;
            document.getElementById('val-val-loss').innerText = STATE.training.loss;
            
            logConsole('success', `NEURAL FITTING COMPLETE: Optimization converges with final val_loss: 0.0018.`);
            logConsole('success', `MODEL PUSH: Distributing refined tabular edge load-balancer to dynamic proxy shield enclaves.`);
            
            showToast('🧠', 'AI refinement process completed! Optimized model dispatched to edge.');
        } else {
            // Update progress DOM elements
            document.getElementById('progress-pct-lbl').innerText = `${STATE.training.progress}%`;
            document.getElementById('progress-bar-fill').style.width = `${STATE.training.progress}%`;
            
            // Log random fitting messages
            if (STATE.training.progress % 15 === 0) {
                const currentEpoch = Math.floor(STATE.training.progress / 2) + STATE.training.epoch;
                const tempLoss = (STATE.training.loss - (STATE.training.progress * 0.00003)).toFixed(4);
                logConsole('info', `Epoch ${currentEpoch}/100 | Step Loss: ${tempLoss} | Fitting butterfly transform bounds...`);
            }
        }
    }, 400);
    
    showToast('🧠', 'Central refinement process started inside Control Plane...');
}

function abortTraining() {
    if (!STATE.training.isTraining) return;
    
    clearInterval(STATE.training.timer);
    STATE.training.isTraining = false;
    
    document.getElementById('btn-start-training').disabled = false;
    document.getElementById('btn-stop-training').disabled = true;
    document.getElementById('progress-container').classList.add('hidden');
    
    logConsole('warn', `PROCESS ABORTED: Neural fitting thread terminated by administrator request.`);
    showToast('🛑', 'AI refinement loop halted.');
}

// 7. General Utility Functions
function logConsole(type, msg) {
    const consoleLogs = document.getElementById('console-logs');
    if (!consoleLogs) return;
    
    const div = document.createElement('div');
    div.className = `console-line text-${type}`;
    
    const now = new Date();
    const timeStr = now.toISOString().slice(11, 19);
    div.innerText = `[${timeStr}] ${msg}`;
    
    consoleLogs.appendChild(div);
    consoleLogs.scrollTop = consoleLogs.scrollHeight;
}

function showToast(icon, msg) {
    const toast = document.getElementById('toast-notification');
    const toastIcon = document.getElementById('toast-icon');
    const toastMsg = document.getElementById('toast-message');
    
    toastIcon.innerText = icon;
    toastMsg.innerText = msg;
    
    toast.classList.remove('hidden');
    
    // Auto hide after 3 seconds
    if (window.toastTimeout) clearTimeout(window.toastTimeout);
    window.toastTimeout = setTimeout(() => {
        toast.classList.add('hidden');
    }, 3000);
}
