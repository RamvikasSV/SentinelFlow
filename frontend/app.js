// Cyber Agent Front-End Controller

let ws;
const wsStatus = document.getElementById("ws-status");
const logTerminal = document.getElementById("log-terminal");
const thoughtLog = document.getElementById("thought-log");
const chatMessages = document.getElementById("chat-messages");
const chatInput = document.getElementById("chat-input");
const blockedIpList = document.getElementById("blocked-ip-list");
const blockedCountVal = document.getElementById("blocked-count-val");
const firewallCount = document.getElementById("firewall-count");
const targetModeVal = document.getElementById("target-mode-val");
const processTableBody = document.getElementById("process-table-body");
const connectionsTableBody = document.getElementById("connections-table-body");
const registeredUsersList = document.getElementById("registered-users-list");

let recentBlockedIPs = new Set();

// Initialize application
document.addEventListener("DOMContentLoaded", () => {
    connectWebSocket();
    // Query initial state
    fetchSystemState();
    fetchUsers();
    
    // Apply default snap layout
    applySnapLayout("3-col");
    
    // Prevent dropdown closing when clicking inside layouts panel
    const selector = document.querySelector(".layout-selector-container");
    if (selector) {
        selector.addEventListener("click", (e) => {
            e.stopPropagation();
        });
    }

    // Auto-query server state every 3 seconds to keep process tables and sockets updated
    setInterval(fetchSystemState, 3000);
});

// WebSocket Connection
function connectWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.host || "localhost:8000";
    const wsUrl = `${protocol}//${host}/ws`;

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        wsStatus.textContent = "CONNECTED";
        wsStatus.className = "status-indicator online";
        addSystemLine("[SYSTEM] Established real-time WebSocket connection to agent pipeline.");
    };

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            handleBrokerEvent(data);
        } catch (e) {
            console.error("Error parsing WebSocket event:", e);
        }
    };

    ws.onclose = () => {
        wsStatus.textContent = "DISCONNECTED";
        wsStatus.className = "status-indicator offline";
        addSystemLine("[SYSTEM] WebSocket disconnected. Attempting reconnection in 3 seconds...");
        removeTypingIndicator();
        setTimeout(connectWebSocket, 3000);
    };

    ws.onerror = (err) => {
        console.error("WebSocket Error:", err);
    };
}

// REST queries to populate UI components on startup/interval
async function fetchSystemState() {
    try {
        const res = await fetch("/api/state");
        if (res.ok) {
            const state = await res.json();
            updateHostStateUI(state);
        }
    } catch (e) {
        console.error("Error fetching system state:", e);
    }
}

async function fetchUsers() {
    try {
        const res = await fetch("/api/users");
        if (res.ok) {
            const users = await res.json();
            updateUsersUI(users);
        }
    } catch (e) {
        console.error("Error fetching registered recipients:", e);
    }
}

function updateUsersUI(users) {
    if (!registeredUsersList) return;
    registeredUsersList.innerHTML = "";
    if (users.length === 0) {
        registeredUsersList.innerHTML = '<li class="empty-list-placeholder">No recipients registered. Falling back to default .env recipient.</li>';
    } else {
        users.forEach(u => {
            const li = document.createElement("li");
            li.className = "user-item";
            const dateStr = u.created_at ? new Date(u.created_at).toLocaleString() : "Unknown";
            li.innerHTML = `
                <div class="user-info">
                    <span class="user-name">${u.name}</span>
                    <span class="user-email">${u.email}</span>
                    <span class="user-meta">Registered: ${dateStr}</span>
                </div>
                <button class="btn-delete" onclick="deleteUser('${u.email}')">DELETE</button>
            `;
            registeredUsersList.appendChild(li);
        });
    }
}

async function handleRegisterUser() {
    const nameInput = document.getElementById("reg-name");
    const emailInput = document.getElementById("reg-email");
    if (!nameInput || !emailInput) return;
    
    const name = nameInput.value.trim();
    const email = emailInput.value.trim();
    if (!name || !email) return;

    try {
        const res = await fetch("/api/users", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ name, email })
        });
        if (res.ok) {
            addSystemLine(`[USER ACTION] Registered new notification recipient: ${name} (${email})`);
            nameInput.value = "";
            emailInput.value = "";
            fetchUsers();
        } else {
            const data = await res.json();
            alert(`Error registering recipient: ${data.detail || 'Invalid email or duplicate registration'}`);
        }
    } catch (e) {
        console.error("Error registering user:", e);
    }
}

async function deleteUser(email) {
    try {
        const res = await fetch(`/api/users/${encodeURIComponent(email)}`, {
            method: "DELETE"
        });
        if (res.ok) {
            addSystemLine(`[USER ACTION] Removed notification recipient: ${email}`);
            fetchUsers();
        }
    } catch (e) {
        console.error("Error deleting recipient:", e);
    }
}

// Handle Agent Broker Events
function handleBrokerEvent(event) {
    const type = event.event_type;
    const source = event.source;
    const data = event.data;

    // 1. Raw Log Line
    if (type === "log_line") {
        appendTerminalLine(data.line, data.type);
    }
    
    // 2. Agent Thought Log
    else if (type === "agent_thought") {
        appendThoughtItem(source, data.text);
        triggerAgentNodeAnimation(source);
    }
    
    // 3. Chat Message
    else if (type === "chat_message") {
        if (source !== "user") {
            removeTypingIndicator();
        }
        // Avoid double printing user messages since we append on send
        if (source === "user" && isLastBubbleUser()) {
            return;
        }
        appendChatBubble(source, data.text);
    }
    
    // 4. Remediation or Threat classification details
    else if (type === "remediation" || type === "threat_classification") {
        fetchSystemState(); // Force update states
    }
}

// UI: Log Terminal Updater
function appendTerminalLine(line, type) {
    const span = document.createElement("span");
    span.className = `term-line ${type}-line`;
    
    // Highlight warn or critical lines
    const lowerLine = line.toLowerCase();
    if (lowerLine.includes("failed") || lowerLine.includes("failure") || lowerLine.includes("unauthorized") || lowerLine.includes("not allowed")) {
        span.className += " warn-line";
    }
    if (lowerLine.includes("blocked") || lowerLine.includes("quarantine") || lowerLine.includes("drop") || lowerLine.includes("breach") || lowerLine.includes("compromise")) {
        span.className += " critical-line";
    }

    span.textContent = line;
    logTerminal.appendChild(span);
    
    // Auto-scroll
    logTerminal.scrollTop = logTerminal.scrollHeight;

    // Performance limiter (keep max 400 lines)
    if (logTerminal.children.length > 400) {
        logTerminal.removeChild(logTerminal.firstChild);
    }
}

function addSystemLine(msg) {
    appendTerminalLine(msg, "system");
}

// UI: Agent Thinking Log
function appendThoughtItem(agent, text) {
    const item = document.createElement("div");
    item.className = "thought-item";
    
    const time = new Date().toLocaleTimeString();
    
    item.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <span class="agent-tag ${agent}">${agent.toUpperCase()}</span>
            <span class="time">${time}</span>
        </div>
        <p class="thought-text">${text}</p>
    `;
    
    thoughtLog.appendChild(item);
    thoughtLog.scrollTop = thoughtLog.scrollHeight;
}

// UI: Agent flowchart animations
function triggerAgentNodeAnimation(agent) {
    const nodeScanner = document.getElementById("node-scanner");
    const nodeClassifier = document.getElementById("node-classifier");
    const nodeForensics = document.getElementById("node-forensics");
    const nodeResponse = document.getElementById("node-response");
    
    const lineScannerClassifier = document.getElementById("line-scanner-classifier");
    const lineClassifierForensics = document.getElementById("line-classifier-forensics");
    const lineForensicsResponse = document.getElementById("line-forensics-response");
    const lineClassifierResponse = document.getElementById("line-classifier-response");

    // Remove active classes
    nodeScanner.classList.remove("active");
    nodeClassifier.classList.remove("active-classifier");
    nodeForensics.classList.remove("active-forensics");
    nodeResponse.classList.remove("active-response");
    
    lineScannerClassifier.classList.remove("active");
    lineClassifierForensics.classList.remove("active");
    lineForensicsResponse.classList.remove("active");
    lineClassifierResponse.classList.remove("active");

    // Apply active class to node based on thought source
    if (agent === "log_scanner") {
        nodeScanner.classList.add("active");
        lineScannerClassifier.classList.add("active");
    } else if (agent === "threat_classifier") {
        nodeClassifier.classList.add("active-classifier");
        lineClassifierForensics.classList.add("active");
        lineClassifierResponse.classList.add("active");
    } else if (agent === "forensics_investigator") {
        nodeForensics.classList.add("active-forensics");
        lineForensicsResponse.classList.add("active");
    } else if (agent === "response_agent") {
        nodeResponse.classList.add("active-response");
    }

    // Decay animation after 1.8 seconds to represent idle wait states
    setTimeout(() => {
        nodeScanner.classList.remove("active");
        nodeClassifier.classList.remove("active-classifier");
        nodeForensics.classList.remove("active-forensics");
        nodeResponse.classList.remove("active-response");
        
        lineScannerClassifier.classList.remove("active");
        lineClassifierForensics.classList.remove("active");
        lineForensicsResponse.classList.remove("active");
        lineClassifierResponse.classList.remove("active");
    }, 1800);
}

// UI: Chat Bubbles & Markdown Translator
function appendChatBubble(sender, text) {
    const bubble = document.createElement("div");
    bubble.className = `chat-bubble ${sender === "user" ? "user" : "assistant"}`;
    
    const formattedText = parseMarkdown(text);
    
    bubble.innerHTML = `
        <div class="bubble-sender">${sender.toUpperCase()}</div>
        <div class="bubble-content">${formattedText}</div>
    `;
    
    chatMessages.appendChild(bubble);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

function isLastBubbleUser() {
    const bubbles = chatMessages.children;
    if (bubbles.length === 0) return false;
    for (let i = bubbles.length - 1; i >= 0; i--) {
        const bubble = bubbles[i];
        if (bubble.id === "typing-indicator-bubble") {
            continue;
        }
        return bubble.classList.contains("user");
    }
    return false;
}

function parseMarkdown(text) {
    let html = text;
    
    // 1. Escape HTML first to prevent raw tag issues
    html = html
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
    
    // 2. Parse Markdown Tables
    const lines = html.split('\n');
    let inTable = false;
    let tableRows = [];
    let processedLines = [];
    
    for (let i = 0; i < lines.length; i++) {
        let line = lines[i].trim();
        
        if (line.startsWith('|') && line.endsWith('|')) {
            if (!inTable) {
                inTable = true;
                tableRows = [];
            }
            tableRows.push(line);
        } else {
            if (inTable) {
                processedLines.push(renderHTMLTable(tableRows));
                inTable = false;
            }
            processedLines.push(lines[i]);
        }
    }
    if (inTable) {
        processedLines.push(renderHTMLTable(tableRows));
    }
    
    html = processedLines.join('\n');
    
    // 3. Bold (**text**)
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    
    // 4. Headers (### Name)
    html = html.replace(/### (.*?)(?:\n|$)/g, '<h3>$1</h3>');
    
    // 5. Unordered lists (- Item)
    html = html.replace(/^\s*-\s*(.*?)$/gm, '<li>$1</li>');
    html = html.replace(/(<li>.*?<\/li>)/gs, '<ul>$1</ul>');
    html = html.replace(/<\/ul>\s*<ul>/g, '');
    
    // 6. Code blocks ```code```
    html = html.replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>');
    
    // 7. Inline code `code`
    html = html.replace(/`(.*?)`/g, '<code>$1</code>');
    
    return html;
}

function renderHTMLTable(markdownRows) {
    if (markdownRows.length < 2) {
        return markdownRows.join('\n');
    }
    
    const dividerRow = markdownRows[1];
    const isDivider = /^\|\s*[:\-|\s]+\s*\|$/.test(dividerRow);
    if (!isDivider) {
        return markdownRows.join('\n');
    }
    
    const alignments = dividerRow
        .split('|')
        .slice(1, -1)
        .map(cell => {
            cell = cell.trim();
            const alignLeft = cell.startsWith(':');
            const alignRight = cell.endsWith(':');
            if (alignLeft && alignRight) return 'center';
            if (alignRight) return 'right';
            return 'left';
        });
        
    const headerCells = markdownRows[0]
        .split('|')
        .slice(1, -1)
        .map(cell => cell.trim());
        
    let tableHtml = '<div class="chat-table-container"><table class="chat-table"><thead><tr>';
    
    headerCells.forEach((header, index) => {
        const align = alignments[index] || 'left';
        tableHtml += `<th style="text-align: ${align}">${header}</th>`;
    });
    
    tableHtml += '</tr></thead><tbody>';
    
    for (let r = 2; r < markdownRows.length; r++) {
        const cells = markdownRows[r]
            .split('|')
            .slice(1, -1)
            .map(cell => cell.trim());
            
        if (cells.length === 0 || (cells.length === 1 && cells[0] === "")) continue;
        
        tableHtml += '<tr>';
        for (let c = 0; c < headerCells.length; c++) {
            const cellVal = cells[c] !== undefined ? cells[c] : '';
            const align = alignments[c] || 'left';
            tableHtml += `<td style="text-align: ${align}">${cellVal}</td>`;
        }
        tableHtml += '</tr>';
    }
    
    tableHtml += '</tbody></table></div>';
    return tableHtml;
}

// UI: Host state metrics tables
function updateHostStateUI(state) {
    targetModeVal.textContent = state.mode.toUpperCase();
    
    // Update blocked list
    blockedIpList.innerHTML = "";
    const blockedCount = state.blocked_ips.length;
    blockedCountVal.textContent = blockedCount;
    firewallCount.textContent = `${blockedCount} IP(s)`;

    if (blockedCount === 0) {
        blockedIpList.innerHTML = '<li class="empty-list-placeholder">No active IP drops in firewall</li>';
    } else {
        state.blocked_ips.forEach(ip => {
            const li = document.createElement("li");
            li.className = "blocked-item";
            li.innerHTML = `
                <span class="ip">🚫 ${ip}</span>
                <button class="unblock-action" onclick="unblockIP('${ip}')">UNBLOCK</button>
            `;
            blockedIpList.appendChild(li);
        });
    }

    // Update process table
    processTableBody.innerHTML = "";
    if (state.processes.length === 0) {
        processTableBody.innerHTML = '<tr><td colspan="5" class="empty-table-placeholder">No processes reported</td></tr>';
    } else {
        state.processes.forEach(p => {
            const tr = document.createElement("tr");
            
            // Check if process is malicious
            const isMalicious = p.cmd.includes("backdoor") || p.cmd.includes("shell") || p.cmd.includes("nc -e");
            if (isMalicious) {
                tr.className = "malicious-row";
            }
            
            tr.innerHTML = `
                <td><code>${p.pid}</code></td>
                <td><code>${p.user}</code></td>
                <td>${p.cpu}%</td>
                <td>${p.mem}%</td>
                <td><code>${p.cmd}</code></td>
            `;
            processTableBody.appendChild(tr);
        });
    }

    // Update connections table
    connectionsTableBody.innerHTML = "";
    if (state.connections.length === 0) {
        connectionsTableBody.innerHTML = '<tr><td colspan="4" class="empty-table-placeholder">No active connections</td></tr>';
    } else {
        state.connections.forEach(c => {
            const tr = document.createElement("tr");
            
            // Highlight connections from blocked IPs or related malicious socket configurations
            const isSuspicious = c.remote.includes(":4444");
            if (isSuspicious) {
                tr.className = "malicious-row";
            }
            
            tr.innerHTML = `
                <td><code>${c.proto.toUpperCase()}</code></td>
                <td><code>${c.local}</code></td>
                <td><code>${c.remote}</code></td>
                <td><code>${c.state}</code></td>
            `;
            connectionsTableBody.appendChild(tr);
        });
    }
}

// REST Action: Trigger manual unblock from UI button
async function unblockIP(ip) {
    try {
        const res = await fetch(`/api/firewall/unblock/${ip}`, { method: "POST" });
        if (res.ok) {
            addSystemLine(`[USER ACTION] Triggered manual unblock command for: ${ip}`);
            fetchSystemState();
        }
    } catch (e) {
        console.error("Error unblocking IP:", e);
    }
}

// REST Action: Trigger simulated attacks
async function triggerSimulation(type) {
    try {
        addSystemLine(`[USER ACTION] Triggered attack simulation: ${type}`);
        const res = await fetch(`/api/simulate/${type}`, { method: "POST" });
        if (res.ok) {
            const data = await res.json();
            appendThoughtItem("system", `Attack simulation launched: ${data.message}`);
        }
    } catch (e) {
        console.error("Error launching simulation:", e);
    }
}

// Send chat command
function sendChatMessage() {
    const text = chatInput.value.trim();
    if (!text) return;

    appendChatBubble("user", text);
    chatInput.value = "";

    // Show typing indicator
    showTypingIndicator();

    // Send via WebSocket
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            action: "chat_command",
            message: text
        }));
    } else {
        removeTypingIndicator();
        appendChatBubble("crew_coordinator", "⚠️ **Connection Error**: Lost websocket link to coordinator. Try again in a few seconds.");
    }
}

function checkChatInput(event) {
    if (event.key === "Enter") {
        sendChatMessage();
    }
}

// Click suggestion chip
function clickSuggestion(command) {
    chatInput.value = command;
    sendChatMessage();
}

// Show typing indicator bubble
function showTypingIndicator() {
    if (document.getElementById("typing-indicator-bubble")) {
        return;
    }
    const bubble = document.createElement("div");
    bubble.className = "chat-bubble assistant typing-bubble";
    bubble.id = "typing-indicator-bubble";
    
    bubble.innerHTML = `
        <div class="bubble-sender">
            <span class="avatar-icon">🤖</span>
            CREW_COORDINATOR
        </div>
        <div class="bubble-content">
            <div class="typing-indicator">
                <span class="typing-dot"></span>
                <span class="typing-dot"></span>
                <span class="typing-dot"></span>
            </div>
        </div>
    `;
    
    chatMessages.appendChild(bubble);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// Remove typing indicator bubble
function removeTypingIndicator() {
    const bubble = document.getElementById("typing-indicator-bubble");
    if (bubble) {
        bubble.remove();
    }
}

// Switch active sidebar tabs
function switchSideTab(tabId) {
    // Remove active class from all side tabs
    const tabs = document.querySelectorAll(".side-tab");
    tabs.forEach(t => t.classList.remove("active"));
    
    // Add active class to clicked tab
    const activeTab = document.querySelector(`.side-tab[onclick*="switchSideTab('${tabId}')"]`);
    if (activeTab) {
        activeTab.classList.add("active");
    }
    
    // Hide all side panes
    const panes = document.querySelectorAll(".side-pane");
    panes.forEach(p => p.classList.remove("active-pane"));
    
    // Show target side pane
    const targetPane = document.getElementById(`side-pane-${tabId}`);
    if (targetPane) {
        targetPane.classList.add("active-pane");
    }
    
    // Auto scroll console and logs to bottom if they are opened
    if (tabId === "chat") {
        chatMessages.scrollTop = chatMessages.scrollHeight;
    } else if (tabId === "agents") {
        thoughtLog.scrollTop = thoughtLog.scrollHeight;
    }
}

// Toggle Left Panel (Logs)
function toggleLeftPanel() {
    const panel = document.querySelector(".main-left");
    const restoreBtn = document.getElementById("restore-left-btn");
    const workspace = document.querySelector(".workspace-layout");
    
    if (panel.classList.contains("collapsed-panel")) {
        panel.classList.remove("collapsed-panel");
        if (workspace) workspace.classList.remove("left-collapsed");
        restoreBtn.style.display = "none";
        // Recalculate terminal scroll
        setTimeout(() => {
            if (logTerminal) logTerminal.scrollTop = logTerminal.scrollHeight;
        }, 360);
    } else {
        panel.classList.add("collapsed-panel");
        if (workspace) workspace.classList.add("left-collapsed");
        restoreBtn.style.display = "flex";
    }
}

// Toggle Right Panel (Chat)
function toggleRightPanel() {
    const panel = document.querySelector(".main-right");
    const restoreBtn = document.getElementById("restore-right-btn");
    const workspace = document.querySelector(".workspace-layout");
    
    if (panel.classList.contains("collapsed-panel")) {
        panel.classList.remove("collapsed-panel");
        if (workspace) workspace.classList.remove("right-collapsed");
        restoreBtn.style.display = "none";
        // Recalculate chat scroll
        setTimeout(() => {
            if (chatMessages) chatMessages.scrollTop = chatMessages.scrollHeight;
        }, 360);
    } else {
        panel.classList.add("collapsed-panel");
        if (workspace) workspace.classList.add("right-collapsed");
        restoreBtn.style.display = "flex";
    }
}

// Toggle Snap Flyout Menu
function toggleSnapFlyout(event) {
    event.stopPropagation();
    const flyout = document.getElementById("snap-flyout");
    flyout.classList.toggle("show");
}

// Close flyout when clicking outside
document.addEventListener("click", () => {
    const flyout = document.getElementById("snap-flyout");
    if (flyout && flyout.classList.contains("show")) {
        flyout.classList.remove("show");
    }
});

// Apply Snap Layout
function applySnapLayout(layoutType) {
    const workspace = document.querySelector(".workspace-layout");
    if (!workspace) return;
    
    // Remove all previous snap classes and collapsed workspace states
    workspace.className = "workspace-layout";
    workspace.classList.remove("left-collapsed", "right-collapsed");
    
    // Add new snap class
    workspace.classList.add(`snap-${layoutType}`);
    
    // Hide restore side bars when a snap layout is active
    document.getElementById("restore-left-btn").style.display = "none";
    document.getElementById("restore-right-btn").style.display = "none";
    
    // Remove collapsed classes from columns
    document.querySelector(".main-left").classList.remove("collapsed-panel");
    document.querySelector(".main-middle").classList.remove("collapsed-panel");
    document.querySelector(".main-right").classList.remove("collapsed-panel");
    
    // Update active class on snap cards
    const cards = document.querySelectorAll(".snap-option-card");
    cards.forEach(card => {
        const onClickAttr = card.getAttribute("onclick") || "";
        if (onClickAttr.includes(`'${layoutType}'`)) {
            card.classList.add("active");
        } else {
            card.classList.remove("active");
        }
    });
    
    // Close snap flyout
    const flyout = document.getElementById("snap-flyout");
    if (flyout) {
        flyout.classList.remove("show");
    }
    
    // Force auto scroll logs and chat
    setTimeout(() => {
        if (logTerminal) logTerminal.scrollTop = logTerminal.scrollHeight;
        if (chatMessages) chatMessages.scrollTop = chatMessages.scrollHeight;
        if (thoughtLog) thoughtLog.scrollTop = thoughtLog.scrollHeight;
    }, 100);
}
