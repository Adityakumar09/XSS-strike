// Initialize Vanta.js background
VANTA.NET({
    el: "#vanta-bg",
    mouseControls: true,
    touchControls: true,
    gyroControls: false,
    minHeight: 200.00,
    minWidth: 200.00,
    scale: 1.00,
    scaleMobile: 1.00,
    color: 0xff6600,
    backgroundColor: 0x0a0a0a,
    points: 15.00,
    maxDistance: 25.00,
    spacing: 18.00
});

let scanInProgress = false;
let currentScanId = null;
let scanInterval = null;
let logsInterval = null;
let allVulnerabilities = [];
let filteredVulnerabilities = [];
let allLogs = [];
let filteredLogs = [];
let logsVisible = false;
let lastLogCount = 0;

// Counter animation variables
let counters = {
    totalVulns: 0,
    reflectedCount: 0,
    highConfidenceCount: 0,
    mediumConfidenceCount: 0
};

// Toast notification function
function showToast(message, type = 'success', duration = 3000) {
    Toastify({
        text: message,
        duration: duration,
        close: true,
        gravity: "top",
        position: "right",
        className: type,
        stopOnFocus: true,
        style: {
            background: type === 'success' ? "linear-gradient(135deg, #00aa00, #00ff00)" :
                       type === 'error' ? "linear-gradient(135deg, #cc0000, #ff0000)" :
                       type === 'warning' ? "linear-gradient(135deg, #ff9900, #ffcc00)" :
                       "linear-gradient(135deg, #ff6600, #ff9900)",
            borderRadius: "8px",
            boxShadow: "0 8px 25px rgba(255, 102, 0, 0.3)",
            fontWeight: "600",
            fontSize: "0.9rem"
        }
    }).showToast();
}

// Logs functionality
function toggleLogs() {
    const logsContainer = document.getElementById('logs-container');
    const toggleBtn = document.getElementById('logs-toggle');
    
    if (logsVisible) {
        logsContainer.style.display = 'none';
        toggleBtn.innerHTML = '<i class="fas fa-eye"></i> Show Logs';
        logsVisible = false;
    } else {
        logsContainer.style.display = 'block';
        toggleBtn.innerHTML = '<i class="fas fa-eye-slash"></i> Hide Logs';
        logsVisible = true;
        displayLogs();
    }
}

function clearLogs() {
    allLogs = [];
    filteredLogs = [];
    lastLogCount = 0;
    const logsContent = document.getElementById('logs-content');
    if (logsContent) {
        logsContent.innerHTML = '<div class="log-entry info">Logs cleared</div>';
    }
    document.getElementById('logs-count').textContent = '0';
    showToast('Logs cleared', 'success', 2000);
}

function filterLogs() {
    const filterValue = document.getElementById('logs-filter').value;
    
    if (filterValue === '') {
        filteredLogs = [...allLogs];
    } else {
        filteredLogs = allLogs.filter(log => log.type === filterValue);
    }
    
    displayLogs();
}

function displayLogs() {
    const logsContent = document.getElementById('logs-content');
    const logsCount = document.getElementById('logs-count');
    
    if (!logsContent || !logsCount) return;
    
    logsCount.textContent = filteredLogs.length;
    
    if (filteredLogs.length === 0) {
        logsContent.innerHTML = '<div class="log-entry info">No logs to display</div>';
        return;
    }
    
    // Show only last 50 logs for performance
    const recentLogs = filteredLogs.slice(-50);
    
    logsContent.innerHTML = recentLogs.map(log => {
        const timestamp = log.timestamp || new Date().toLocaleTimeString();
        const message = escapeHtml(log.message || '');
        const parameter = log.parameter ? escapeHtml(log.parameter) : '';
        const payload = log.payload ? escapeHtml(log.payload) : '';
        const result = log.result ? escapeHtml(log.result) : '';
        
        return `
            <div class="log-entry ${log.type || 'info'}">
                <span class="log-timestamp">[${timestamp}]</span>
                <span class="log-message">${message}</span>
                ${parameter ? `<div class="log-details">Parameter: <span class="log-parameter">${parameter}</span></div>` : ''}
                ${payload ? `<div class="log-details">Payload: <span class="log-payload">${payload}</span></div>` : ''}
                ${result ? `<div class="log-details">Result: ${result}</div>` : ''}
            </div>
        `;
    }).join('');
    
    // Auto-scroll to bottom
    logsContent.scrollTop = logsContent.scrollHeight;
}

async function fetchLogs() {
    if (!currentScanId) return;
    
    try {
        const response = await fetch(`/scan_logs/${currentScanId}`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.logs && data.logs.length > lastLogCount) {
            allLogs = data.logs;
            lastLogCount = data.logs.length;
            
            // Apply current filter
            filterLogs();
            
            if (logsVisible) {
                displayLogs();
            }
        }
    } catch (error) {
        console.error('Error fetching logs:', error);
    }
}

function startLogsMonitoring() {
    if (logsInterval) {
        clearInterval(logsInterval);
    }
    logsInterval = setInterval(fetchLogs, 500); // Fetch logs every 500ms
}

function stopLogsMonitoring() {
    if (logsInterval) {
        clearInterval(logsInterval);
        logsInterval = null;
    }
}

async function startScan() {
    if (scanInProgress) return;
    
    const targetUrl = document.getElementById('target-url').value;
    
    if (!targetUrl) {
        showToast('Please enter a target URL', 'error');
        return;
    }
    
    if (!isValidUrl(targetUrl)) {
        showToast('Please enter a valid URL', 'error');
        return;
    }
    
    // Reset all counters and data
    resetCounters();
    
    scanInProgress = true;
    currentScanId = Date.now().toString();
    lastLogCount = 0;
    
    // Update UI
    document.getElementById('start-scan-btn').style.display = 'none';
    document.getElementById('stop-scan-btn').style.display = 'block';
    document.getElementById('results').style.display = 'block';
    
    showToast('Starting XSS vulnerability scan...', 'success');
    
    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                url: targetUrl,
                scan_id: currentScanId
            })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.error) {
            showToast(`Scan error: ${data.error}`, 'error');
            resetScanUI();
            return;
        }
        
        // Start monitoring scan progress and logs
        startScanMonitoring();
        startLogsMonitoring();
        
        // Show logs by default during scan
        if (!logsVisible) {
            toggleLogs();
        }
        
    } catch (error) {
        console.error('Scan error:', error);
        showToast('An error occurred during scanning. Please try again.', 'error');
        resetScanUI();
    }
}

function resetCounters() {
    // Reset all counters to 0
    const elements = [
        'total-vulns', 'reflected-count', 'high-confidence-count', 'medium-confidence-count',
        'tests-completed', 'total-tests', 'total-payloads', 'parameters-found', 'vulns-found'
    ];
    
    elements.forEach(id => {
        const element = document.getElementById(id);
        if (element) element.textContent = '0';
    });
    
    // Reset progress bar
    const progressFill = document.getElementById('progress-fill');
    const progressPercentage = document.getElementById('progress-percentage');
    if (progressFill) progressFill.style.width = '0%';
    if (progressPercentage) progressPercentage.textContent = '0%';
    
    // Clear data arrays
    allVulnerabilities = [];
    filteredVulnerabilities = [];
    allLogs = [];
    filteredLogs = [];
    lastLogCount = 0;
    
    // Clear UI containers
    const vulnerabilitiesList = document.getElementById('vulnerabilities-list');
    const logsContent = document.getElementById('logs-content');
    const logsCount = document.getElementById('logs-count');
    
    if (vulnerabilitiesList) vulnerabilitiesList.innerHTML = '';
    if (logsContent) logsContent.innerHTML = '';
    if (logsCount) logsCount.textContent = '0';
    
    // Reset counters object
    counters = {
        totalVulns: 0,
        reflectedCount: 0,
        highConfidenceCount: 0,
        mediumConfidenceCount: 0
    };
    
    // Remove any completion indicators
    const completionDivs = document.querySelectorAll('.scan-complete');
    completionDivs.forEach(div => div.remove());
}

function startScanMonitoring() {
    if (scanInterval) {
        clearInterval(scanInterval);
    }
    
    document.getElementById('scan-status').textContent = 'Scanning in progress...';
    
    scanInterval = setInterval(async () => {
        try {
            const response = await fetch(`/scan_status/${currentScanId}`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            
            const data = await response.json();
            
            // Update progress with real data
            updateScanProgress(data);
            
            // Update vulnerabilities
            if (data.vulnerabilities && data.vulnerabilities.length > 0) {
                allVulnerabilities = data.vulnerabilities;
                filteredVulnerabilities = [...allVulnerabilities];
                displayVulnerabilities();
                updateSummaryCards();
            }
            
            // Check if scan is complete
            if (!data.is_running || data.scan_complete) {
                stopScanMonitoring();
                stopLogsMonitoring();
                
                document.getElementById('scan-status').textContent = 'Scan completed';
                document.getElementById('progress-percentage').textContent = '100%';
                document.getElementById('progress-fill').style.width = '100%';
                
                // Show completion notification
                const vulnCount = data.vulnerabilities_found || 0;
                if (vulnCount > 0) {
                    showToast(`Scan completed! Found ${vulnCount} vulnerabilities`, 'warning', 5000);
                } else {
                    showToast('Scan completed! No vulnerabilities found', 'success', 5000);
                }
                
                // Add completion indicator
                const scanProgress = document.getElementById('scan-progress');
                if (scanProgress && !document.querySelector('.scan-complete')) {
                    const completionDiv = document.createElement('div');
                    completionDiv.className = 'scan-complete';
                    completionDiv.innerHTML = `<i class="fas fa-check-circle"></i> Scan Completed - ${vulnCount} vulnerabilities found`;
                    scanProgress.appendChild(completionDiv);
                }
                
                resetScanUI();
            }
            
        } catch (error) {
            console.error('Error monitoring scan:', error);
            showToast('Error monitoring scan progress', 'error');
            stopScanMonitoring();
            stopLogsMonitoring();
            resetScanUI();
        }
    }, 1000);
}

function stopScanMonitoring() {
    if (scanInterval) {
        clearInterval(scanInterval);
        scanInterval = null;
    }
}

async function stopScan() {
    try {
        const response = await fetch('/stop_scan', {
            method: 'POST'
        });
        
        if (response.ok) {
            stopScanMonitoring();
            stopLogsMonitoring();
            document.getElementById('scan-status').textContent = 'Scan stopped by user';
            showToast('Scan stopped by user', 'warning');
            resetScanUI();
        }
        
    } catch (error) {
        console.error('Error stopping scan:', error);
        showToast('Error stopping scan', 'error');
    }
}

function resetScanUI() {
    scanInProgress = false;
    const startBtn = document.getElementById('start-scan-btn');
    const stopBtn = document.getElementById('stop-scan-btn');
    
    if (startBtn) startBtn.style.display = 'block';
    if (stopBtn) stopBtn.style.display = 'none';
}

function updateScanProgress(data) {
    // Update progress bar with real percentage
    const progress = Math.min(data.progress || 0, 100);
    const progressFill = document.getElementById('progress-fill');
    const progressPercentage = document.getElementById('progress-percentage');
    
    if (progressFill) progressFill.style.width = `${progress}%`;
    if (progressPercentage) progressPercentage.textContent = `${Math.round(progress)}%`;
    
    // Update all counters with real data
    const updates = {
        'tests-completed': data.completed_tests || 0,
        'total-tests': data.total_tests || 0,
        'total-payloads': data.total_payloads || 0,
        'parameters-found': data.parameters_found || 0,
        'vulns-found': data.vulnerabilities_found || 0
    };
    
    Object.entries(updates).forEach(([id, value]) => {
        const element = document.getElementById(id);
        if (element) element.textContent = value;
    });
}

function updateSummaryCards() {
    const totalVulns = allVulnerabilities.length;
    const reflectedCount = allVulnerabilities.filter(v => v.type === 'reflected').length;
    const highConfidenceCount = allVulnerabilities.filter(v => v.confidence === 'High').length;
    const mediumConfidenceCount = allVulnerabilities.filter(v => v.confidence === 'Medium').length;
    
    // Only animate if values have changed
    if (counters.totalVulns !== totalVulns) {
        animateCounter('total-vulns', counters.totalVulns, totalVulns);
        counters.totalVulns = totalVulns;
    }
    
    if (counters.reflectedCount !== reflectedCount) {
        animateCounter('reflected-count', counters.reflectedCount, reflectedCount);
        counters.reflectedCount = reflectedCount;
    }
    
    if (counters.highConfidenceCount !== highConfidenceCount) {
        animateCounter('high-confidence-count', counters.highConfidenceCount, highConfidenceCount);
        counters.highConfidenceCount = highConfidenceCount;
    }
    
    if (counters.mediumConfidenceCount !== mediumConfidenceCount) {
        animateCounter('medium-confidence-count', counters.mediumConfidenceCount, mediumConfidenceCount);
        counters.mediumConfidenceCount = mediumConfidenceCount;
    }
}

function animateCounter(elementId, startValue, targetValue) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    const duration = 1000;
    const startTime = performance.now();
    
    function updateCounter(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const currentValue = Math.floor(startValue + (targetValue - startValue) * progress);
        
        element.textContent = currentValue;
        
        if (progress < 1) {
            requestAnimationFrame(updateCounter);
        } else {
            element.textContent = targetValue;
        }
    }
    
    requestAnimationFrame(updateCounter);
}

function displayVulnerabilities() {
    const container = document.getElementById('vulnerabilities-list');
    if (!container) return;
    
    container.innerHTML = '';
    
    if (filteredVulnerabilities.length === 0) {
        container.innerHTML = `
            <div class="no-vulnerabilities">
                <h3><i class="fas fa-shield-alt"></i> No vulnerabilities found matching current filters</h3>
                <p>Try adjusting your filters or the target appears to be secure.</p>
            </div>
        `;
        return;
    }
    
    filteredVulnerabilities.forEach((vuln, index) => {
        const vulnElement = createVulnerabilityElement(vuln, index);
        container.appendChild(vulnElement);
    });
}

function createVulnerabilityElement(vuln, index) {
    const div = document.createElement('div');
    div.className = 'vulnerability-item';
    
    const typeClass = (vuln.type || 'unknown').toLowerCase();
    const confidenceClass = (vuln.confidence || 'medium').toLowerCase();
    
    div.innerHTML = `
        <div class="vuln-header">
            <div class="vuln-badges">
                <span class="vuln-type ${typeClass}">${(vuln.type || 'UNKNOWN').toUpperCase()} XSS</span>
                <span class="vuln-confidence ${confidenceClass}">${vuln.confidence || 'Medium'} Confidence</span>
                <span class="vuln-status">Status: ${vuln.status_code || 'N/A'}</span>
            </div>
        </div>
        <div class="vuln-details">
            <div class="vuln-detail-row">
                <span class="vuln-detail-label">URL:</span>
                <span class="vuln-detail-value">${escapeHtml(vuln.url || 'N/A')}</span>
            </div>
            ${vuln.parameter ? `
                <div class="vuln-detail-row">
                    <span class="vuln-detail-label">Parameter:</span>
                    <span class="vuln-detail-value">${escapeHtml(vuln.parameter)}</span>
                </div>
            ` : ''}
            <div class="vuln-detail-row">
                <span class="vuln-detail-label">Payload ID:</span>
                <span class="vuln-detail-value">${vuln.payload_id || 'N/A'}</span>
            </div>
            <div class="vuln-detail-row">
                <span class="vuln-detail-label">Response Time:</span>
                <span class="vuln-detail-value">${vuln.response_time || 'N/A'} ms</span>
            </div>
            ${vuln.execution_details ? `
                <div class="execution-details">
                    <strong>Execution Details:</strong> ${escapeHtml(vuln.execution_details)}
                </div>
            ` : ''}
            <div class="vuln-payload" onclick="copyPayload('${escapeHtml(vuln.payload || '')}')">
                <strong>Payload:</strong> ${escapeHtml(vuln.payload || 'N/A')}
                <small style="opacity: 0.7; margin-left: 10px;">(Click to copy)</small>
            </div>
        </div>
    `;
    
    return div;
}

function copyPayload(payload) {
    if (!payload) return;
    
    navigator.clipboard.writeText(payload).then(() => {
        showToast('Payload copied to clipboard!', 'success');
    }).catch(err => {
        showToast('Failed to copy payload', 'error');
        console.error('Copy failed:', err);
    });
}

function filterResults() {
    const statusFilter = document.getElementById('status-filter').value;
    const confidenceFilter = document.getElementById('confidence-filter').value;
    const payloadSearch = document.getElementById('payload-search').value.toLowerCase();
    
    filteredVulnerabilities = allVulnerabilities.filter(vuln => {
        const matchesStatus = !statusFilter || vuln.status_code == statusFilter;
        const matchesConfidence = !confidenceFilter || vuln.confidence === confidenceFilter;
        const matchesPayload = !payloadSearch || (vuln.payload && vuln.payload.toLowerCase().includes(payloadSearch));
        
        return matchesStatus && matchesConfidence && matchesPayload;
    });
    
    displayVulnerabilities();
    showToast(`Filtered to ${filteredVulnerabilities.length} results`, 'success', 2000);
}

async function exportCSV() {
    if (allVulnerabilities.length === 0) {
        showToast('No vulnerabilities to export', 'warning');
        return;
    }
    
    try {
        const response = await fetch('/export_csv');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const blob = await response.blob();
        
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `xss_scan_results_${new Date().getTime()}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        
        showToast('CSV file exported successfully!', 'success');
        
    } catch (error) {
        console.error('Error exporting CSV:', error);
        showToast('Error exporting CSV file', 'error');
    }
}

function clearResults() {
    allVulnerabilities = [];
    filteredVulnerabilities = [];
    allLogs = [];
    filteredLogs = [];
    lastLogCount = 0;
    
    const elements = ['results', 'status-filter', 'confidence-filter', 'payload-search', 'logs-filter'];
    elements.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            if (id === 'results') {
                element.style.display = 'none';
            } else {
                element.value = '';
            }
        }
    });
    
    resetScanUI();
    resetCounters();
    showToast('Results cleared', 'success');
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function isValidUrl(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

// Add keyboard shortcuts
document.addEventListener('keydown', function(e) {
    if (e.ctrlKey && e.key === 'Enter') {
        if (!scanInProgress) {
            startScan();
        }
    }
    
    if (e.key === 'Escape' && scanInProgress) {
        stopScan();
    }
    
    if (e.ctrlKey && e.key === 's') {
        e.preventDefault();
        if (allVulnerabilities.length > 0) {
            exportCSV();
        }
    }
    
    if (e.ctrlKey && e.key === 'l') {
        e.preventDefault();
        toggleLogs();
    }
});

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    showToast('XSS Scanner ready! Enter a URL to begin scanning.', 'success', 4000);
    
    // Initialize logs section
    const logsContainer = document.getElementById('logs-container');
    if (logsContainer) {
        logsContainer.style.display = 'none';
        logsVisible = false;
    }
    
    // Test connectivity
    fetch('/health')
        .then(response => response.json())
        .then(data => {
            console.log('Scanner backend connected:', data);
        })
        .catch(error => {
            console.error('Backend connection failed:', error);
            showToast('Warning: Backend connection issues detected', 'warning', 5000);
        });
});
