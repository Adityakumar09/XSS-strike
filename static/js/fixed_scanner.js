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
let allVulnerabilities = [];
let filteredVulnerabilities = [];

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
    
    // Reset all counters to 0
    resetCounters();
    
    scanInProgress = true;
    currentScanId = Date.now().toString();
    
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
        
        const data = await response.json();
        
        if (data.error) {
            showToast(`Scan error: ${data.error}`, 'error');
            resetScanUI();
            return;
        }
        
        // Start monitoring scan progress
        startScanMonitoring();
        
    } catch (error) {
        console.error('Scan error:', error);
        showToast('An error occurred during scanning. Please try again.', 'error');
        resetScanUI();
    }
}

function resetCounters() {
    // Reset all counters to 0
    document.getElementById('total-vulns').textContent = '0';
    document.getElementById('reflected-count').textContent = '0';
    document.getElementById('high-confidence-count').textContent = '0';
    document.getElementById('medium-confidence-count').textContent = '0';
    document.getElementById('tests-completed').textContent = '0';
    document.getElementById('total-tests').textContent = '0';
    document.getElementById('total-payloads').textContent = '0';
    document.getElementById('parameters-found').textContent = '0';
    document.getElementById('vulns-found').textContent = '0';
    
    // Reset progress bar
    document.getElementById('progress-fill').style.width = '0%';
    document.getElementById('progress-percentage').textContent = '0%';
    
    // Clear vulnerabilities
    allVulnerabilities = [];
    filteredVulnerabilities = [];
    document.getElementById('vulnerabilities-list').innerHTML = '';
    
    // Reset counters object
    counters = {
        totalVulns: 0,
        reflectedCount: 0,
        highConfidenceCount: 0,
        mediumConfidenceCount: 0
    };
}

function startScanMonitoring() {
    document.getElementById('scan-status').textContent = 'Scanning in progress...';
    
    scanInterval = setInterval(async () => {
        try {
            const response = await fetch(`/scan_status/${currentScanId}`);
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
                const completionDiv = document.createElement('div');
                completionDiv.className = 'scan-complete';
                completionDiv.innerHTML = `<i class="fas fa-check-circle"></i> Scan Completed - ${vulnCount} vulnerabilities found`;
                document.getElementById('scan-progress').appendChild(completionDiv);
                
                resetScanUI();
            }
            
        } catch (error) {
            console.error('Error monitoring scan:', error);
            showToast('Error monitoring scan progress', 'error');
            stopScanMonitoring();
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
        await fetch('/stop_scan', {
            method: 'POST'
        });
        
        stopScanMonitoring();
        document.getElementById('scan-status').textContent = 'Scan stopped by user';
        showToast('Scan stopped by user', 'warning');
        resetScanUI();
        
    } catch (error) {
        console.error('Error stopping scan:', error);
        showToast('Error stopping scan', 'error');
    }
}

function resetScanUI() {
    scanInProgress = false;
    document.getElementById('start-scan-btn').style.display = 'block';
    document.getElementById('stop-scan-btn').style.display = 'none';
}

function updateScanProgress(data) {
    // Update progress bar with real percentage
    const progress = Math.min(data.progress || 0, 100);
    document.getElementById('progress-fill').style.width = `${progress}%`;
    document.getElementById('progress-percentage').textContent = `${Math.round(progress)}%`;
    
    // Update all counters with real data
    document.getElementById('tests-completed').textContent = data.completed_tests || 0;
    document.getElementById('total-tests').textContent = data.total_tests || 0;
    document.getElementById('total-payloads').textContent = data.total_payloads || 0;
    document.getElementById('parameters-found').textContent = data.parameters_found || 0;
    document.getElementById('vulns-found').textContent = data.vulnerabilities_found || 0;
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
    
    const typeClass = vuln.type.toLowerCase();
    const confidenceClass = (vuln.confidence || 'medium').toLowerCase();
    
    div.innerHTML = `
        <div class="vuln-header">
            <div class="vuln-badges">
                <span class="vuln-type ${typeClass}">${vuln.type.toUpperCase()} XSS</span>
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
            <div class="vuln-payload" onclick="copyPayload('${escapeHtml(vuln.payload)}')">
                <strong>Payload:</strong> ${escapeHtml(vuln.payload)}
                <small style="opacity: 0.7; margin-left: 10px;">(Click to copy)</small>
            </div>
        </div>
    `;
    
    return div;
}

function copyPayload(payload) {
    navigator.clipboard.writeText(payload).then(() => {
        showToast('Payload copied to clipboard!', 'success');
    }).catch(err => {
        showToast('Failed to copy payload', 'error');
    });
}

function filterResults() {
    const statusFilter = document.getElementById('status-filter').value;
    const confidenceFilter = document.getElementById('confidence-filter').value;
    const payloadSearch = document.getElementById('payload-search').value.toLowerCase();
    
    filteredVulnerabilities = allVulnerabilities.filter(vuln => {
        const matchesStatus = !statusFilter || vuln.status_code == statusFilter;
        const matchesConfidence = !confidenceFilter || vuln.confidence === confidenceFilter;
        const matchesPayload = !payloadSearch || vuln.payload.toLowerCase().includes(payloadSearch);
        
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
    document.getElementById('results').style.display = 'none';
    document.getElementById('status-filter').value = '';
    document.getElementById('confidence-filter').value = '';
    document.getElementById('payload-search').value = '';
    resetScanUI();
    resetCounters();
    showToast('Results cleared', 'success');
}

function escapeHtml(text) {
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
});

// Show welcome message
document.addEventListener('DOMContentLoaded', function() {
    showToast('XSS Scanner ready! Enter a URL to begin scanning.', 'success', 4000);
});
