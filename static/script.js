document.addEventListener('DOMContentLoaded', () => {
    // Theme Toggle Enhancement
    const themeToggle = document.getElementById('themeToggle');
    const backButton = document.getElementById('backButton');
    let currentPage = 'mainPage';
    const icon = themeToggle.querySelector('i');

    // Theme Toggle Logic
    themeToggle.addEventListener('click', () => {
        document.body.classList.toggle('dark-theme');
        if (document.body.classList.contains('dark-theme')) {
            icon.classList.remove('fa-lightbulb');
            icon.classList.add('fa-moon');
        } else {
            icon.classList.add('fa-lightbulb');
            icon.classList.remove('fa-moon');
        }
        localStorage.setItem('theme', document.body.classList.contains('dark-theme') ? 'dark' : 'light');
    });

    // Loading overlay
    const loadingOverlay = document.createElement('div');
    loadingOverlay.className = 'loading-overlay';
    loadingOverlay.innerHTML = `
        <div class="loading-content">
            <div class="loading-spinner"></div>
            <div class="loading-text">Initializing scan...</div>
            <div class="scan-progress">
                <div class="scan-progress-bar"></div>
            </div>
        </div>
    `;
    document.body.appendChild(loadingOverlay);

    // Helper functions for loading animations
    function updateLoadingText(text) {
        document.querySelector('.loading-text').textContent = text;
    }

    function updateScanProgress(percent) {
        document.querySelector('.scan-progress-bar').style.width = `${percent}%`;
    }

    function getScanStatusText(progress) {
        if (progress < 20) return 'Initializing scan...';
        if (progress < 40) return 'Checking target availability...';
        if (progress < 60) return 'Analyzing security parameters...';
        if (progress < 80) return 'Processing results...';
        return 'Finalizing scan...';
    }

    // Modified showTechniquePage function to handle the combined scanning page
    window.showTechniquePage = (technique) => {
        const mainPage = document.getElementById('mainPage');
        const techniquePage = document.getElementById(`${technique}Page`);

        if (!mainPage || !techniquePage) return;

        mainPage.classList.remove('active');
        techniquePage.classList.add('active');
        backButton.style.display = 'flex';
        currentPage = `${technique}Page`;

        // Initialize scan button and tools for this technique page
        initScanButton(techniquePage);
        initializeToolSelection();
    };

    // Back button functionality
    backButton.addEventListener('click', () => {
        const currentPageElement = document.getElementById(currentPage);
        const mainPage = document.getElementById('mainPage');

        if (currentPageElement && mainPage) {
            currentPageElement.classList.remove('active');
            mainPage.classList.add('active');
            backButton.style.display = 'none';
            currentPage = 'mainPage';
        }
    });

    // Function to initialize scan button for a specific page
    function initScanButton(page) {
        const button = page.querySelector('.start-scan-btn');
        if (!button) return;

        // Remove any existing event listeners
        const newButton = button.cloneNode(true);
        button.parentNode.replaceChild(newButton, button);

        // Create visualization container if it doesn't exist
        let visualizationContainer = page.querySelector('.network-visualization');
        if (!visualizationContainer) {
            visualizationContainer = document.createElement('div');
            visualizationContainer.className = 'network-visualization';
            visualizationContainer.id = `network-viz-${page.id}`;
            // Insert before the button's parent element
            const buttonParent = newButton.parentElement;
            if (buttonParent) {
                buttonParent.parentNode.insertBefore(visualizationContainer, buttonParent);
            }
        }

        const networkViz = createNetworkVisualization(visualizationContainer.id);

        newButton.addEventListener('click', async () => {
            const target = page.querySelector('input[type="text"]').value;
            if (!target) {
                alert('Please enter a target');
                return;
            }

            const technique = page.id.replace('Page', '');
            const selectedTools = Array.from(page.querySelectorAll('.tool-item input:checked')).map(input => {
                return input.closest('.tool-item').dataset.tool;
            });

            // Show loading overlay
            loadingOverlay.classList.add('active');
            updateLoadingText('Initializing scan...');
            updateScanProgress(0);

            newButton.disabled = true;
            newButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';

            try {
                networkViz.clear();
                networkViz.start();

                // Start the scan
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        target,
                        technique,
                        tools: selectedTools
                    })
                });

                const data = await response.json();

                if (data.error) {
                    alert(data.error);
                    return;
                }

                // Track scan progress
                const scanId = data.scan_id;
                let completed = false;
                let progress = 0;

                while (!completed && progress < 100) {
                    const progressResponse = await fetch(`/scan/progress/${scanId}`);
                    const progressData = await progressResponse.json();

                    if (progressData.error) {
                        throw new Error(progressData.error);
                    }

                    // Update scan results display
                    showResults(progressData);

                    if (progressData.status === 'completed') {
                        completed = true;
                        progress = 100;
                    } else if (progressData.status === 'failed') {
                        throw new Error('Scan failed');
                    } else {
                        progress = progressData.progress;
                    }

                    updateLoadingText(`${progressData.current_tool || 'Scanning'} - ${Math.round(progress)}%`);
                    updateScanProgress(progress);

                    if (!completed) {
                        await new Promise(resolve => setTimeout(resolve, 1000));
                    }
                }

                // Show results
                showResults(data);

            } catch (error) {
                console.error('Scan error:', error);
                alert('An error occurred during the scan');
            } finally {
                newButton.disabled = false;
                newButton.innerHTML = 'Start Scan';
                loadingOverlay.classList.remove('active');
                networkViz.clear();
            }
        });
    }

    // Initialize scan buttons for all technique pages
    document.querySelectorAll('.technique-page').forEach(page => {
        initScanButton(page);
    });

    // Navigation
    backButton.addEventListener('click', () => {
        const currentPageElement = document.getElementById(currentPage);
        const mainPage = document.getElementById('mainPage');

        currentPageElement.classList.remove('active');
        mainPage.classList.add('active');
        backButton.style.display = 'none';
        currentPage = 'mainPage';
    });

    // Navigation Tabs
    const navTabs = document.querySelectorAll('.nav-tab');
    navTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const targetPage = tab.dataset.page;
            // Update active tab
            navTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            // Show target page
            document.querySelectorAll('.page').forEach(page => {
                page.classList.remove('active');
                if (page.id === targetPage) {
                    page.classList.add('active');
                }
            });
        });
    });


    // Scan Configuration
    function getOptionsForTechnique(technique, page) {
        const options = {};

        switch (technique) {
            case 'passive':
                const dnsChecks = page.querySelectorAll('.checkbox-group input[type="checkbox"]');
                options.dns = Array.from(dnsChecks)
                    .filter(cb => cb.checked)
                    .map(cb => cb.parentElement.textContent.trim());
                break;

            case 'active':
                const portRange = page.querySelector('input[placeholder="Port range"]').value;
                const speed = page.querySelector('select').value;
                options.portRange = portRange;
                options.speed = speed;
                break;

            case 'vulnerability':
                const vulnTypes = page.querySelectorAll('.checkbox-group input[type="checkbox"]');
                options.types = Array.from(vulnTypes)
                    .filter(cb => cb.checked)
                    .map(cb => cb.parentElement.textContent.trim());
                break;
        }

        return options;
    }

    function showResults(data) {
        const resultsContainer = document.createElement('div');
        resultsContainer.className = 'scan-results';

        // Show scan details
        const detailsSection = document.createElement('div');
        detailsSection.className = 'scan-details';
        detailsSection.innerHTML = `
            <h3>Scan Details</h3>
            <div class="details-grid">
                <div class="detail-item">
                    <span class="detail-label">Target:</span>
                    <span class="detail-value">${data.target || 'N/A'}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Status:</span>
                    <span class="detail-value">${data.status || 'N/A'}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Tools Used:</span>
                    <span class="detail-value">${data.tools ? data.tools.join(', ') : 'N/A'}</span>
                </div>
                ${data.current_tool ? `
                <div class="detail-item">
                    <span class="detail-label">Current Tool:</span>
                    <span class="detail-value">${data.current_tool}</span>
                </div>
                ` : ''}
            </div>
        `;
        resultsContainer.appendChild(detailsSection);

        // Show DNS Records if available
        if (data.results && data.results['dns-lookup']) {
            const dnsResults = data.results['dns-lookup'];
            if (dnsResults.records) {
                const dnsSection = document.createElement('div');
                dnsSection.className = 'dns-results-section';
                let dnsHtml = '<h3>DNS Records</h3><div class="dns-records">';

                for (const [recordType, records] of Object.entries(dnsResults.records)) {
                    if (records && records.length > 0) {
                        dnsHtml += `
                            <div class="record-type">
                                <h4>${recordType} Records</h4>
                                <ul class="record-list">
                                    ${records.map(record => `<li>${record}</li>`).join('')}
                                </ul>
                            </div>
                        `;
                    }
                }
                dnsHtml += '</div>';
                dnsSection.innerHTML = dnsHtml;
                resultsContainer.appendChild(dnsSection);
            }

            // Show vulnerabilities if available
            if (dnsResults.vulnerabilities && dnsResults.vulnerabilities.length > 0) {
                const vulnSection = document.createElement('div');
                vulnSection.className = 'vulnerabilities-section';
                vulnSection.innerHTML = `
                    <h3>Security Findings</h3>
                    <div class="vuln-list">
                        ${dnsResults.vulnerabilities.map(vuln => `
                            <div class="vuln-item ${vuln.severity}">
                                <div class="vuln-header">
                                    <span class="vuln-severity">${vuln.severity}</span>
                                    <span class="vuln-name">${vuln.type}</span>
                                </div>
                                <div class="vuln-description">${vuln.description}</div>
                            </div>
                        `).join('')}
                    </div>
                `;
                resultsContainer.appendChild(vulnSection);
            }
        }

        // Add to page under command preview
        const techniquePage = document.querySelector('.technique-page.active');
        if (techniquePage) {
            const commandPreview = techniquePage.querySelector('.editor-container');
            if (commandPreview) {
                // Clear any existing results only if we have new complete results
                // or if status has changed to completed
                const existingResults = commandPreview.querySelector('.scan-results');
                if (existingResults && (data.status === 'completed' || (data.results && Object.keys(data.results).length > 0))) {
                    existingResults.remove();
                }
                // Append new results
                commandPreview.appendChild(resultsContainer);
                // Scroll to results
                resultsContainer.scrollIntoView({ behavior: 'smooth' });
            }
        }
    }

    // Category selection
    window.selectCategory = (category) => {
        selectedCategory = category;
        document.querySelectorAll('.category-card').forEach(card => {
            card.classList.remove('selected');
            if (card.dataset.type === category) {
                card.classList.add('selected');
            }
        });

        scanConfig.style.display = 'block';
        scanConfig.scrollIntoView({ behavior: 'smooth' });
    };

    // Progress update
    function updateProgress(percent, status = '') {
        progress.style.width = `${percent}%`;
        if (status) {
            document.querySelector('.scan-status').textContent = status;
        }
    }

    // Error handling
    function showError(message) {
        resultText.innerHTML = `<div class="error">${message}</div>`;
        results.style.display = 'block';
    }


    // Save scan to history
    function saveScanToHistory(scanData) {
        const history = JSON.parse(localStorage.getItem('scanHistory') || '[]');
        history.unshift({
            id: Date.now(),
            timestamp: new Date().toISOString(),
            target: scanData.target,
            category: selectedCategory,
            results: scanData.report
        });
        localStorage.setItem('scanHistory', JSON.stringify(history.slice(0, 10))); // Keep last 10 scans
        updateHistoryList();
    }

    // Update history list
    function updateHistoryList() {
        const history = JSON.parse(localStorage.getItem('scanHistory') || '[]');
        historyList.innerHTML = history.map(scan => `
            <div class="history-item" onclick="showHistoricalScan(${scan.id})">
                <div class="history-header">
                    <strong>${scan.target}</strong>
                    <span>${new Date(scan.timestamp).toLocaleString()}</span>
                </div>
                <div class="history-category">${scan.category}</div>
            </div>
        `).join('');

        if (history.length > 0) {
            scanHistory.style.display = 'block';
        }
    }


    // Export results
    window.exportResults = (format) => {
        if (!currentScan) return;

        if (format === 'pdf') {
            // Implementation for PDF export
            const content = resultText.textContent;
            // Use a PDF library or service to generate PDF
            console.log('PDF export not implemented yet');
        } else if (format === 'json') {
            const blob = new Blob([JSON.stringify(currentScan, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `scan_results_${new Date().toISOString()}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
    };

    // Show historical scan
    window.showHistoricalScan = (scanId) => {
        const history = JSON.parse(localStorage.getItem('scanHistory') || '[]');
        const scan = history.find(s => s.id === scanId);
        if (scan) {
            results.style.display = 'block';
            resultText.textContent = scan.results;
            results.scrollIntoView({ behavior: 'smooth' });
        }
    };

    // Tickets System
    class TicketManager {
        constructor() {
            this.tickets = [];
            this.filterSelect = document.getElementById('ticketFilter');
            this.ticketsList = document.querySelector('.tickets-list');

            // Event Listeners
            this.filterSelect.addEventListener('change', () => this.filterTickets());
            document.querySelector('.btn-refresh').addEventListener('click', () => this.loadTickets());
        }

        async loadTickets() {
            try {
                const response = await fetch('/api/tickets');
                const data = await response.json();
                this.tickets = data.tickets;
                this.filterTickets();
            } catch (error) {
                console.error('Error loading tickets:', error);
            }
        }

        filterTickets() {
            const filter = this.filterSelect.value;
            const filteredTickets = filter === 'all'
                ? this.tickets
                : this.tickets.filter(ticket => ticket.status === filter);
            this.renderTickets(filteredTickets);
        }

        renderTickets(tickets) {
            this.ticketsList.innerHTML = tickets.map(ticket => `
                <div class="ticket-card">
                    <div class="ticket-header">
                        <h3 class="ticket-title">${ticket.title}</h3>
                        <span class="ticket-status status-${ticket.status}">${ticket.status}</span>
                    </div>
                    <div class="ticket-meta">
                        <span>Reported by: ${ticket.reporter}</span>
                        <span>Found: ${new Date(ticket.dateFound).toLocaleDateString()}</span>
                    </div>
                    <div class="ticket-description">${ticket.description}</div>
                    ${ticket.cve ? `<div class="ticket-cve">${ticket.cve}</div>` : ''}
                    <div class="ticket-comments">
                        ${ticket.comments.map(comment => `
                            <div class="comment">
                                <div class="comment-avatar">${comment.author[0]}</div>
                                <div class="comment-content">
                                    <div class="comment-header">
                                        <span class="comment-author">${comment.author}</span>
                                        <span class="comment-date">${new Date(comment.date).toLocaleDateString()}</span>
                                    </div>
                                    <div class="comment-text">${comment.text}</div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `).join('');
        }
    }

    // Initialize Ticket Manager if on tickets page
    if (document.getElementById('ticketsPage')) {
        const ticketManager = new TicketManager();
        ticketManager.loadTickets();
    }

    // Alert Configuration
    const testEmailBtn = document.getElementById('testEmailBtn');
    const saveAlertConfig = document.getElementById('saveAlertConfig');
    const enableEmailAlerts = document.getElementById('enableEmailAlerts');
    const alertEmail = document.getElementById('alertEmail');

    if (testEmailBtn) {
        testEmailBtn.addEventListener('click', async () => {
            if (!alertEmail.value) {
                alert('Please enter an email address first');
                return;
            }

            testEmailBtn.disabled = true;
            testEmailBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Testing...';

            try {
                const response = await fetch('/api/test-email', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        email: alertEmail.value
                    })
                });

                const data = await response.json();
                if (data.success) {
                    alert('Test email sent successfully!');
                } else {
                    alert('Failed to send test email: ' + data.error);
                }
            } catch (error) {
                alert('Failed to test email configuration');
            } finally {
                testEmailBtn.disabled = false;
                testEmailBtn.innerHTML = 'Test Email Configuration';
            }
        });
    }

    if (saveAlertConfig) {
        saveAlertConfig.addEventListener('click', async () => {
            const config = {
                email: {
                    enabled: enableEmailAlerts.checked,
                    address: alertEmail.value,
                    thresholds: {
                        critical: document.querySelector('input[type="checkbox"][value="critical"]').checked,
                        high: document.querySelector('input[type="checkbox"][value="high"]').checked,
                        medium: document.querySelector('input[type="checkbox"][value="medium"]').checked
                    }
                },
                schedule: {
                    enabled: document.getElementById('enableScheduledScans').checked,
                    frequency: document.getElementById('scanFrequency').value,
                    time: document.getElementById('scanTime').value
                }
            };

            try {
                const response = await fetch('/api/alert-config', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(config)
                });

                const data = await response.json();
                if (data.success) {
                    alert('Alert configuration saved successfully!');
                } else {
                    alert('Failed to save configuration: ' + data.error);
                }
            } catch (error) {
                alert('Failed to save alert configuration');
            }
        });
    }

    // Initialize
    updateHistoryList();

    // Dashboard Charts Initialization
    if (document.getElementById('dashboardPage')) {
        initializeDashboardCharts();
    }

    // Tool Selection and Command Preview Logic
    function initializeToolSelection() {
        const toolItems = document.querySelectorAll('.tool-item');

        toolItems.forEach(tool => {
            const toggleInput = tool.querySelector('.toggle-switch input');
            if (!toggleInput) return;

            toggleInput.addEventListener('change', function() {
                // Get the technique page that contains this tool
                const techniquePage = this.closest('.technique-page');
                if (!techniquePage) return;

                // Update the tool item's selected state
                const toolItem = this.closest('.tool-item');
                if (this.checked) {
                    toolItem.classList.add('selected');
                } else {
                    toolItem.classList.remove('selected');
                }

                updateSelectedTools(techniquePage);
                updateCommandPreview(techniquePage);
            });
        });

        // Initialize edit command buttons
        document.querySelectorAll('.btn-edit').forEach(btn => {
            btn.addEventListener('click', function() {
                const commandText = this.closest('.editor-container').querySelector('.command-text');
                if (!commandText) return;

                if (commandText.contentEditable === 'true') {
                    // Save mode
                    commandText.contentEditable = 'false';
                    this.innerHTML = '<i class="fas fa-edit"></i> Edit Command';
                } else {
                    // Edit mode
                    commandText.contentEditable = 'true';
                    commandText.focus();
                    this.innerHTML = '<i class="fas fa-save"></i> Save Command';
                }
            });
        });
    }

    // Update the command preview generation for combined scanning tools
    function updateCommandPreview(techniquePage) {
        const commandPreview = techniquePage.querySelector('.command-text');
        const selectedItems = techniquePage.querySelectorAll('.tool-item input:checked');
        const targetInput = techniquePage.querySelector('input[type="text"]');
        const target = targetInput && targetInput.value ? targetInput.value : '[target]';
        const portRange = document.getElementById('portRange')?.value || '1-1000';
        const scanSpeed = document.getElementById('scanSpeed')?.value || 'normal';

        if (!commandPreview) return;

        if (selectedItems.length === 0) {
            commandPreview.textContent = 'No tools selected';
            return;
        }

        const commands = Array.from(selectedItems).map(input => {
            const toolItem = input.closest('.tool-item');
            switch (toolItem.dataset.tool) {
                // Passive scanning tools
                case 'dns-lookup':
                    return `dig ${target} ANY`;
                case 'whois':
                    return `whois ${target}`;
                case 'ssl-check':
                    return `openssl s_client -connect ${target}:443 -status`;
                case 'subdomain-enum':
                    return `subfinder -d ${target}`;
                case 'dns-zone':
                    return `dig axfr ${target}`;
                case 'reverse-ip':
                    return `host ${target}`;
                case 'email-records':
                    return `dig ${target} MX TXT\ndig txt _dmarc.${target}\ndig txt ${target} +short`;
                case 'security-headers':
                    return `curl -I -L ${target}`;
                case 'robots-txt':
                    return `curl -L ${target}/robots.txt`;
                case 'cert-transparency':
                    return `curl -sL "https://crt.sh/?q=${target}&output=json"`;
                case 'dns-sec':
                    return `dig ${target} DNSKEY +dnssec`;

                // Active scanning tools
                case 'port-scan':
                    return `Port scan with options:
- Version detection: enabled
- Default scripts: enabled
- Timing: ${scanSpeed === 'slow' ? 'T2' : scanSpeed === 'fast' ? 'T4' : 'T3'}
- Port range: ${portRange}
- Target: ${target}`;
                case 'xss-scan':
                    return `xsser --url ${target} --auto`;
                case 'sqli-scan':
                    return `sqlmap -u ${target} --batch --random-agent`;
                case 'dir-enum':
                    return `gobuster dir -u ${target} -w /usr/share/wordlists/dirb/common.txt`;
                case 'cms-scan':
                    return `wpscan --url ${target} --enumerate p,t,u`;
                case 'waf-detect':
                    return `wafw00f ${target}`;
                case 'banner-grab':
                    return `nc -v ${target} [port]`;
                case 'traceroute':
                    return `traceroute ${target}`;
                case 'http-headers':
                    return `curl -I ${target}`;
                case 'tech-detect':
                    return `whatweb ${target}`;
                default:
                    return `# ${toolItem.querySelector('.tool-name').textContent}`;
            }
        });

        commandPreview.textContent = commands.join('\n');
    }

    function updateSelectedTools(techniquePage) {
        const selectedTools = techniquePage.querySelector('.selected-tools');
        const selectedItems = techniquePage.querySelectorAll('.tool-item input:checked');

        if (!selectedTools) return;

        if (selectedItems.length === 0) {
            selectedTools.innerHTML = '<div class="no-tools">No tools selected</div>';
            return;
        }

        const toolTags = Array.from(selectedItems).map(input => {
            const toolItem = input.closest('.tool-item');
            const icon = toolItem.querySelector('.tool-icon i');
            const name = toolItem.querySelector('.tool-name');
            return `
                <div class="selected-tool-tag">
                    <i class="${icon ? icon.className : 'fas fa-tools'}"></i>
                    ${name ? name.textContent : 'Tool'}
                    <i class="fas fa-times" onclick="removeSelectedTool(this, '${toolItem.dataset.tool}')"></i>
                </div>
            `;
        });

        selectedTools.innerHTML = toolTags.join('');
    }

    // Function to remove a selected tool
    window.removeSelectedTool = function(element, toolId) {
        const techniquePage = element.closest('.technique-page');
        if (!techniquePage) return;

        const toolItem = techniquePage.querySelector(`.tool-item[data-tool="${toolId}"]`);
        if (toolItem) {
            const toggleInput = toolItem.querySelector('.toggle-switch input');
            if (toggleInput) {
                toggleInput.checked = false;
                updateSelectedTools(techniquePage);
                updateCommandPreview(techniquePage);
            }
        }
    };

    // Initialize tool selection functionality
    initializeToolSelection();

    // Add input event listeners for target updates
    document.querySelectorAll('.technique-page input[type="text"]').forEach(input => {
        input.addEventListener('input', function() {
            const techniquePage = this.closest('.technique-page');
            if (techniquePage) {
                updateCommandPreview(techniquePage);
            }
        });
    });

    // Dashboard Charts Initialization
    if (document.getElementById('dashboardPage')) {
        initializeDashboardCharts();
    }
});

function initializeDashboardCharts() {
    // Active Scans Chart
    const activeScanCtx = document.getElementById('activeScanChart').getContext('2d');
    const activeScanChart = new Chart(activeScanCtx, {
        type: 'doughnut',
        data: {
            labels: ['In Progress', 'Completed', 'Failed'],
            datasets: [{
                data: [4, 8, 1],
                backgroundColor: [
                    'rgba(54, 162, 235, 0.8)',
                    'rgba(75, 192, 192, 0.8)',
                    'rgba(255, 99, 132, 0.8)'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });

    // Risk Score Chart
    const riskScoreCtx = document.getElementById('riskScoreChart').getContext('2d');
    const riskScoreChart = new Chart(riskScoreCtx, {
        type: 'gauge',
        data: {
            datasets: [{
                value: 75,
                minValue: 0,
                maxValue: 100,
                backgroundColor: ['#ff6384', '#36a2eb', '#4bc0c0'],
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
        }
    });

    // Vulnerability Trends Chart
    const vulnTrendCtx = document.getElementById('vulnTrendChart').getContext('2d');
    const vulnTrendChart = new Chart(vulnTrendCtx, {
        type: 'line',
        data: {
            labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
            datasets: [{
                label: 'Critical',
                data: [12, 19, 3, 5, 2, 3],
                borderColor: 'rgba(255, 99, 132, 1)',
                tension: 0.4
            }, {
                label: 'High',
                data: [7, 11, 5, 8, 3, 7],
                borderColor: 'rgba(255, 159, 64, 1)',
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });

    // Update charts periodically
    setInterval(() => {
        updateDashboardData();
    }, 5000);
}

function updateDashboardData() {
    // Fetch new data from the server and update charts
    fetch('/api/dashboard/stats')
        .then(response => response.json())
        .then(data => {
            // Update charts with new data
            // This will be implemented when we add the backend API
        })
        .catch(error => console.error('Error updating dashboard:', error));
}

// Network Visualization
function createNetworkVisualization(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return; //Handle case where container might not exist yet.
    const visualization = document.createElement('div');
    visualization.className = 'network-visualization';
    container.appendChild(visualization);

    const nodes = [];
    const connections = [];
    const threats = [];

    function createNode(x, y) {
        const node = document.createElement('div');
        node.className = 'network-node';
        node.style.left = `${x}%`;
        node.style.top = `${y}%`;
        visualization.appendChild(node);
        nodes.push(node);
        return node;
    }

    function createConnection(fromNode, toNode) {
        const connection = document.createElement('div');
        connection.className = 'network-connection';

        const fromRect = fromNode.getBoundingClientRect();
        const toRect = toNode.getBoundingClientRect();
        const containerRect = visualization.getBoundingClientRect();

        const dx = toRect.left - fromRect.left;
        const dy = toRect.top - fromRect.top;
        const angle = Math.atan2(dy, dx) * 180 / Math.PI;
        const length = Math.sqrt(dx * dx + dy * dy);

        connection.style.width = `${length}px`;
        connection.style.left = `${fromRect.left - containerRect.left + 10}px`;
        connection.style.top = `${fromRect.top - containerRect.top + 10}px`;
        connection.style.transform = `rotate(${angle}deg)`;

        visualization.appendChild(connection);
        connections.push(connection);
        return connection;
    }

    function createThreat(x, y) {
        const threat = document.createElement('div');
        threat.className = 'threat-indicator';
        threat.style.left = `${x}%`;
        threat.style.top = `${y}%`;
        visualization.appendChild(threat);
        threats.push(threat);
        return threat;
    }

    function createScanWave(x, y) {
        const wave = document.createElement('div');
        wave.className = 'scan-wave';
        wave.style.left = `${x}%`;
        wave.style.top = `${y}%`;
        visualization.appendChild(wave);
        setTimeout(() => visualization.removeChild(wave), 2000);
    }

    function simulateNetworkScan() {
        // Create initial nodes
        const sourceNode = createNode(10, 50);

        // Simulate scanning process
        let scannedNodes = 0;
        const maxNodes = 8;

        const scanInterval = setInterval(() => {
            if (scannedNodes >= maxNodes) {
                clearInterval(scanInterval);
                return;
            }

            // Create a new node
            const x = 20 + Math.random() * 60;
            const y = 20 + Math.random() * 60;
            const newNode = createNode(x, y);

            // Create connection from source
            createConnection(sourceNode, newNode);

            // Randomly create threats
            if (Math.random() > 0.7) {
                const threatX = x + (Math.random() * 10 - 5);
                const threatY = y + (Math.random() * 10 - 5);
                createThreat(threatX, threatY);
            }

            // Create scan wave effect
            createScanWave(x, y);

            scannedNodes++;
        }, 1000);
    }

    return {
        start: simulateNetworkScan,
        clear: () => {
            nodes.forEach(node => node.remove());
            connections.forEach(conn => conn.remove());
            threats.forEach(threat => threat.remove());
            nodes.length = connections.length = threats.length = 0;
        }
    };
}