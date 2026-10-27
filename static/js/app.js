/**
 * PCAP Analyzer Pro V2 - Frontend Application
 * Modern UI with Dark/Light Mode, AI Chatbot, Toast Notifications
 */

class VirtualScroll {
    constructor(container, spacer, tbody, rowHeight = 38) {
        this.container = container;
        this.spacer = spacer;
        this.tbody = tbody;
        this.rowHeight = rowHeight;
        this.data = [];
        this.filteredData = [];
        this.renderFn = null;
        this.visibleCount = Math.ceil(container.offsetHeight / rowHeight) + 5;
        this.lastScrollTop = 0;
        this.scrollRafPending = false;

        // passive: le handler ne bloque jamais le scroll; rAF: un seul rendu par frame
        container.addEventListener('scroll', () => {
            if (this.scrollRafPending) return;
            this.scrollRafPending = true;
            requestAnimationFrame(() => {
                this.scrollRafPending = false;
                this.onScroll();
            });
        }, { passive: true });

        // Recalculer le nombre de lignes visibles quand la fenêtre change de taille
        this.resizeHandler = () => {
            const count = Math.ceil(this.container.offsetHeight / this.rowHeight) + 5;
            this.visibleCount = count;
            this.render();
        };
        window.addEventListener('resize', this.resizeHandler, { passive: true });
    }

    setData(data, renderFn) {
        this.data = data;
        this.filteredData = data;
        this.renderFn = renderFn;
        this.render();
    }

    setFilteredData(filteredData) {
        this.filteredData = filteredData;
        this.container.scrollTop = 0;
        this.render();
    }

    onScroll() {
        const scrollTop = this.container.scrollTop;
        if (Math.abs(scrollTop - this.lastScrollTop) < this.rowHeight / 2) return;
        this.lastScrollTop = scrollTop;
        this.render();
    }

    render() {
        const total = this.filteredData.length;
        const scrollTop = this.container.scrollTop;
        const startIndex = Math.max(0, Math.floor(scrollTop / this.rowHeight) - 2);
        const endIndex = Math.min(total, startIndex + this.visibleCount + 4);

        const table = this.tbody.closest('table');
        const headerHeight = table?.querySelector('thead')?.getBoundingClientRect().height || 0;
        const columnWidths = Array.from(table?.querySelectorAll('thead th') || []).map(th => th.getBoundingClientRect().width);
        this.spacer.style.height = `${total * this.rowHeight + headerHeight}px`;

        // Construire hors DOM puis remplacer en une opération
        const fragment = document.createDocumentFragment();
        for (let i = startIndex; i < endIndex; i++) {
            const row = this.renderFn(this.filteredData[i], i);
            row.style.position = 'absolute';
            row.style.top = `${i * this.rowHeight + headerHeight}px`;
            row.style.width = '100%';
            if (columnWidths.length) {
                row.style.display = 'grid';
                row.style.gridTemplateColumns = columnWidths.map(width => `${width}px`).join(' ');
            }
            fragment.appendChild(row);
        }
        this.tbody.replaceChildren(fragment);
    }
}

class PCAPAnalyzer {
    constructor() {
        this.currentTaskId = null;
        this.pollInterval = null;
        this.echartsInstances = {};
        this.currentResults = null;
        this.currentPacketPage = 1;
        this.packetsPerPage = 100;
        this.navigationStack = ['overview'];
        this.timeline = null;
        this.timelinePlayback = null;
        this.chatHistory = [];
        this.chatbotOpen = false;
        this.guidedProblems = [];
        this.guidedQuestions = [];
        this.autoQuestionnaireEnabled = false;
        this.autoQuestionnaireInProgress = false;
        this.autoQuestionnaireDoneForTask = '';
        this.autoQuestionnaireTimer = null;
        this.defaultChatSuggestions = [
            {
                label: 'Anomalies principales',
                prompt: 'Quelles sont les principales anomalies détectées ?'
            },
            {
                label: 'IPs suspectes',
                prompt: 'Y a-t-il des IPs suspectes ?'
            },
            {
                label: 'Résumé DNS',
                prompt: 'Résumé du trafic DNS'
            },
            {
                label: 'Performance',
                prompt: 'Problèmes de performance ?'
            }
        ];
        this.premiumEntrancePlayed = false;
        this.macVendorCache = {};
        this.macVendorInflight = {};
        this.streamsData = [];
        this.allPackets = [];
        this.filteredPackets = [];
        this.packetIndex = { byProto: {}, byIp: {} };
        this.streamFilterTimer = null;
        this.streamOffset = 0;
        this.streamLimit = 100;
        this.streamTotal = 0;
        this.multiPcapFiles = [];
        this.multiPcapTaskId = null;
        this.multiPcapResults = null;
        this.multiRenderedDetailSessionId = null;
        this.multiSelectedSessionId = null;
        this.multiCauseFilter = '';
        this.multiSegmentFilter = '';
        this.multiRiskMinFilter = 0;
        this.multiFilterTimer = null;
        this.multiHopTimeline = null;
        this.multiHopFocusedIndex = null;
        this.multiChainNodeByHop = {};
        this.multiChainEdgeByHop = {};
        this.multiHopSyncLock = false;
        this.multiAutoDegradationEnabled = true;
        this.multiChainPrimaryEdgeIndex = null;
        this.multiChainPrimaryToHopIndex = null;
        this.multiGlobalChainNodeByCapture = {};
        this.multiGlobalChainEdgeByPair = {};
        this.globalDrilldownSnapshot = null;
        this.globalDrilldownFilter = { query: '', protocol: '', riskMin: 0 };
        this.currentTabId = 'overview';
        this.menuHealthState = {};
        this.menuHealthOrder = [];
        this.renderSignatures = {
            dns: '',
            http: '',
        };
        this.streamsLoadedKey = '';
        this.packetsLoadedTaskId = '';
        this.lastTabSwitchTs = 0;
        this.visualObserver = null;
        this.visualRefreshScheduled = false;
        this.focusInvestigationEnabled = false;
        this.tabTransitionLock = false;
        this.pendingTabId = null;
        this.pendingSpotlightRoots = new Set();
        this.menuHealthRenderScheduled = false;
        this.chartResizeRaf = null;
        this.tabsWheelBound = false;
        this.networkVisualState = {
            mode: 'idle',
            riskLevel: 'NONE',
            anomalyCount: 0,
            intensity: 0.18,
            burst: 0.12,
            updatedAt: Date.now(),
        };

        this.init();
    }

    init() {
        this.initTheme();
        this.setupEventListeners();
        this.renderChatSuggestions();
        this.loadHistory();
        this.setupChartDefaults();
        this.setupTabs();
        this.initVisualDynamics();
        this.initFocusMode();
        window.addEventListener('resize', () => {
            this.requestChartsResize();
            this.updateActiveTabPill();
        });
    }

    requestChartsResize(frameCount = 1) {
        const frames = Math.max(1, Number(frameCount || 1));
        if (this.chartResizeRaf) {
            cancelAnimationFrame(this.chartResizeRaf);
            this.chartResizeRaf = null;
        }

        const run = (remaining) => {
            this.chartResizeRaf = requestAnimationFrame(() => {
                if (remaining > 1) {
                    run(remaining - 1);
                    return;
                }
                this.chartResizeRaf = null;
                Object.values(this.echartsInstances || {}).forEach((chart) => {
                    if (chart && !chart.isDisposed()) chart.resize();
                });
            });
        };

        run(frames);
    }

    scheduleMenuHealthRender() {
        if (this.menuHealthRenderScheduled) return;
        this.menuHealthRenderScheduled = true;
        requestAnimationFrame(() => {
            this.menuHealthRenderScheduled = false;
            this.renderMenuHealthCenter();
        });
    }

    initVisualDynamics() {
        this.updateActiveTabPill();
        this.bindInteractiveSpotlights(document);

        if (this.visualObserver) return;
        this.visualObserver = new MutationObserver((mutations) => {
            const roots = [];
            mutations.forEach((mutation) => {
                mutation.addedNodes?.forEach((node) => {
                    // Ignorer les lignes de tableaux (virtual scroll, listes):
                    // elles ne contiennent jamais de cartes spotlight et
                    // déclencheraient un querySelectorAll par ligne
                    if (node?.nodeType === Node.ELEMENT_NODE
                        && node.tagName !== 'TR' && node.tagName !== 'TD'
                        && node.tagName !== 'OPTION' && node.tagName !== 'LI') {
                        roots.push(node);
                    }
                });
            });
            if (roots.length) this.scheduleVisualRefresh(roots);
        });
        this.visualObserver.observe(document.body, { childList: true, subtree: true });
    }

    scheduleVisualRefresh(roots = []) {
        if (Array.isArray(roots) && roots.length) {
            roots.forEach((root) => this.pendingSpotlightRoots.add(root));
        }
        if (this.visualRefreshScheduled) return;
        this.visualRefreshScheduled = true;
        requestAnimationFrame(() => {
            this.visualRefreshScheduled = false;
            const pendingRoots = Array.from(this.pendingSpotlightRoots || []);
            this.pendingSpotlightRoots.clear();

            if (!pendingRoots.length) {
                this.bindInteractiveSpotlights(document);
                return;
            }
            pendingRoots.forEach((root) => this.bindInteractiveSpotlights(root));
        });
    }

    bindInteractiveSpotlights(root = document) {
        if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
        if (!window.matchMedia('(pointer: fine)').matches) return;

        const selector = '.card, .tabs-container, .adv-metric-card, .stream-kpi-card, .multi-session-summary-grid > div';
        const candidates = [];
        if (root?.nodeType === Node.ELEMENT_NODE && root.matches?.(selector)) {
            candidates.push(root);
        }
        if (root?.querySelectorAll) {
            root.querySelectorAll(selector).forEach((el) => candidates.push(el));
        } else if (root === document) {
            document.querySelectorAll(selector).forEach((el) => candidates.push(el));
        }

        candidates.forEach((el) => {
            if (el.dataset.spotlightBound === '1') return;
            el.dataset.spotlightBound = '1';
            el.classList.add('interactive-spotlight');

            let moveRaf = 0;
            let nextX = 50;
            let nextY = 50;
            const flushPointer = () => {
                moveRaf = 0;
                el.style.setProperty('--spot-x', `${nextX.toFixed(2)}%`);
                el.style.setProperty('--spot-y', `${nextY.toFixed(2)}%`);
            };

            el.addEventListener('pointermove', (event) => {
                const rect = el.getBoundingClientRect();
                if (!rect.width || !rect.height) return;
                const x = ((event.clientX - rect.left) / rect.width) * 100;
                const y = ((event.clientY - rect.top) / rect.height) * 100;
                nextX = Math.max(0, Math.min(100, x));
                nextY = Math.max(0, Math.min(100, y));
                if (moveRaf) return;
                moveRaf = requestAnimationFrame(flushPointer);
            });

            el.addEventListener('pointerleave', () => {
                nextX = 50;
                nextY = 50;
                if (moveRaf) cancelAnimationFrame(moveRaf);
                moveRaf = requestAnimationFrame(flushPointer);
            });
        });
    }

    updateActiveTabPill() {
        const tabs = document.querySelector('.tabs');
        const pill = document.getElementById('tabsActivePill');
        if (!tabs || !pill) return;

        const active = tabs.querySelector('.tab.active');
        if (!active) {
            pill.style.opacity = '0';
            return;
        }

        pill.style.width = `${active.offsetWidth}px`;
        pill.style.height = `${active.offsetHeight}px`;
        pill.style.transform = `translate(${active.offsetLeft}px, ${active.offsetTop}px)`;
        pill.style.opacity = '1';
    }

    // ==================== THEME MANAGEMENT ====================

    initTheme() {
        const savedTheme = localStorage.getItem('pcap-theme') || 'light';
        document.documentElement.setAttribute('data-theme', savedTheme);
        this.updateThemeIcons(savedTheme);
        const savedUiStyle = localStorage.getItem('pcap-ui-style') || 'default';
        this.applyUiStyle(savedUiStyle, false);

        const themeToggle = document.getElementById('themeToggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', () => this.toggleTheme());
        }

        const liquidToggle = document.getElementById('liquidToggle');
        if (liquidToggle) {
            liquidToggle.addEventListener('click', () => this.toggleUiStyle());
        }
    }

    toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('pcap-theme', newTheme);
        this.updateThemeIcons(newTheme);
        this.updateChartsTheme();

        this.showToast('success', 'Thème changé', `Mode ${newTheme === 'dark' ? 'sombre' : 'clair'} activé`);
    }

    updateThemeIcons(theme) {
        const sunIcon = document.getElementById('sunIcon');
        const moonIcon = document.getElementById('moonIcon');

        if (theme === 'dark') {
            sunIcon?.classList.remove('active');
            moonIcon?.classList.add('active');
        } else {
            sunIcon?.classList.add('active');
            moonIcon?.classList.remove('active');
        }
    }

    toggleUiStyle() {
        const currentStyle = document.documentElement.getAttribute('data-ui-style') || 'default';
        const newStyle = currentStyle === 'superneon' ? 'default' : 'superneon';
        this.applyUiStyle(newStyle, true);
        this.updateChartsTheme();
    }

    applyUiStyle(style, showNotification = false) {
        const normalizedStyle = (style === 'superneon' || style === 'apple-liquid') ? 'superneon' : 'default';
        document.documentElement.setAttribute('data-ui-style', normalizedStyle);
        localStorage.setItem('pcap-ui-style', normalizedStyle);
        this.updateUiStyleToggle(normalizedStyle);

        if (showNotification) {
            const message = normalizedStyle === 'superneon'
                ? 'Mode Superneon activé'
                : 'Mode standard réactivé';
            this.showToast('success', 'Style mis à jour', message);
        }
    }

    updateUiStyleToggle(style) {
        const liquidToggle = document.getElementById('liquidToggle');
        if (!liquidToggle) return;

        const isNeon = style === 'superneon';
        liquidToggle.classList.toggle('active', isNeon);
        liquidToggle.setAttribute('aria-pressed', String(isNeon));
    }

    initFocusMode() {
        this.focusInvestigationEnabled = localStorage.getItem('pcap-focus-investigation') === '1';
        this.updateFocusModeToggle();
        this.applyFocusInvestigation();
    }

    toggleFocusInvestigation() {
        this.focusInvestigationEnabled = !this.focusInvestigationEnabled;
        localStorage.setItem('pcap-focus-investigation', this.focusInvestigationEnabled ? '1' : '0');
        this.updateFocusModeToggle();
        this.applyFocusInvestigation();
        this.showToast(
            'info',
            'Focus Investigation',
            this.focusInvestigationEnabled
                ? 'Mode Focus activé: les cartes non pertinentes sont atténuées.'
                : 'Mode Focus désactivé: vue complète restaurée.'
        );
    }

    updateFocusModeToggle() {
        const toggle = document.getElementById('focusModeToggle');
        if (!toggle) return;

        const enabled = this.focusInvestigationEnabled;
        toggle.classList.toggle('active', enabled);
        toggle.setAttribute('aria-pressed', String(enabled));
        const label = toggle.querySelector('.focus-mode-label');
        if (label) label.textContent = enabled ? 'Focus ON' : 'Focus';
        document.body.classList.toggle('focus-investigation', enabled);
    }

    getActiveTabId() {
        return document.querySelector('.tab.active')?.dataset?.tab || 'overview';
    }

    getFocusGroupsForTab(tabId) {
        const key = String(tabId || '').toLowerCase();
        const mapping = {
            overview: new Set(['all']),
            dns: new Set(['dns', 'risk', 'packets']),
            http: new Set(['http', 'tls', 'dns', 'risk', 'packets']),
            timeline: new Set(['packets', 'sessions', 'risk']),
            streams: new Set(['sessions', 'risk', 'packets']),
            'multi-pcap': new Set(['sessions', 'risk', 'packets']),
            packets: new Set(['packets', 'risk']),
            'team-ia': new Set(['sessions', 'risk', 'packets']),
            'tls-audit': new Set(['tls', 'sessions', 'risk']),
            'threat-intel': new Set(['dns', 'http', 'risk']),
            'flow-behavior': new Set(['sessions', 'risk', 'packets']),
            'lateral-movement': new Set(['sessions', 'risk', 'packets']),
            qos: new Set(['sessions', 'risk', 'packets']),
            'tcp-health': new Set(['sessions', 'risk', 'packets']),
            playbook: new Set(['risk', 'sessions']),
        };
        return mapping[key] || new Set(['risk', 'packets']);
    }

    resolveSummaryCardFocusGroup(card) {
        if (!card) return 'other';
        if (card.dataset.focusGroup) return card.dataset.focusGroup;

        let group = 'other';
        if (card.querySelector('#riskLevel')) group = 'risk';
        else if (card.querySelector('#dnsQueries') || card.querySelector('#uniqueDomains')) group = 'dns';
        else if (card.querySelector('#httpRequests')) group = 'http';
        else if (card.querySelector('#tlsSessions')) group = 'tls';
        else if (card.querySelector('#tcpSessions')) group = 'sessions';
        else if (card.querySelector('#totalPackets') || card.querySelector('#totalBytes')) group = 'packets';
        card.dataset.focusGroup = group;
        return group;
    }

    isSummaryCardRelevantForTab(card, tabId) {
        const groups = this.getFocusGroupsForTab(tabId);
        if (groups.has('all')) return true;
        const group = this.resolveSummaryCardFocusGroup(card);
        return groups.has(group) || groups.has('risk') && group === 'risk';
    }

    applyFocusInvestigation() {
        const section = document.getElementById('resultsSection');
        if (!section) return;

        const cards = Array.from(section.querySelectorAll('.card'));
        cards.forEach((card) => {
            card.classList.remove('focus-dim', 'focus-keep', 'focus-critical');
        });

        section.classList.toggle('focus-investigation-active', this.focusInvestigationEnabled);
        if (!this.focusInvestigationEnabled) return;

        const activeTabId = this.getActiveTabId();
        const keep = new Set();

        const activeContent = document.getElementById(`tab-${activeTabId}`);
        if (activeContent) {
            activeContent.querySelectorAll('.card').forEach((card) => keep.add(card));
        }

        section.querySelectorAll('.summary-card').forEach((card) => {
            if (this.isSummaryCardRelevantForTab(card, activeTabId)) {
                keep.add(card);
            }
        });

        const hero = section.querySelector('.premium-hero');
        if (hero) keep.add(hero);

        cards.forEach((card) => {
            if (keep.has(card)) {
                card.classList.add('focus-keep');
            } else {
                card.classList.add('focus-dim');
            }
        });

        const riskCard = document.getElementById('riskCard');
        const riskLevel = String(riskCard?.getAttribute('data-risk') || '').toUpperCase();
        if (riskCard && (riskLevel === 'HIGH' || riskLevel === 'CRITICAL')) {
            riskCard.classList.remove('focus-dim');
            riskCard.classList.add('focus-keep', 'focus-critical');
        }
    }

    getThemeColors() {
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        return {
            primary: '#0ea5a4',
            accent: '#f97316',
            success: '#10b981',
            warning: '#f59e0b',
            danger: '#ef4444',
            text: isDark ? '#f8fafc' : '#0f172a',
            textSecondary: isDark ? '#94a3b8' : '#64748b',
            grid: isDark ? 'rgba(148, 163, 184, 0.08)' : 'rgba(100, 116, 139, 0.12)',
            background: isDark ? '#0f172a' : '#ffffff'
        };
    }

    // ==================== TOAST NOTIFICATIONS ====================

    showToast(type, title, message, duration = 4000) {
        const container = document.getElementById('toastContainer');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;

        const icons = {
            success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
            error: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
            warning: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
            info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
        };

        toast.innerHTML = `
            <div class="toast-icon">${icons[type] || icons.info}</div>
            <div class="toast-content">
                <div class="toast-title">${this.escapeHtml(title)}</div>
                <div class="toast-message">${this.escapeHtml(message)}</div>
            </div>
            <button class="toast-close" onclick="this.parentElement.remove()">✕</button>
        `;

        container.appendChild(toast);

        setTimeout(() => {
            toast.classList.add('removing');
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }

    // ==================== CHATBOT ====================

    toggleChatbot() {
        this.chatbotOpen = !this.chatbotOpen;
        const panel = document.getElementById('chatbotPanel');
        if (panel) {
            panel.classList.toggle('open', this.chatbotOpen);
        }
    }

    async sendChatMessage(message = null) {
        const input = document.getElementById('chatInput');
        const messageText = message || input?.value?.trim();

        if (!messageText) return null;
        if (!this.currentTaskId) {
            this.showToast('warning', 'Pas d\'analyse', 'Veuillez d\'abord analyser un fichier PCAP');
            return { success: false, error: 'Aucune analyse active' };
        }

        // Clear input
        if (input) input.value = '';

        // Add user message
        this.addChatMessage('user', messageText);

        // Show typing indicator
        const typingDiv = this.addChatTyping();

        try {
            const response = await fetch(`/api/analysis/${this.currentTaskId}/chat`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: messageText })
            });

            const data = await response.json();

            // Remove typing indicator
            typingDiv.remove();

            if (data.success) {
                this.addChatMessage('ai', data.response, data.structured || null);
                return data;
            } else {
                this.addChatMessage(
                    'ai',
                    data.error && data.error !== '0' ? `⚠️ ${data.error}` : '⚠️ Service IA non disponible. Vérifiez qu\'Ollama est bien démarré avec: OLLAMA_HOST=0.0.0.0:11434 ollama serve',
                    data.structured || null
                );
                return data;
            }
        } catch (error) {
            typingDiv.remove();
            this.addChatMessage('ai', 'Erreur de connexion au service IA. Vérifiez qu\'Ollama est bien démarré.');
            console.error('Chat error:', error);
            return { success: false, error: String(error?.message || error || 'Chat error') };
        }
    }

    addChatMessage(type, content, structured = null) {
        const container = document.getElementById('chatbotMessages');
        if (!container) return;

        const messageDiv = document.createElement('div');
        messageDiv.className = `chat-message ${type}`;

        const avatar = type === 'user' ? '👤' : '🤖';
        const structuredHtml = type === 'ai' ? this.renderAIStructuredTable(structured, content, true) : '';

        messageDiv.innerHTML = `
            <div class="chat-avatar">${avatar}</div>
            <div class="chat-bubble">
                <div>${this.formatChatMessage(content)}</div>
                ${structuredHtml}
            </div>
        `;

        container.appendChild(messageDiv);
        container.scrollTop = container.scrollHeight;

        this.chatHistory.push({ type, content, structured, timestamp: Date.now() });
    }

    addChatTyping() {
        const container = document.getElementById('chatbotMessages');
        if (!container) return document.createElement('div');

        const typingDiv = document.createElement('div');
        typingDiv.className = 'chat-message ai';
        typingDiv.innerHTML = `
            <div class="chat-avatar">🤖</div>
            <div class="chat-bubble">
                <div class="chat-typing">
                    <span></span><span></span><span></span>
                </div>
            </div>
        `;

        container.appendChild(typingDiv);
        container.scrollTop = container.scrollHeight;

        return typingDiv;
    }

    renderChatSuggestions(suggestions = null) {
        const container = document.getElementById('chatSuggestions');
        if (!container) return;

        const source = Array.isArray(suggestions) && suggestions.length
            ? suggestions
            : this.defaultChatSuggestions;
        const chips = source.slice(0, 4);

        container.innerHTML = '';
        chips.forEach((item) => {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'suggestion-chip';
            btn.textContent = String(item.label || 'Question');
            btn.addEventListener('click', () => this.sendChatMessage(String(item.prompt || '').trim()));
            container.appendChild(btn);
        });
    }

    severityToScore(level, scoreHint = 0) {
        const sev = String(level || '').toUpperCase();
        if (sev === 'CRITICAL') return 100 + Number(scoreHint || 0);
        if (sev === 'HIGH') return 80 + Number(scoreHint || 0);
        if (sev === 'MEDIUM') return 55 + Number(scoreHint || 0);
        if (sev === 'LOW') return 30 + Number(scoreHint || 0);
        return 10 + Number(scoreHint || 0);
    }

    splitEndpoint(endpoint) {
        const raw = String(endpoint || '').trim();
        if (!raw) return { ip: '-', port: '-' };
        const idx = raw.lastIndexOf(':');
        if (idx > 0 && idx < raw.length - 1) {
            return { ip: raw.slice(0, idx), port: raw.slice(idx + 1) };
        }
        return { ip: raw, port: '-' };
    }

    inferProblemProtocol(problem) {
        const proto = String(problem?.protocol || '').trim().toUpperCase();
        if (proto) return proto;
        const text = `${problem?.symptom || ''} ${problem?.category || ''}`.toUpperCase();
        if (text.includes('DNS')) return 'DNS';
        if (text.includes('HTTPS') || text.includes('TLS') || text.includes('SSL')) return 'HTTPS';
        if (text.includes('HTTP')) return 'HTTP';
        if (text.includes('UDP')) return 'UDP';
        if (text.includes('TCP') || text.includes('SYN') || text.includes('RST')) return 'TCP';
        return 'N/A';
    }

    getProblemRecommendedTab(problem) {
        const proto = this.inferProblemProtocol(problem);
        if (proto === 'DNS') return 'dns';
        if (proto === 'HTTP' || proto === 'HTTPS') return 'http';
        if (proto === 'TCP' || proto === 'UDP') return 'streams';
        return 'overview';
    }

    buildProblemPrompt(problem) {
        const proto = this.inferProblemProtocol(problem);
        const src = `${problem.src_ip || '-'}${problem.src_port && problem.src_port !== '-' ? `:${problem.src_port}` : ''}`;
        const dst = `${problem.dst_ip || '-'}${problem.dst_port && problem.dst_port !== '-' ? `:${problem.dst_port}` : ''}`;
        const symptom = problem.symptom || 'Symptôme non précisé';
        const severity = String(problem.severity || 'MEDIUM').toUpperCase();
        const evidence = problem.evidence || 'Aucune preuve supplémentaire';

        return `Contexte incident PCAP:
- Catégorie: ${problem.category || 'N/A'}
- Sévérité: ${severity}
- Symptôme: ${symptom}
- Source: ${src}
- Destination: ${dst}
- Protocole: ${proto}
- Preuves observées: ${evidence}

Analyse ce cas et donne une piste technique exploitable immédiatement.
Réponds STRICTEMENT en JSON:
{
  "summary": "diagnostic court",
  "culprits": [{"culprit":"...", "evidence":"...", "confidence": 0}],
  "signals": ["..."],
  "recommendations": ["..."]
}`;
    }

    buildProblemSpotlight(results) {
        const out = [];
        const safeResults = results || {};
        const anomaly = safeResults.anomaly_detection || safeResults.anomaly_analysis || {};
        const anomalies = Array.isArray(anomaly?.anomalies) ? anomaly.anomalies : [];
        const tcpSessions = Array.isArray(safeResults?.tcp_analysis?.sessions) ? safeResults.tcp_analysis.sessions : [];
        const dnsAnomalies = Array.isArray(safeResults?.dns_analysis?.anomalies) ? safeResults.dns_analysis.anomalies : [];
        const httpAnomalies = Array.isArray(safeResults?.http_analysis?.anomalies) ? safeResults.http_analysis.anomalies : [];

        anomalies.slice(0, 30).forEach((item, idx) => {
            const severity = String(item?.severity || 'MEDIUM').toUpperCase();
            const srcIp = String(item?.src_ip || item?.source_ip || item?.ip || '-');
            const dstIp = String(item?.dst_ip || item?.destination_ip || '-');
            const protocol = String(item?.protocol || '').toUpperCase();
            const symptom = String(item?.description || item?.type || 'Anomalie détectée');
            const scoreHint = Number(item?.score || 0);
            const evidence = [
                item?.type ? `type=${item.type}` : '',
                Number.isFinite(scoreHint) && scoreHint > 0 ? `score=${scoreHint}` : '',
                item?.recommendation ? `reco=${item.recommendation}` : ''
            ].filter(Boolean).join(' • ');
            out.push({
                id: `anomaly-${idx}`,
                category: 'Anomalie',
                severity,
                score: this.severityToScore(severity, Math.min(20, Math.max(0, scoreHint / 5))),
                symptom,
                src_ip: srcIp,
                src_port: '-',
                dst_ip: dstIp,
                dst_port: '-',
                protocol: protocol || this.inferProblemProtocol({ symptom }),
                evidence,
            });
        });

        tcpSessions.slice(0, 50).forEach((session, idx) => {
            const retrans = Number(session?.retransmissions || 0);
            const rst = Number(session?.rst_count || 0);
            const state = String(session?.state || 'UNKNOWN').toUpperCase();
            const isHalfOpen = ['SYN_SENT', 'SYN_RECEIVED', 'INIT'].includes(state);
            if (retrans <= 0 && rst <= 0 && !isHalfOpen) return;

            const src = this.splitEndpoint(session?.src || '');
            const dst = this.splitEndpoint(session?.dst || '');
            let severity = 'MEDIUM';
            if (rst > 0 || retrans >= 12 || isHalfOpen) severity = 'HIGH';
            if ((rst >= 3) || (retrans >= 25 && isHalfOpen)) severity = 'CRITICAL';

            let symptom = 'Dégradation TCP observée';
            if (rst > 0) symptom = `RST observés (${rst})`;
            else if (isHalfOpen) symptom = `Handshake incomplet (${state})`;
            else if (retrans > 0) symptom = `Retransmissions élevées (${retrans})`;

            out.push({
                id: `tcp-${idx}`,
                category: 'Session TCP',
                severity,
                score: this.severityToScore(severity, Math.min(25, retrans + rst * 4)),
                symptom,
                src_ip: src.ip || '-',
                src_port: src.port || '-',
                dst_ip: dst.ip || '-',
                dst_port: dst.port || '-',
                protocol: 'TCP',
                evidence: `state=${state} • retrans=${retrans} • rst=${rst} • packets=${Number(session?.packets || 0)}`,
            });
        });

        dnsAnomalies.slice(0, 8).forEach((item, idx) => {
            const severity = String(item?.severity || 'MEDIUM').toUpperCase();
            out.push({
                id: `dns-${idx}`,
                category: 'Anomalie DNS',
                severity,
                score: this.severityToScore(severity),
                symptom: String(item?.description || item?.type || 'Anomalie DNS'),
                src_ip: '-',
                src_port: '-',
                dst_ip: '-',
                dst_port: '-',
                protocol: 'DNS',
                evidence: item?.recommendation ? `reco=${item.recommendation}` : '',
            });
        });

        httpAnomalies.slice(0, 8).forEach((item, idx) => {
            const severity = String(item?.severity || 'MEDIUM').toUpperCase();
            out.push({
                id: `http-${idx}`,
                category: 'Anomalie HTTP',
                severity,
                score: this.severityToScore(severity),
                symptom: String(item?.description || item?.type || 'Anomalie HTTP/HTTPS'),
                src_ip: '-',
                src_port: '-',
                dst_ip: '-',
                dst_port: '-',
                protocol: this.inferProblemProtocol({ symptom: item?.description || item?.type || '' }),
                evidence: item?.recommendation ? `reco=${item.recommendation}` : '',
            });
        });

        const dedup = new Map();
        out.forEach((item) => {
            const key = `${item.symptom}|${item.src_ip}|${item.dst_ip}|${item.protocol}`;
            const current = dedup.get(key);
            if (!current || Number(item.score) > Number(current.score)) {
                dedup.set(key, item);
            }
        });

        return Array.from(dedup.values())
            .sort((a, b) => Number(b.score || 0) - Number(a.score || 0))
            .slice(0, 10)
            .map((item, idx) => ({
                ...item,
                order: idx + 1,
                suggested_tab: this.getProblemRecommendedTab(item),
            }));
    }

    buildGuidedQuestionsFromProblems(problems) {
        return (Array.isArray(problems) ? problems : []).slice(0, 5).map((problem, idx) => {
            const proto = this.inferProblemProtocol(problem);
            const src = `${problem.src_ip || '-'}${problem.src_port && problem.src_port !== '-' ? `:${problem.src_port}` : ''}`;
            const dst = `${problem.dst_ip || '-'}${problem.dst_port && problem.dst_port !== '-' ? `:${problem.dst_port}` : ''}`;
            return {
                id: `guided-${idx}`,
                problemId: problem.id,
                label: `Cas ${idx + 1}: ${proto} ${src} → ${dst}`,
                text: `Pourquoi "${problem.symptom}" est visible sur ${src} → ${dst} (${proto}) et quelles vérifications immédiates faire ?`,
                prompt: this.buildProblemPrompt(problem),
            };
        });
    }

    renderProblemSpotlight(results = this.currentResults) {
        const highlightsEl = document.getElementById('problemHighlightsList');
        const questionsEl = document.getElementById('guidedQuestionsList');
        const previewEl = document.getElementById('guidedAiPreview');
        if (!highlightsEl || !questionsEl || !previewEl) return;

        if (!results) {
            this.guidedProblems = [];
            this.guidedQuestions = [];
            highlightsEl.innerHTML = '<div class="investigation-empty">Aucune analyse chargée.</div>';
            questionsEl.innerHTML = '<div class="investigation-empty">Les questions guidées apparaîtront ici après analyse.</div>';
            previewEl.innerHTML = '<div class="investigation-empty">Cliquez sur une question guidée pour demander une piste à l’IA.</div>';
            this.renderChatSuggestions();
            return;
        }

        const problems = this.buildProblemSpotlight(results);
        this.guidedProblems = problems;
        this.guidedQuestions = this.buildGuidedQuestionsFromProblems(problems);

        if (!problems.length) {
            highlightsEl.innerHTML = '<div class="investigation-empty">Aucun symptôme critique détecté dans cette capture.</div>';
        } else {
            highlightsEl.innerHTML = problems.map((p, idx) => `
                <article class="investigation-problem severity-${this.sanitizeClassToken(String(p.severity || 'LOW').toLowerCase())}">
                    <div class="investigation-problem-top">
                        <span class="problem-rank">#${idx + 1}</span>
                        <span class="severity-badge ${this.sanitizeClassToken(p.severity || '')}">${this.escapeHtml(p.severity || 'LOW')}</span>
                        <span class="proto-badge ${this.sanitizeClassToken(this.inferProblemProtocol(p).toLowerCase())}">${this.escapeHtml(this.inferProblemProtocol(p))}</span>
                    </div>
                    <div class="investigation-problem-symptom">${this.escapeHtml(p.symptom || 'Symptôme')}</div>
                    <div class="investigation-problem-flow">
                        <code>${this.escapeHtml(p.src_ip || '-')}</code>
                        <span>→</span>
                        <code>${this.escapeHtml(p.dst_ip || '-')}</code>
                    </div>
                    <div class="investigation-problem-meta">${this.escapeHtml(p.category || '')}${p.evidence ? ` • ${this.escapeHtml(this.truncate(p.evidence, 88))}` : ''}</div>
                    <div class="investigation-problem-actions">
                        <button class="btn btn-small" type="button" data-problem-focus="${this.escapeHtml(p.id)}">Filtrer</button>
                        <button class="btn btn-small btn-ai" type="button" data-problem-ask="${this.escapeHtml(p.id)}">🤖 Piste IA</button>
                    </div>
                </article>
            `).join('');

            highlightsEl.querySelectorAll('[data-problem-focus]').forEach((btn) => {
                btn.addEventListener('click', () => this.focusProblemById(btn.getAttribute('data-problem-focus')));
            });
            highlightsEl.querySelectorAll('[data-problem-ask]').forEach((btn) => {
                btn.addEventListener('click', () => this.askGuidedQuestionByProblem(btn.getAttribute('data-problem-ask')));
            });
        }

        if (!this.guidedQuestions.length) {
            questionsEl.innerHTML = '<div class="investigation-empty">Aucune question guidée disponible.</div>';
        } else {
            questionsEl.innerHTML = this.guidedQuestions.map((q) => `
                <div class="guided-question-item">
                    <div class="guided-question-label">${this.escapeHtml(q.label)}</div>
                    <div class="guided-question-text">${this.escapeHtml(q.text)}</div>
                    <div class="guided-question-actions">
                        <button class="btn btn-small btn-ai" type="button" data-guided-ask="${this.escapeHtml(q.id)}">🤖 Poser à l’IA</button>
                    </div>
                </div>
            `).join('');
            questionsEl.querySelectorAll('[data-guided-ask]').forEach((btn) => {
                btn.addEventListener('click', () => this.askGuidedQuestion(btn.getAttribute('data-guided-ask')));
            });
        }

        previewEl.innerHTML = '<div class="investigation-empty">Cliquez sur une question guidée pour demander une piste à l’IA.</div>';

        this.renderChatSuggestions(this.guidedQuestions.map((q, idx) => ({
            label: idx === 0 ? 'Top problème' : `Question ${idx + 1}`,
            prompt: q.prompt,
        })));
    }

    focusProblemById(problemId) {
        const problem = (this.guidedProblems || []).find((p) => String(p.id) === String(problemId));
        if (!problem) return;

        const tab = problem.suggested_tab || this.getProblemRecommendedTab(problem);
        const query = String(problem.src_ip && problem.src_ip !== '-' ? problem.src_ip : (problem.dst_ip && problem.dst_ip !== '-' ? problem.dst_ip : '')).trim();
        const protocol = this.inferProblemProtocol(problem);

        this.globalDrilldownFilter = {
            query,
            protocol: protocol === 'N/A' ? '' : protocol,
            riskMin: 40,
        };

        const streamIp = document.getElementById('streamIpFilter');
        if (streamIp) streamIp.value = query;
        const streamProblemOnly = document.getElementById('streamProblematicOnly');
        if (streamProblemOnly) streamProblemOnly.checked = true;

        this.switchTab(tab);

        if (this.currentResults) {
            this.displayDnsResults(this.currentResults.dns_analysis || {});
            this.displayHttpResults(this.currentResults.http_analysis || {});
            if (tab === 'streams') this.loadStreams();
            if (tab === 'packets') this.applyPacketFilters();
            if (typeof window.advApplyGlobalDrilldown === 'function') {
                window.advApplyGlobalDrilldown(this.globalDrilldownFilter);
            }
        }

        this.showToast('info', 'Troubleshooting', `Filtre appliqué sur ${query || 'le contexte'} (${protocol})`);
    }

    askGuidedQuestionByProblem(problemId) {
        const question = (this.guidedQuestions || []).find((q) => String(q.problemId) === String(problemId));
        if (!question) {
            this.showToast('warning', 'Question guidée', 'Aucune question disponible pour ce problème');
            return;
        }
        this.askGuidedQuestion(question.id);
    }

    async askTopGuidedQuestion() {
        const top = (this.guidedQuestions || [])[0];
        if (!top) {
            this.showToast('warning', 'Question guidée', 'Aucun problème prioritaire détecté');
            return;
        }
        await this.askGuidedQuestion(top.id);
    }

    async askGuidedQuestion(questionId) {
        const previewEl = document.getElementById('guidedAiPreview');
        const question = (this.guidedQuestions || []).find((q) => String(q.id) === String(questionId));
        if (!question) {
            this.showToast('warning', 'Question guidée', 'Question introuvable');
            return;
        }

        const problem = (this.guidedProblems || []).find((p) => String(p.id) === String(question.problemId));
        if (problem) this.focusProblemById(problem.id);

        if (previewEl) {
            previewEl.innerHTML = `<div class="investigation-loading">🤖 Analyse IA en cours pour: ${this.escapeHtml(question.label)}</div>`;
        }

        const payload = await this.sendChatMessage(question.prompt);
        if (!previewEl) return;

        if (payload?.success) {
            const structured = this.renderAIStructuredTable(payload.structured || null, payload.response || '', false);
            previewEl.innerHTML = `
                <div class="investigation-ai-title">${this.escapeHtml(question.label)}</div>
                <div class="investigation-ai-subtitle">${this.escapeHtml(question.text)}</div>
                ${structured || `<div class="investigation-ai-fallback">${this.formatChatMessage(payload.response || '')}</div>`}
            `;
        } else {
            const errorText = payload?.error || 'Erreur IA';
            previewEl.innerHTML = `<div class="investigation-ai-error">❌ ${this.escapeHtml(errorText)}</div>`;
        }
    }

    getAutoQuestionnairePlan() {
        const guided = (Array.isArray(this.guidedQuestions) ? this.guidedQuestions : []).slice(0, 3);
        if (guided.length >= 3) return guided.map((q, idx) => ({ id: `auto-${idx + 1}`, label: q.label, prompt: q.prompt }));

        const topProblems = (Array.isArray(this.guidedProblems) ? this.guidedProblems : []).slice(0, 3);
        if (topProblems.length) {
            return topProblems.map((p, idx) => ({
                id: `auto-problem-${idx + 1}`,
                label: `Question auto #${idx + 1}`,
                prompt: this.buildProblemPrompt(p),
            }));
        }

        return [
            {
                id: 'auto-default-1',
                label: 'Question auto #1',
                prompt: 'Donne la problématique réseau principale actuellement observable (symptôme, IP source, IP destination, protocole) et la priorité de traitement.'
            },
            {
                id: 'auto-default-2',
                label: 'Question auto #2',
                prompt: 'Identifie la cause technique la plus probable des ralentissements/congestion, avec les preuves mesurables et les vérifications immédiates.'
            },
            {
                id: 'auto-default-3',
                label: 'Question auto #3',
                prompt: 'Propose un plan d\'investigation court en 5 étapes pour confirmer la root cause et isoler l\'équipement potentiellement fautif.'
            }
        ];
    }

    scheduleAutoQuestionnaire() {
        if (!this.autoQuestionnaireEnabled) return;
        if (!this.currentTaskId) return;
        if (this.autoQuestionnaireDoneForTask === this.currentTaskId) return;
        if (this.autoQuestionnaireTimer) clearTimeout(this.autoQuestionnaireTimer);
        this.autoQuestionnaireTimer = setTimeout(() => {
            this.runAutoQuestionnaire().catch((e) => console.error('Auto questionnaire error:', e));
        }, 650);
    }

    async runAutoQuestionnaire(force = false) {
        if (!this.currentTaskId) return;
        if (!this.autoQuestionnaireEnabled && !force) return;
        if (this.autoQuestionnaireInProgress && !force) return;
        if (!force && this.autoQuestionnaireDoneForTask === this.currentTaskId) return;

        const previewEl = document.getElementById('guidedAiPreview');
        const plan = this.getAutoQuestionnairePlan().slice(0, 3);
        if (!plan.length) return;

        this.autoQuestionnaireInProgress = true;
        const answers = [];
        try {
            if (previewEl) {
                previewEl.innerHTML = `<div class="investigation-loading">🤖 Questionnaire automatique en cours (0/${plan.length})...</div>`;
            }

            if (!this.chatbotOpen) {
                this.toggleChatbot();
            }

            for (let i = 0; i < plan.length; i += 1) {
                const step = plan[i];
                if (previewEl) {
                    previewEl.innerHTML = `<div class="investigation-loading">🤖 Questionnaire automatique en cours (${i + 1}/${plan.length})...<br>${this.escapeHtml(step.label || `Question ${i + 1}`)}</div>`;
                }
                const response = await this.sendChatMessage(step.prompt);
                answers.push({ step, response });
                await new Promise((resolve) => setTimeout(resolve, 260));
            }
        } catch (error) {
            console.error('Auto questionnaire run error:', error);
            if (previewEl) {
                previewEl.innerHTML = `<div class="investigation-ai-error">❌ Échec questionnaire automatique: ${this.escapeHtml(error?.message || 'Erreur inconnue')}</div>`;
            }
        } finally {
            this.autoQuestionnaireInProgress = false;
        }

        const questionnaireCompleted = answers.length === plan.length;
        if (questionnaireCompleted) this.autoQuestionnaireDoneForTask = this.currentTaskId;

        if (previewEl && answers.length > 0) {
            const items = answers.map((entry, idx) => {
                const ok = Boolean(entry?.response?.success);
                const payload = this.normalizeAIStructuredData(entry?.response?.structured || null, entry?.response?.response || '');
                const summary = payload.summary || `Réponse ${idx + 1}`;
                return `
                    <div class="guided-auto-result ${ok ? '' : 'error'}">
                        <div class="guided-auto-title">Q${idx + 1} • ${this.escapeHtml(entry?.step?.label || `Question ${idx + 1}`)}</div>
                        <div class="guided-auto-text">${this.escapeHtml(summary)}</div>
                    </div>
                `;
            }).join('');
            previewEl.innerHTML = `
                <div class="investigation-ai-title">${questionnaireCompleted ? '✅ Questionnaire automatique terminé' : '⚠️ Questionnaire automatique partiel'}</div>
                <div class="investigation-ai-subtitle">${questionnaireCompleted ? '3 questions analysées automatiquement après la fin d’analyse.' : `Réponses obtenues: ${answers.length}/${plan.length}. Vérifiez la connectivité IA.`}</div>
                <div class="guided-auto-list">${items}</div>
            `;
        }
    }

    formatChatMessage(content) {
        // Escape first, then allow a minimal markdown subset.
        return this.escapeHtml(content)
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/`(.*?)`/g, '<code>$1</code>')
            .replace(/\n/g, '<br>');
    }

    parseAIConfidence(value) {
        if (value === null || value === undefined) return null;
        if (typeof value === 'number' && Number.isFinite(value)) {
            return Math.min(100, Math.max(0, value));
        }
        const raw = String(value).trim().toLowerCase();
        const match = raw.match(/(\d{1,3}(?:[.,]\d+)?)/);
        if (match) {
            const n = Number(match[1].replace(',', '.'));
            if (Number.isFinite(n)) return Math.min(100, Math.max(0, n));
        }
        if (raw.includes('high') || raw.includes('élev') || raw.includes('eleve')) return 80;
        if (raw.includes('medium') || raw.includes('modér') || raw.includes('moder')) return 55;
        if (raw.includes('low') || raw.includes('faible')) return 30;
        return null;
    }

    normalizeAIStructuredData(structured, fallbackText = '') {
        let payload = structured;
        if (typeof payload === 'string') {
            try {
                payload = JSON.parse(payload);
            } catch (_) {
                payload = null;
            }
        }

        const normalized = {
            summary: '',
            culprits: [],
            signals: [],
            recommendations: [],
            confidence_note: ''
        };

        if (Array.isArray(payload)) {
            normalized.culprits = payload.map(item => {
                if (typeof item === 'string') {
                    return { culprit: item, evidence: '', confidence: null };
                }
                if (item && typeof item === 'object') {
                    return {
                        culprit: String(item.culprit || item.coupable || item.entity || item.name || item.ip || item.mac || 'Inconnu'),
                        evidence: String(item.evidence || item.preuve || item.reason || item.justification || item.details || ''),
                        confidence: this.parseAIConfidence(item.confidence ?? item.confiance ?? item.score)
                    };
                }
                return null;
            }).filter(Boolean);
        } else if (payload && typeof payload === 'object') {
            normalized.summary = String(payload.summary || payload.synthese || payload.verdict || '');
            normalized.confidence_note = String(payload.confidence_note || payload.note_confiance || '');

            let culprits = payload.culprits || payload.coupables || payload.suspects || payload.responsables;
            if (!culprits && (payload.culprit || payload.coupable_probable || payload.preuve || payload.confiance)) {
                culprits = [payload];
            }
            if (culprits && !Array.isArray(culprits)) culprits = [culprits];
            if (Array.isArray(culprits)) {
                normalized.culprits = culprits.map(item => {
                    if (typeof item === 'string') return { culprit: item, evidence: '', confidence: null };
                    if (!item || typeof item !== 'object') return null;
                    return {
                        culprit: String(item.culprit || item.coupable || item.responsable || item.entity || item.equipment || item.equipement || item.ip || item.mac || item.host || item.segment || 'Inconnu'),
                        evidence: String(item.evidence || item.preuve || item.reason || item.raison || item.justification || item.description || ''),
                        confidence: this.parseAIConfidence(item.confidence ?? item.confiance ?? item.score ?? item.probability)
                    };
                }).filter(Boolean);
            }

            const signals = payload.signals || payload.signaux || payload.findings || [];
            if (Array.isArray(signals)) {
                normalized.signals = signals.map(v => String(v).trim()).filter(Boolean);
            } else if (typeof signals === 'string' && signals.trim()) {
                normalized.signals = [signals.trim()];
            }

            const recs = payload.recommendations || payload.actions || payload.next_steps || payload.remediation || payload['remédiation'] || [];
            if (Array.isArray(recs)) {
                normalized.recommendations = recs.map(v => String(v).trim()).filter(Boolean);
            } else if (typeof recs === 'string' && recs.trim()) {
                normalized.recommendations = [recs.trim()];
            }
        }

        if (!normalized.summary && fallbackText) {
            normalized.summary = String(fallbackText).split('\n').map(v => v.trim()).filter(Boolean)[0] || '';
        }

        return normalized;
    }

    renderAIStructuredTable(structured, fallbackText = '', compact = false) {
        const data = this.normalizeAIStructuredData(structured, fallbackText);
        const hasAny = data.summary || data.culprits.length || data.signals.length || data.recommendations.length;
        if (!hasAny) return '';

        const rows = data.culprits.length
            ? data.culprits.map(item => {
                const conf = item.confidence;
                const confLabel = conf === null || conf === undefined ? 'N/A' : `${Math.round(conf)}%`;
                const confCls = conf >= 75 ? 'high' : conf >= 45 ? 'medium' : 'low';
                return `
                    <tr>
                        <td>${this.escapeHtml(item.culprit || 'Inconnu')}</td>
                        <td>${this.escapeHtml(item.evidence || 'Preuve non fournie')}</td>
                        <td><span class="ai-confidence-badge ${confCls}">${this.escapeHtml(confLabel)}</span></td>
                    </tr>
                `;
            }).join('')
            : `
                <tr>
                    <td colspan="3"><em>Aucun coupable explicite détecté</em></td>
                </tr>
            `;

        const summary = data.summary ? `<div class="ai-structured-summary">${this.escapeHtml(data.summary)}</div>` : '';
        const signals = data.signals.length
            ? `<div class="ai-structured-list"><strong>Signaux:</strong> ${data.signals.slice(0, compact ? 3 : 6).map(s => `<span class="ai-chip">${this.escapeHtml(s)}</span>`).join(' ')}</div>`
            : '';
        const recommendations = data.recommendations.length
            ? `<div class="ai-structured-list"><strong>Actions:</strong> ${data.recommendations.slice(0, compact ? 3 : 6).map(s => `<span class="ai-chip">${this.escapeHtml(s)}</span>`).join(' ')}</div>`
            : '';
        const confidenceNote = data.confidence_note
            ? `<div class="ai-structured-note">${this.escapeHtml(data.confidence_note)}</div>`
            : '';

        return `
            <div class="ai-structured-block ${compact ? 'compact' : ''}">
                ${summary}
                <div class="ai-structured-table-wrap">
                    <table class="ai-structured-table">
                        <thead>
                            <tr>
                                <th>Coupable probable</th>
                                <th>Preuve</th>
                                <th>Confiance</th>
                            </tr>
                        </thead>
                        <tbody>${rows}</tbody>
                    </table>
                </div>
                ${signals}
                ${recommendations}
                ${confidenceNote}
            </div>
        `;
    }

    // ==================== AI ANALYSIS BUTTONS ====================

    async analyzeWithAI(context) {
        if (!this.currentTaskId) {
            this.showToast('warning', 'Pas d\'analyse', 'Veuillez d\'abord analyser un fichier PCAP');
            return;
        }

        this.showToast('info', 'Analyse IA', `Analyse ${context} en cours...`);

        // Open chatbot and send contextual question
        if (!this.chatbotOpen) {
            this.toggleChatbot();
        }

        const questions = {
            'anomalies': 'Analyse les anomalies détectées et donne des recommandations de sécurité',
            'dns': 'Analyse les requêtes DNS et détecte les domaines potentiellement malveillants',
            'http': 'Analyse le trafic HTTP/HTTPS et identifie les comportements suspects',
            'protocols': 'Analyse la distribution des protocoles et identifie les anomalies',
            'top_ips': 'Analyse les IPs les plus actives et identifie les comportements suspects',
            'summary': 'Donne un résumé exécutif de l\'analyse PCAP'
        };

        const question = questions[context] || `Analyse le contexte: ${context}`;
        await this.sendChatMessage(question);
    }

    setupEventListeners() {
        // Upload area
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');

        if (uploadArea && fileInput) {
            uploadArea.addEventListener('click', () => fileInput.click());
            uploadArea.addEventListener('dragover', (e) => {
                e.preventDefault();
                uploadArea.classList.add('dragover');
            });
            uploadArea.addEventListener('dragleave', () => {
                uploadArea.classList.remove('dragover');
            });
            uploadArea.addEventListener('drop', (e) => {
                e.preventDefault();
                uploadArea.classList.remove('dragover');
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    this.uploadFile(files[0]);
                }
            });

            fileInput.addEventListener('change', (e) => {
                if (e.target.files.length > 0) {
                    this.uploadFile(e.target.files[0]);
                }
            });
        }

        const openMultiModeBtn = document.getElementById('openMultiPcapMode');
        if (openMultiModeBtn) {
            openMultiModeBtn.addEventListener('click', () => this.openMultiPcapMode());
        }

        // Export buttons
        const exportJson = document.getElementById('exportJson');
        const exportCsv = document.getElementById('exportCsv');
        const exportPdf = document.getElementById('exportPdf');

        if (exportJson) exportJson.addEventListener('click', () => this.exportReport('json'));
        if (exportCsv) exportCsv.addEventListener('click', () => this.exportReport('csv'));
        if (exportPdf) exportPdf.addEventListener('click', () => this.exportReport('pdf'));

        // New analysis button
        const newAnalysisBtn = document.getElementById('newAnalysisBtn');
        if (newAnalysisBtn) {
            newAnalysisBtn.addEventListener('click', () => this.resetAnalysis());
        }

        // Refresh history button
        const refreshHistory = document.getElementById('refreshHistory');
        if (refreshHistory) {
            refreshHistory.addEventListener('click', () => this.loadHistory());
        }

        // Ollama config menu
        const ollamaConfigBtn = document.getElementById('ollamaConfigBtn');
        if (ollamaConfigBtn) {
            ollamaConfigBtn.addEventListener('click', () => this.openOllamaConfigMenu());
        }
        const ollamaStatus = document.getElementById('ollamaStatus');
        if (ollamaStatus) {
            ollamaStatus.addEventListener('click', () => this.openOllamaConfigMenu());
        }
        const maclookupConfigBtn = document.getElementById('maclookupConfigBtn');
        if (maclookupConfigBtn) {
            maclookupConfigBtn.addEventListener('click', () => this.openMacLookupConfigMenu());
        }
        const maclookupStatus = document.getElementById('maclookupStatus');
        if (maclookupStatus) {
            maclookupStatus.addEventListener('click', () => this.openMacLookupConfigMenu());
        }
        const focusModeToggle = document.getElementById('focusModeToggle');
        if (focusModeToggle) {
            focusModeToggle.addEventListener('click', () => this.toggleFocusInvestigation());
        }
        const guidedRefreshBtn = document.getElementById('guidedRefreshBtn');
        if (guidedRefreshBtn) {
            guidedRefreshBtn.addEventListener('click', () => this.renderProblemSpotlight(this.currentResults));
        }
        const guidedAskTopBtn = document.getElementById('guidedAskTopBtn');
        if (guidedAskTopBtn) {
            guidedAskTopBtn.addEventListener('click', () => this.askTopGuidedQuestion());
        }

        const guidedRunBtn = document.getElementById('guidedRunBtn');
        if (guidedRunBtn) guidedRunBtn.addEventListener('click', () => this.runAutoQuestionnaire(true));

        // Streams filters
        const streamIpFilter = document.getElementById('streamIpFilter');
        const streamTypeFilter = document.getElementById('streamTypeFilter');
        const streamSortBy = document.getElementById('streamSortBy');
        const streamPageSize = document.getElementById('streamPageSize');
        const streamProblematicOnly = document.getElementById('streamProblematicOnly');
        const streamRefreshBtn = document.getElementById('streamRefreshBtn');
        const streamResetBtn = document.getElementById('streamResetBtn');
        const streamExportProblematicBtn = document.getElementById('streamExportProblematicBtn');
        const streamPrevBtn = document.getElementById('streamPrevBtn');
        const streamNextBtn = document.getElementById('streamNextBtn');

        if (streamIpFilter) {
            streamIpFilter.addEventListener('input', () => {
                clearTimeout(this.streamFilterTimer);
                this.streamFilterTimer = setTimeout(() => {
                    this.streamOffset = 0;
                    this.loadStreams();
                }, 250);
            });
            streamIpFilter.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    this.streamOffset = 0;
                    this.loadStreams();
                }
            });
        }
        if (streamTypeFilter) {
            streamTypeFilter.addEventListener('change', () => {
                this.streamOffset = 0;
                this.loadStreams();
            });
        }
        if (streamSortBy) {
            streamSortBy.addEventListener('change', () => {
                this.streamOffset = 0;
                this.loadStreams();
            });
        }
        if (streamPageSize) {
            streamPageSize.addEventListener('change', () => {
                this.streamLimit = Math.max(1, parseInt(streamPageSize.value, 10) || 100);
                this.streamOffset = 0;
                this.loadStreams();
            });
        }
        if (streamProblematicOnly) {
            streamProblematicOnly.addEventListener('change', () => {
                this.streamOffset = 0;
                this.loadStreams();
            });
        }
        if (streamRefreshBtn) streamRefreshBtn.addEventListener('click', () => this.loadStreams(true));
        if (streamExportProblematicBtn) {
            streamExportProblematicBtn.addEventListener('click', () => this.exportProblematicStreamsCsv());
        }
        if (streamResetBtn) {
            streamResetBtn.addEventListener('click', () => {
                if (streamIpFilter) streamIpFilter.value = '';
                if (streamTypeFilter) streamTypeFilter.value = '';
                if (streamSortBy) streamSortBy.value = 'risk';
                if (streamPageSize) streamPageSize.value = '100';
                if (streamProblematicOnly) streamProblematicOnly.checked = false;
                this.streamLimit = 100;
                this.streamOffset = 0;
                this.loadStreams(true);
            });
        }
        if (streamPrevBtn) {
            streamPrevBtn.addEventListener('click', () => {
                if (this.streamOffset <= 0) return;
                this.streamOffset = Math.max(0, this.streamOffset - this.streamLimit);
                this.loadStreams();
            });
        }
        if (streamNextBtn) {
            streamNextBtn.addEventListener('click', () => {
                if (this.streamOffset + this.streamLimit >= this.streamTotal) return;
                this.streamOffset += this.streamLimit;
                this.loadStreams();
            });
        }

        // Multi-PCAP upload area
        const multiUploadArea = document.getElementById('multiUploadArea');
        const multiFileInput = document.getElementById('multiFileInput');
        const multiAnalyzeBtn = document.getElementById('multiAnalyzeBtn');
        const multiClearBtn = document.getElementById('multiClearBtn');
        const multiProblematicOnly = document.getElementById('multiProblematicOnly');
        const multiReloadResultsBtn = document.getElementById('multiReloadResultsBtn');
        const multiExportCsvBtn = document.getElementById('multiExportCsvBtn');
        const multiExportDfirBtn = document.getElementById('multiExportDfirBtn');
        const multiSessionSearch = document.getElementById('multiSessionSearch');
        const multiProtocolFilter = document.getElementById('multiProtocolFilter');
        const multiConfidenceFilter = document.getElementById('multiConfidenceFilter');
        const multiSortBy = document.getElementById('multiSortBy');
        const multiResetFiltersBtn = document.getElementById('multiResetFiltersBtn');
        const multiGlobalSearch = document.getElementById('multiGlobalSearch');
        const multiGlobalProtocol = document.getElementById('multiGlobalProtocol');
        const multiGlobalRiskMin = document.getElementById('multiGlobalRiskMin');
        const multiDrillApplyBtn = document.getElementById('multiDrillApplyBtn');
        const multiDrillResetBtn = document.getElementById('multiDrillResetBtn');
        const multiDrillExportBtn = document.getElementById('multiDrillExportBtn');

        if (multiUploadArea && multiFileInput) {
            multiUploadArea.addEventListener('click', () => multiFileInput.click());
            multiUploadArea.addEventListener('dragover', (e) => {
                e.preventDefault();
                multiUploadArea.classList.add('dragover');
            });
            multiUploadArea.addEventListener('dragleave', () => {
                multiUploadArea.classList.remove('dragover');
            });
            multiUploadArea.addEventListener('drop', (e) => {
                e.preventDefault();
                multiUploadArea.classList.remove('dragover');
                this.addMultiPcapFiles(Array.from(e.dataTransfer.files || []));
            });

            multiFileInput.addEventListener('change', (e) => {
                this.addMultiPcapFiles(Array.from(e.target.files || []));
                e.target.value = '';
            });
        }

        if (multiAnalyzeBtn) multiAnalyzeBtn.addEventListener('click', () => this.analyzeMultiPcap());
        if (multiClearBtn) multiClearBtn.addEventListener('click', () => this.clearMultiPcapSelection());
        if (multiProblematicOnly) multiProblematicOnly.addEventListener('change', () => this.renderMultiPcapSessionsTable());
        if (multiReloadResultsBtn) multiReloadResultsBtn.addEventListener('click', () => this.reloadMultiPcapResults());
        if (multiExportCsvBtn) multiExportCsvBtn.addEventListener('click', () => this.exportMultiPcapCsv());
        if (multiExportDfirBtn) multiExportDfirBtn.addEventListener('click', () => this.exportMultiPcapDfirJson());
        if (multiSessionSearch) {
            multiSessionSearch.addEventListener('input', () => {
                clearTimeout(this.multiFilterTimer);
                this.multiFilterTimer = setTimeout(() => this.renderMultiPcapSessionsTable(), 180);
            });
        }
        if (multiProtocolFilter) multiProtocolFilter.addEventListener('change', () => this.renderMultiPcapSessionsTable());
        if (multiConfidenceFilter) multiConfidenceFilter.addEventListener('change', () => this.renderMultiPcapSessionsTable());
        if (multiSortBy) multiSortBy.addEventListener('change', () => this.renderMultiPcapSessionsTable());
        if (multiResetFiltersBtn) multiResetFiltersBtn.addEventListener('click', () => this.resetMultiPcapFilters());
        if (multiGlobalSearch) {
            multiGlobalSearch.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') this.applyGlobalDrilldownFromControls();
            });
        }
        if (multiGlobalProtocol) {
            multiGlobalProtocol.addEventListener('change', () => this.applyGlobalDrilldownFromControls(true));
        }
        if (multiGlobalRiskMin) {
            multiGlobalRiskMin.addEventListener('change', () => this.applyGlobalDrilldownFromControls(true));
        }
        if (multiDrillApplyBtn) multiDrillApplyBtn.addEventListener('click', () => this.applyGlobalDrilldownFromControls());
        if (multiDrillResetBtn) multiDrillResetBtn.addEventListener('click', () => this.resetGlobalDrilldownControls());
        if (multiDrillExportBtn) multiDrillExportBtn.addEventListener('click', () => this.exportGlobalDrilldownSnapshotCsv());

        // Modal close
        const modalClose = document.getElementById('modalClose');
        const detailModal = document.getElementById('detailModal');

        if (modalClose) {
            modalClose.addEventListener('click', () => this.closeModal());
        }

        if (detailModal) {
            detailModal.addEventListener('click', (e) => {
                if (e.target === detailModal || e.target.classList.contains('modal-overlay')) {
                    this.closeModal();
                }
            });
        }

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeModal();
                if (this.chatbotOpen) this.toggleChatbot();
            }
        });
    }

    setupChartDefaults() {
        // ECharts doesn't need global defaults — theme applied per-chart instance
        this.echartsInstances = {};
    }

    updateChartsTheme() {
        // Re-render all ECharts instances with current theme
        Object.values(this.echartsInstances).forEach(chart => {
            if (chart && !chart.isDisposed()) {
                const option = chart.getOption();
                if (option) chart.setOption(option, { notMerge: false });
            }
        });
    }

    setupTabs() {
        const tabs = Array.from(document.querySelectorAll('.tab'));
        const validTabs = new Set(
            tabs
                .map(t => String(t.dataset.tab || '').trim())
                .filter(Boolean)
        );

        const restoreTabFromUrlOrStorage = () => {
            let fromHash = '';
            try {
                const hash = String(window.location.hash || '');
                const tabFromQuery = hash.match(/tab=([a-z0-9-]+)/i);
                fromHash = tabFromQuery?.[1] || (hash.startsWith('#') ? hash.slice(1) : '');
            } catch (_) {
                fromHash = '';
            }
            let fromStorage = '';
            try {
                fromStorage = String(localStorage.getItem('pcap:last_tab') || '');
            } catch (_) {
                fromStorage = '';
            }
            const candidate = fromHash || fromStorage;
            return validTabs.has(candidate) ? candidate : '';
        };

        tabs.forEach((tab, idx) => {
            tab.setAttribute('role', 'tab');
            tab.setAttribute('aria-selected', tab.classList.contains('active') ? 'true' : 'false');
            tab.setAttribute('tabindex', tab.classList.contains('active') ? '0' : '-1');
            tab.addEventListener('keydown', (e) => {
                const key = e.key;
                if (!['ArrowRight', 'ArrowLeft', 'ArrowDown', 'ArrowUp', 'Home', 'End', 'Enter', ' '].includes(key)) return;
                e.preventDefault();
                if (key === 'Enter' || key === ' ') {
                    e.currentTarget.click();
                    return;
                }
                let nextIdx = idx;
                if (key === 'ArrowRight' || key === 'ArrowDown') nextIdx = (idx + 1) % tabs.length;
                if (key === 'ArrowLeft' || key === 'ArrowUp') nextIdx = (idx - 1 + tabs.length) % tabs.length;
                if (key === 'Home') nextIdx = 0;
                if (key === 'End') nextIdx = tabs.length - 1;
                const group = tabs[nextIdx]?.closest('.nomios-nav-group');
                if (group) group.open = true;
                tabs[nextIdx]?.focus();
            });
            tab.addEventListener('click', (e) => {
                const tabId = e.target.closest('.tab').dataset.tab;
                this.switchTab(tabId);
            });
        });
        const tabsContainer = document.querySelector('.tabs');
        if (tabsContainer) tabsContainer.setAttribute('role', 'tablist');

        const restoredTab = restoreTabFromUrlOrStorage();
        if (restoredTab) {
            this.switchTab(restoredTab);
        }
        this.setupTabsScrollNavigation();
        this.initMenuHealthCenter();
        this.updateActiveTabPill();
    }

    setupTabsScrollNavigation() {
        const tabs = document.querySelector('.tabs');
        if (!tabs || this.tabsWheelBound) return;
        this.tabsWheelBound = true;

        tabs.addEventListener('wheel', (event) => {
            if (tabs.scrollWidth <= tabs.clientWidth) return;
            if (Math.abs(event.deltaY) <= Math.abs(event.deltaX)) return;
            event.preventDefault();
            tabs.scrollLeft += event.deltaY * 0.9;
        }, { passive: false });
    }

    initMenuHealthCenter() {
        const container = document.getElementById('menuHealthCenter');
        const itemsHost = document.getElementById('menuHealthItems');
        if (!container || !itemsHost) return;

        const tabs = Array.from(document.querySelectorAll('.tab[data-tab]'));
        this.menuHealthOrder = tabs
            .map((tab) => String(tab.dataset.tab || '').trim())
            .filter(Boolean);

        const prevState = this.menuHealthState || {};
        this.menuHealthState = {};
        this.menuHealthOrder.forEach((tabId) => {
            const prev = prevState[tabId] || {};
            this.menuHealthState[tabId] = {
                status: this.normalizeMenuHealthStatus(prev.status || 'idle'),
                message: String(prev.message || 'En attente'),
                updatedAt: Number(prev.updatedAt || 0),
            };
        });
        container.style.display = '';
        this.renderMenuHealthCenter();
    }

    normalizeMenuHealthStatus(status) {
        const allowed = new Set(['idle', 'loading', 'ok', 'missing', 'fallback', 'error']);
        const value = String(status || 'idle').trim().toLowerCase();
        return allowed.has(value) ? value : 'idle';
    }

    getMenuHealthLabel(tabId) {
        const tabBtn = document.querySelector(`.tab[data-tab="${tabId}"]`);
        if (!tabBtn) return tabId;
        const txt = String(tabBtn.textContent || '').replace(/\s+/g, ' ').trim();
        return txt || tabId;
    }

    setMenuHealthStatus(tabId, status = 'idle', message = '', options = {}) {
        if (!tabId) return;
        if (!this.menuHealthState || typeof this.menuHealthState !== 'object') {
            this.menuHealthState = {};
        }
        const normalized = this.normalizeMenuHealthStatus(status);
        const nextMessage = String(message || '').trim() || this.menuHealthState?.[tabId]?.message || 'En attente';
        this.menuHealthState[tabId] = {
            status: normalized,
            message: nextMessage,
            updatedAt: Date.now(),
        };
        if (options?.defer) return;
        this.scheduleMenuHealthRender();
    }

    refreshMenuHealthFromResults(results) {
        const protocolSummary = results?.protocol_analysis?.summary || {};
        const dnsSummary = results?.dns_analysis?.summary || {};
        const httpSummary = results?.http_analysis?.summary || {};
        const tcpSummary = results?.tcp_analysis?.summary || {};
        const packetsIndex = Array.isArray(results?.packets_index) ? results.packets_index : [];

        const totalPackets = Number(protocolSummary.total_packets || packetsIndex.length || 0);
        const dnsQueries = Number(dnsSummary.total_queries || 0);
        const httpReq = Number(httpSummary.total_requests || 0);
        const tlsSess = Number(httpSummary.total_tls_sessions || 0);
        const tcpSessions = Number(tcpSummary.total_sessions || (Array.isArray(results?.tcp_analysis?.sessions) ? results.tcp_analysis.sessions.length : 0));

        this.setMenuHealthStatus('overview', totalPackets > 0 ? 'ok' : 'missing', totalPackets > 0 ? `${totalPackets.toLocaleString('fr-FR')} paquets` : 'Aucun paquet', { defer: true });
        this.setMenuHealthStatus('dns', dnsQueries > 0 ? 'ok' : 'missing', dnsQueries > 0 ? `${dnsQueries.toLocaleString('fr-FR')} requêtes DNS` : 'Aucune requête DNS', { defer: true });
        this.setMenuHealthStatus('http', (httpReq > 0 || tlsSess > 0) ? 'ok' : 'missing', (httpReq > 0 || tlsSess > 0) ? `${httpReq.toLocaleString('fr-FR')} HTTP / ${tlsSess.toLocaleString('fr-FR')} TLS` : 'Aucune donnée HTTP/TLS', { defer: true });
        this.setMenuHealthStatus('timeline', totalPackets > 0 ? 'ok' : 'missing', totalPackets > 0 ? 'Prêt pour visualisation' : 'Aucun événement disponible', { defer: true });
        this.setMenuHealthStatus('streams', tcpSessions > 0 ? 'ok' : 'missing', tcpSessions > 0 ? `${tcpSessions.toLocaleString('fr-FR')} sessions TCP` : 'Aucune session TCP', { defer: true });
        this.setMenuHealthStatus('packets', totalPackets > 0 ? 'ok' : 'missing', totalPackets > 0 ? `${totalPackets.toLocaleString('fr-FR')} paquets indexés` : 'Aucun paquet indexé', { defer: true });
        this.setMenuHealthStatus('team-ia', this.currentTaskId ? 'ok' : 'missing', this.currentTaskId ? 'IA prête (analyse à lancer)' : 'Aucune analyse chargée', { defer: true });

        if (!this.multiPcapResults) {
            this.setMenuHealthStatus('multi-pcap', 'missing', this.multiPcapFiles.length >= 2 ? 'Corrélation non lancée' : 'Chargez au moins 2 captures', { defer: true });
        }

        ['tls-audit', 'threat-intel', 'flow-behavior', 'lateral-movement', 'qos', 'tcp-health', 'playbook'].forEach((tabId) => {
            if (!this.menuHealthState?.[tabId] || this.menuHealthState[tabId].status === 'idle') {
                this.setMenuHealthStatus(tabId, 'idle', 'Ouvrir le menu pour lancer le module', { defer: true });
            }
        });
        this.scheduleMenuHealthRender();
    }

    renderMenuHealthCenter() {
        const container = document.getElementById('menuHealthCenter');
        const itemsHost = document.getElementById('menuHealthItems');
        const summary = document.getElementById('menuHealthSummary');
        if (!container || !itemsHost || !summary) return;

        const order = Array.isArray(this.menuHealthOrder) && this.menuHealthOrder.length
            ? this.menuHealthOrder
            : Object.keys(this.menuHealthState || {});
        if (!order.length) {
            container.style.display = 'none';
            return;
        }
        container.style.display = '';

        const counters = { ok: 0, missing: 0, fallback: 0, error: 0, loading: 0, idle: 0 };
        const iconMap = {
            ok: '✅',
            missing: '🟡',
            fallback: '🟠',
            error: '🔴',
            loading: '🔄',
            idle: '⚪',
        };

        itemsHost.innerHTML = order.map((tabId) => {
            const state = this.menuHealthState?.[tabId] || { status: 'idle', message: 'En attente' };
            const status = this.normalizeMenuHealthStatus(state.status);
            counters[status] = (counters[status] || 0) + 1;
            const title = `${this.getMenuHealthLabel(tabId)} • ${status.toUpperCase()}${state.message ? ` — ${state.message}` : ''}`;
            const activeClass = this.currentTabId === tabId ? ' active' : '';
            const label = this.getMenuHealthLabel(tabId);
            return `
                <button class="menu-health-item clickable${activeClass}" data-status="${this.escapeHtml(status)}" title="${this.escapeHtml(title)}" onclick="analyzer.switchTab(${JSON.stringify(tabId)})">
                    <span class="menu-health-dot" aria-hidden="true"></span>
                    <span>${iconMap[status] || '⚪'} ${this.escapeHtml(label)}</span>
                </button>
            `;
        }).join('');

        summary.textContent = `OK ${counters.ok} • Missing ${counters.missing} • Fallback ${counters.fallback} • Errors ${counters.error} • Loading ${counters.loading}`;
    }

    switchTab(tabId) {
        if (!tabId) return;
        const normalizedTabId = String(tabId);
        if (this.currentTabId === normalizedTabId && !this.tabTransitionLock) {
            this.updateActiveTabPill();
            return;
        }
        if (this.tabTransitionLock) {
            this.pendingTabId = normalizedTabId;
            return;
        }

        const now = Date.now();
        const rapidSwitch = now - this.lastTabSwitchTs < 220;
        this.lastTabSwitchTs = now;

        console.log('🔄 Changement d\'onglet vers:', normalizedTabId);
        this.currentTabId = normalizedTabId;
        const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches || rapidSwitch || Boolean(document.querySelector('.nomios-module-nav'));
        const resultsSection = document.getElementById('resultsSection');

        // Update tab buttons
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        const targetTab = document.querySelector(`.tab[data-tab="${normalizedTabId}"]`);
        if (targetTab) {
            const group = targetTab.closest('.nomios-nav-group');
            if (group) group.open = true;
            targetTab.classList.add('active');
            const reduceMotionTab = window.matchMedia('(prefers-reduced-motion: reduce)').matches || rapidSwitch;
            try {
                targetTab.scrollIntoView({
                    behavior: reduceMotionTab ? 'auto' : 'smooth',
                    block: 'nearest',
                    inline: 'center',
                });
            } catch (_) {
                // noop
            }
        }
        document.querySelectorAll('.tab').forEach((t) => {
            const selected = t === targetTab;
            t.setAttribute('aria-selected', selected ? 'true' : 'false');
            t.setAttribute('tabindex', selected ? '0' : '-1');
        });
        this.updateActiveTabPill();
        try {
            localStorage.setItem('pcap:last_tab', normalizedTabId);
        } catch (_) {
            // noop
        }
        try {
            const base = window.location.pathname + window.location.search;
            window.history.replaceState(null, '', `${base}#tab=${encodeURIComponent(normalizedTabId)}`);
        } catch (_) {
            // noop
        }
        this.renderMenuHealthCenter();

        const currentContent = document.querySelector('.tab-content.active');
        const targetContent = document.getElementById(`tab-${normalizedTabId}`);

        const activateTarget = () => {
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            if (targetContent) {
                targetContent.classList.add('active');
                targetContent.classList.remove('tab-transition-in', 'tab-transition-out');
                if (!reduceMotion) {
                    void targetContent.offsetWidth; // reflow to replay animation
                    targetContent.classList.add('tab-transition-in');
                }
            }
            this.triggerTabDataLoad(normalizedTabId);
            this.bindInteractiveSpotlights(targetContent || document);
            this.applyFocusInvestigation();
            this.requestChartsResize(2);
            if (targetContent && document.querySelector('.nomios-module-nav')) targetContent.scrollIntoView({block:'start',behavior:'auto'});
        };

        if (!reduceMotion && currentContent && targetContent && currentContent !== targetContent) {
            this.tabTransitionLock = true;
            resultsSection?.classList.add('cinematic-switching');
            currentContent.classList.remove('tab-transition-in');
            currentContent.classList.add('tab-transition-out');

            setTimeout(() => {
                currentContent.classList.remove('active', 'tab-transition-out');
                activateTarget();
                resultsSection?.classList.remove('cinematic-switching');
                this.tabTransitionLock = false;

                if (this.pendingTabId && this.pendingTabId !== normalizedTabId) {
                    const nextTab = this.pendingTabId;
                    this.pendingTabId = null;
                    this.switchTab(nextTab);
                } else {
                    this.pendingTabId = null;
                }
            }, 190);
            return;
        }

        activateTarget();
    }

    triggerTabDataLoad(tabId) {
        // Load data for tab if needed
        if (tabId === 'dns' && this.currentResults) {
            this.setMenuHealthStatus('dns', 'loading', 'Chargement DNS...');
            this.displayDnsResults(this.currentResults.dns_analysis || {});
        } else if (tabId === 'http' && this.currentResults) {
            this.setMenuHealthStatus('http', 'loading', 'Chargement HTTP/TLS...');
            this.displayHttpResults(this.currentResults.http_analysis || {});
        } else if (tabId === 'packets' && this.currentResults) {
            this.setMenuHealthStatus('packets', 'loading', 'Chargement paquets...');
            this.loadPackets();
        } else if (tabId === 'streams' && this.currentResults) {
            this.setMenuHealthStatus('streams', 'loading', 'Chargement streams...');
            this.loadStreams();
        } else if (tabId === 'multi-pcap') {
            this.setMenuHealthStatus('multi-pcap', this.multiPcapResults ? 'ok' : 'missing', this.multiPcapResults ? 'Résultats multi-PCAP disponibles' : 'Chargez plusieurs PCAP puis lancez la corrélation');
            this.renderMultiPcapCaptureTable();
            this.renderMultiPcapResults();
        } else if (tabId === 'timeline' && this.currentResults) {
            console.log('🕐 Chargement de la timeline...');
            this.setMenuHealthStatus('timeline', 'loading', 'Chargement timeline...');
            this.loadTimeline();
        } else if (['tls-audit', 'threat-intel', 'flow-behavior', 'lateral-movement', 'qos', 'tcp-health', 'playbook'].includes(tabId) && this.currentTaskId) {
            if (tabId !== 'playbook') {
                this.setMenuHealthStatus(tabId, 'loading', 'Chargement module...');
            } else {
                this.setMenuHealthStatus('playbook', 'idle', 'Lancez la génération du playbook');
            }
            if (typeof advOnTabActivated === 'function') {
                advOnTabActivated(tabId, this.currentTaskId);
            }
        }
    }

    // ==================== NAVIGATION ====================

    navigateTo(view, params = {}) {
        this.navigationStack.push(view);
        this.updateBreadcrumb();

        switch (view) {
            case 'overview':
                this.switchTab('overview');
                break;
            case 'ip-details':
                this.showIpDetails(params.ip);
                break;
            case 'session-details':
                this.showSessionDetails(params.sessionId);
                break;
            case 'packet-details':
                this.showPacketDetails(params.packetNum);
                break;
        }
    }

    updateBreadcrumb() {
        const nav = document.getElementById('breadcrumbNav');

        if (this.navigationStack.length > 1 && nav) {
            nav.style.display = 'block';
        } else if (nav) {
            nav.style.display = 'none';
        }
    }

    goBack() {
        if (this.navigationStack.length > 1) {
            this.navigationStack.pop();
            const previousView = this.navigationStack[this.navigationStack.length - 1];
            this.navigateTo(previousView);
        }
    }

    openMultiPcapMode() {
        const uploadSection = document.getElementById('uploadSection');
        const resultsSection = document.getElementById('resultsSection');
        if (uploadSection) uploadSection.style.display = 'none';
        if (resultsSection) resultsSection.style.display = 'block';
        this.setMenuHealthStatus('multi-pcap', this.multiPcapResults ? 'ok' : 'missing', this.multiPcapResults ? 'Résultats multi-PCAP disponibles' : 'Chargez plusieurs captures pour corréler');
        this.switchTab('multi-pcap');
    }

    // ==================== FILE UPLOAD ====================

    async uploadFile(file) {
        document.getElementById('uploadArea').style.display = 'none';
        document.getElementById('progressContainer').style.display = 'block';
        document.getElementById('progressFileName').textContent = file.name;
        document.getElementById('progressStatus').textContent = 'Envoi en cours...';
        document.getElementById('progressFill').style.width = '5%';

        this.showToast('info', 'Upload', `Envoi de ${file.name} en cours...`);

        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch('/api/upload', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Erreur lors de l\'upload');
            }

            const data = await response.json();
            this.currentTaskId = data.task_id;
            this.renderSignatures = { dns: '', http: '' };
            this.streamsLoadedKey = '';
            this.packetsLoadedTaskId = '';
            this.streamsData = [];
            this.allPackets = [];
            this.filteredPackets = [];
            this.packetIndex = { byProto: {}, byIp: {} };

            document.getElementById('progressFill').style.width = '20%';
            document.getElementById('progressStatus').textContent = 'Analyse en cours...';

            this.showToast('success', 'Upload réussi', 'Analyse du fichier en cours...');
            this.startStatusPolling();

        } catch (error) {
            console.error('Upload error:', error);
            this.showToast('error', 'Erreur Upload', error.message);
            this.showError(error.message);
            this.resetUploadArea();
        }
    }

    startStatusPolling() {
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
        }

        this.pollInterval = setInterval(async () => {
            // Stopper si l'analyse a été réinitialisée entre deux ticks
            if (!this.currentTaskId) {
                clearInterval(this.pollInterval);
                this.pollInterval = null;
                return;
            }
            try {
                const response = await fetch(`/api/status/${this.currentTaskId}`);
                const data = await response.json();

                this.updateProgress(data);

                if (data.status === 'completed') {
                    clearInterval(this.pollInterval);
                    this.pollInterval = null;
                    this.showToast('success', 'Analyse terminée', 'Les résultats sont prêts !');
                    this.loadResults();
                } else if (data.status === 'failed') {
                    clearInterval(this.pollInterval);
                    this.pollInterval = null;
                    this.showToast('error', 'Erreur', data.message || 'Erreur lors de l\'analyse');
                    this.showError(data.message || 'Erreur lors de l\'analyse');
                    this.resetUploadArea();
                }
            } catch (error) {
                console.error('Status polling error:', error);
            }
        }, 1000);
    }

    updateProgress(data) {
        const progressFill = document.getElementById('progressFill');
        const progressStatus = document.getElementById('progressStatus');

        if (data.progress) {
            progressFill.style.width = `${data.progress}%`;
        }

        if (data.message) {
            progressStatus.textContent = data.message;
        }

        if (data.status === 'completed') {
            progressFill.style.width = '100%';
            progressStatus.textContent = 'Analyse terminée!';
        }
    }

    async loadResults() {
        try {
            const response = await fetch(`/api/analysis/${this.currentTaskId}`);
            const results = await response.json();

            this.currentResults = results;

            document.getElementById('progressContainer').style.display = 'none';
            document.getElementById('resultsSection').style.display = 'block';

            this.displayResults(results);
            this.loadHistory();

            // A restored tab may already be selected before the capture is loaded.
            this.triggerTabDataLoad(this.currentTabId);

            // Double frame to let layout settle before chart resize
            this.requestChartsResize(2);

        } catch (error) {
            console.error('Error loading results:', error);
            this.showToast('error', 'Erreur', 'Erreur lors du chargement des résultats');
            this.showError('Erreur lors du chargement des résultats');
        }
    }

    // ==================== DISPLAY RESULTS ====================

    buildProtocolCountsFromPackets(packetsIndex = []) {
        const counts = {};
        (Array.isArray(packetsIndex) ? packetsIndex : []).slice(0, 120000).forEach((pkt) => {
            const proto = String(pkt?.protocol || 'UNKNOWN').toUpperCase();
            counts[proto] = (counts[proto] || 0) + 1;
        });
        return counts;
    }

    buildTopSourcesFromPackets(packetsIndex = [], limit = 10) {
        const map = {};
        (Array.isArray(packetsIndex) ? packetsIndex : []).slice(0, 120000).forEach((pkt) => {
            const ip = String(pkt?.src_ip || '').trim();
            if (!ip) return;
            map[ip] = (map[ip] || 0) + 1;
        });
        return Object.entries(map)
            .map(([ip, count]) => ({ ip, count }))
            .sort((a, b) => Number(b.count || 0) - Number(a.count || 0))
            .slice(0, limit);
    }

    buildFlagCountsFromPackets(packetsIndex = []) {
        const counts = {};
        (Array.isArray(packetsIndex) ? packetsIndex : []).slice(0, 120000).forEach((pkt) => {
            const raw = String(pkt?.flags || '').trim();
            if (!raw || raw === 'None') return;
            raw.split(/[,\s]+/).map(s => s.trim().toUpperCase()).filter(Boolean).forEach((flag) => {
                counts[flag] = (counts[flag] || 0) + 1;
            });
        });
        return counts;
    }

    buildAnomalyCounts(anomaly) {
        const byType = anomaly?.summary?.by_type && typeof anomaly.summary.by_type === 'object'
            ? { ...anomaly.summary.by_type }
            : {};
        if (Object.keys(byType).length) return byType;

        const anomalies = Array.isArray(anomaly?.anomalies) ? anomaly.anomalies : [];
        anomalies.forEach((item) => {
            const type = String(item?.type || 'UNKNOWN').trim();
            byType[type] = (byType[type] || 0) + 1;
        });
        return byType;
    }

    displayResults(results) {
        this.currentResults = results;
        this.renderSignatures = { dns: '', http: '' };
        this.streamsLoadedKey = '';
        this.packetsLoadedTaskId = '';
        this.allPackets = [];
        this.filteredPackets = [];
        this.packetIndex = { byProto: {}, byIp: {} };

        const protocol = results.protocol_analysis || {};
        const tcp = results.tcp_analysis || {};
        const anomaly = results.anomaly_detection || results.anomaly_analysis || {};
        const dns = results.dns_analysis || {};
        const http = results.http_analysis || {};

        const summary = protocol.summary || {};
        const tcpSummary = tcp.summary || {};
        const anomalySummary = anomaly.summary || {};
        const dnsSummary = dns.summary || {};
        const httpSummary = http.summary || {};
        const packetsIndex = Array.isArray(results?.packets_index) ? results.packets_index : [];

        // Summary cards
        this.animateCounter('totalPackets', summary.total_packets || 0);
        document.getElementById('totalBytes').textContent = summary.total_bytes_formatted || '0 B';
        this.animateCounter('tcpSessions', tcpSummary.total_sessions || 0);

        const riskLevel = anomalySummary.risk_level || 'NONE';
        document.getElementById('riskLevel').textContent = riskLevel;
        document.getElementById('anomalyCount').textContent = `${anomalySummary.total_anomalies || 0} anomalies`;
        document.getElementById('riskCard').setAttribute('data-risk', riskLevel);

        // DNS/HTTP cards
        this.animateCounter('dnsQueries', dnsSummary.total_queries || 0);
        this.animateCounter('httpRequests', httpSummary.total_requests || 0);
        this.animateCounter('tlsSessions', httpSummary.total_tls_sessions || 0);
        this.animateCounter('uniqueDomains', dnsSummary.unique_domains || 0);

        // Charts - Overview
        // Normalize protocols: backend returns {TCP: {count, bytes, ...}} — extract counts
        const rawProtocols = protocol.protocols || {};
        const normalizedProtocols = {};
        Object.entries(rawProtocols).forEach(([name, val]) => {
            normalizedProtocols[name] = typeof val === 'object'
                ? Number(val.count || val.packet_count || 0)
                : Number(val || 0);
        });
        const protocolCounts = Object.keys(normalizedProtocols).length
            ? normalizedProtocols
            : this.buildProtocolCountsFromPackets(packetsIndex);

        const rawIpStats = protocol.ip_statistics || {};
        const hasTopSources = Array.isArray(rawIpStats.top_sources) && rawIpStats.top_sources.length > 0;
        const ipStats = hasTopSources
            ? rawIpStats
            : { ...rawIpStats, top_sources: this.buildTopSourcesFromPackets(packetsIndex, 10) };

        const flagStats = (protocol.tcp_flags && typeof protocol.tcp_flags === 'object' && Object.keys(protocol.tcp_flags).length)
            ? protocol.tcp_flags
            : this.buildFlagCountsFromPackets(packetsIndex);

        const anomalyByType = this.buildAnomalyCounts(anomaly);

        this.createProtocolChart(protocolCounts);
        this.createFlagsChart(flagStats);
        this.createTopIpsChart(ipStats);
        this.createAnomaliesChart(anomalyByType);

        // Build time series from packets_index (backend has no dedicated time_series field)
        const timeSeries = this.buildTimeSeries(packetsIndex);
        this.createTrafficTimelineChart(timeSeries);
        this.createTemporalHeatmap(packetsIndex);
        this.createProtocolTreemap(protocolCounts, ipStats || {});
        this.createSankeyChart(ipStats || {}, protocolCounts);

        // Tables - Overview
        this.populateSessionsTable(tcp.sessions || []);
        this.populateAnomaliesTable(anomaly.anomalies || []);
        this.populateMacVendorsTable(protocol.mac_statistics || {});
        try {
            this.renderProblemSpotlight(results);
        } catch (spotlightError) {
            console.error('Problem spotlight render error:', spotlightError);
        }
        this.updateAnalysisMeta(results);
        document.dispatchEvent(new CustomEvent('pcap:analysis-loaded'));
        this.updateNetworkVisualStateFromResults(results);
        this.refreshMenuHealthFromResults(results);
        this.applyPremiumEntrance();
        this.applyFocusInvestigation();

        this.scheduleAutoQuestionnaire();
    }

    updateAnalysisMeta(results) {
        const label = document.getElementById('analysisMetaLabel');
        const signalPackets = document.getElementById('signalPackets');
        const signalRisk = document.getElementById('signalRisk');
        const signalDominantProto = document.getElementById('signalDominantProto');

        const metadata = results?.metadata || {};
        const protocol = results?.protocol_analysis || {};
        const anomaly = results?.anomaly_detection || results?.anomaly_analysis || {};
        const filename = metadata.filename || 'Capture PCAP';
        const rawTs = metadata.analysis_timestamp || metadata.generated_at;
        let timestamp = 'maintenant';

        if (rawTs) {
            const parsed = new Date(rawTs);
            timestamp = Number.isNaN(parsed.getTime()) ? String(rawTs) : parsed.toLocaleString('fr-FR');
        }

        if (label) {
            label.textContent = `${filename} • ${timestamp}`;
        }

        const totalPackets = protocol?.summary?.total_packets || 0;
        const riskLevel = anomaly?.summary?.risk_level || 'NONE';
        const topProto = this.getDominantProtocol(protocol.protocols || {});

        if (signalPackets) signalPackets.textContent = `Paquets: ${this.formatNumber(totalPackets)}`;
        if (signalRisk) signalRisk.textContent = `Risque: ${riskLevel}`;
        if (signalDominantProto) signalDominantProto.textContent = `Top protocole: ${topProto}`;
    }

    applyPremiumEntrance() {
        const section = document.getElementById('resultsSection');
        if (!section) return;

        section.classList.remove('premium-enter');
        void section.offsetWidth; // reflow
        section.classList.add('premium-enter');
        this.premiumEntrancePlayed = true;
    }

    getDominantProtocol(protocols) {
        if (!protocols || typeof protocols !== 'object') return 'N/A';
        let dominantName = 'N/A';
        let dominantCount = -1;

        Object.entries(protocols).forEach(([name, val]) => {
            const count = typeof val === 'object' ? (val.count || 0) : (val || 0);
            if (count > dominantCount) {
                dominantCount = count;
                dominantName = name;
            }
        });

        return dominantName;
    }

    getRiskIntensity(riskLevel) {
        const level = String(riskLevel || 'NONE').toUpperCase();
        if (level === 'CRITICAL') return 0.92;
        if (level === 'HIGH') return 0.72;
        if (level === 'MEDIUM') return 0.5;
        if (level === 'LOW') return 0.34;
        return 0.18;
    }

    updateNetworkVisualStateFromResults(results) {
        const anomaly = results?.anomaly_detection || results?.anomaly_analysis || {};
        const anomalySummary = anomaly?.summary || {};
        const tcpSummary = results?.tcp_analysis?.summary || {};
        const protocolSummary = results?.protocol_analysis?.summary || {};

        const riskLevel = String(anomalySummary.risk_level || 'NONE').toUpperCase();
        const anomalies = Number(anomalySummary.total_anomalies || 0);
        const totalPackets = Number(protocolSummary.total_packets || 0);
        const retransmissions = Number(
            tcpSummary.total_retransmissions
            || tcpSummary.retransmissions_total
            || tcpSummary.retransmissions
            || 0
        );

        const riskBase = this.getRiskIntensity(riskLevel);
        const anomalyBoost = Math.min(0.22, anomalies / 160);
        const retransBoost = totalPackets > 0 ? Math.min(0.18, (retransmissions / totalPackets) * 6) : 0;
        const intensity = Math.min(1, Math.max(0.1, riskBase + anomalyBoost + retransBoost));
        const burst = Math.min(0.95, Math.max(0.08, 0.1 + (anomalies / Math.max(1, totalPackets)) * 48 + riskBase * 0.35));

        this.networkVisualState = {
            ...this.networkVisualState,
            mode: 'single',
            riskLevel,
            anomalyCount: anomalies,
            intensity,
            burst,
            updatedAt: Date.now(),
        };
    }

    updateNetworkVisualStateFromMultiSummary(summary, riskLevel, problematic, sessions) {
        const safeSessions = Math.max(1, Number(sessions || 0));
        const problematicCount = Number(problematic || 0);
        const ratio = problematicCount / safeSessions;
        const riskBase = this.getRiskIntensity(riskLevel);
        const causeBoost = Array.isArray(summary?.top_causes) ? Math.min(0.14, summary.top_causes.length * 0.03) : 0;
        const intensity = Math.min(1, Math.max(0.1, riskBase + Math.min(0.35, ratio * 0.55) + causeBoost));
        const burst = Math.min(0.95, Math.max(0.08, 0.16 + ratio * 0.65 + riskBase * 0.22));

        this.networkVisualState = {
            ...this.networkVisualState,
            mode: 'multi',
            riskLevel: String(riskLevel || 'NONE').toUpperCase(),
            anomalyCount: problematicCount,
            intensity,
            burst,
            updatedAt: Date.now(),
        };
    }

    // ==================== AI INSIGHTS ====================

    async generateSpecificAI(type) {
        if (!this.currentTaskId) {
            this.showToast('warning', 'Pas d\'analyse', 'Veuillez d\'abord analyser un fichier PCAP');
            return;
        }

        const loader = document.getElementById('ai-loader');
        const results = document.getElementById('ai-results');
        const buttons = document.querySelectorAll('.ai-btn');

        // Disable buttons and show loader
        buttons.forEach(btn => btn.disabled = true);
        if (loader) loader.style.display = 'block';
        if (results) results.style.display = 'none';

        this.showToast('info', 'Analyse IA', `Génération de l'analyse ${type} en cours...`);

        try {
            const response = await fetch(`/api/analysis/${this.currentTaskId}/ai-insights`);
            const data = await response.json();

            if (loader) loader.style.display = 'none';
            if (results) {
                results.style.display = 'block';
                this.displayAIResults(data, type);
            }

            this.showToast('success', 'Analyse IA', 'Analyse terminée !');

        } catch (error) {
            console.error('AI analysis error:', error);
            if (loader) loader.style.display = 'none';
            this.showToast('error', 'Erreur IA', 'Erreur lors de l\'analyse IA');

            if (results) {
                results.style.display = 'block';
                results.innerHTML = `
                    <div class="ai-error">
                        <p>❌ Erreur lors de l'analyse IA</p>
                        <p>${this.escapeHtml(error.message)}</p>
                        <p>Vérifiez qu'Ollama est bien démarré avec: <code>ollama serve</code></p>
                    </div>
                `;
            }
        } finally {
            buttons.forEach(btn => btn.disabled = false);
        }
    }

    displayAIResults(data, type) {
        const container = document.getElementById('ai-results');
        if (!container) return;

        if (!data.ai_available) {
            container.innerHTML = `
                <div class="ai-error">
                    <h4>⚠️ Service IA non disponible</h4>
                    <p>Ollama n'est pas accessible. Démarrez-le avec:</p>
                    <code>OLLAMA_HOST=0.0.0.0:11434 ollama serve</code>
                </div>
            `;
            return;
        }

        const insights = data.insights || {};
        const insightsStructured = data.insights_structured || {};
        let html = `<div class="ai-results-content">`;

        if (type === 'full' || type === 'summary') {
            html += `
                <div class="ai-section">
                    <h4>📊 Résumé Exécutif</h4>
                    <div class="ai-content">${this.formatAIContent(insights.summary || 'Aucun résumé disponible')}</div>
                    ${this.renderAIStructuredTable(insightsStructured.summary, insights.summary || '')}
                </div>
            `;
        }

        if (type === 'full' || type === 'dns') {
            const dnsAnalysis = typeof insights.dns_analysis === 'string'
                ? insights.dns_analysis
                : JSON.stringify(insights.dns_analysis, null, 2);
            html += `
                <div class="ai-section">
                    <h4>🌐 Analyse DNS</h4>
                    <div class="ai-content">${this.formatAIContent(dnsAnalysis || 'Aucune donnée DNS')}</div>
                    ${this.renderAIStructuredTable(insightsStructured.dns_analysis, dnsAnalysis || '')}
                </div>
            `;
        }

        if (type === 'full' || type === 'http') {
            const httpAnalysis = typeof insights.http_analysis === 'string'
                ? insights.http_analysis
                : JSON.stringify(insights.http_analysis, null, 2);
            html += `
                <div class="ai-section">
                    <h4>🔗 Analyse HTTP/HTTPS</h4>
                    <div class="ai-content">${this.formatAIContent(httpAnalysis || 'Aucune donnée HTTP')}</div>
                    ${this.renderAIStructuredTable(insightsStructured.http_analysis, httpAnalysis || '')}
                </div>
            `;
        }

        if (type === 'full' || type === 'troubleshoot') {
            html += `
                <div class="ai-section">
                    <h4>🔧 Dépannage & Recommandations</h4>
                    <div class="ai-content">${this.formatAIContent(insights.troubleshooting || 'Aucune recommandation')}</div>
                    ${this.renderAIStructuredTable(insightsStructured.troubleshooting, insights.troubleshooting || '')}
                </div>
            `;
        }

        if (type === 'full') {
            const attackRaw = insights.attack_patterns_raw || '';
            const attackFallback = attackRaw || JSON.stringify(insights.attack_patterns || [], null, 2);
            html += `
                <div class="ai-section">
                    <h4>🎯 Coupables Probables (patterns)</h4>
                    <div class="ai-content">${this.formatAIContent(attackFallback || 'Aucun pattern détecté')}</div>
                    ${this.renderAIStructuredTable(insightsStructured.attack_patterns, attackFallback || '')}
                </div>
            `;
        }

        html += `
            <div class="ai-metadata">
                <span>🤖 Modèle: ${this.escapeHtml(data.model || 'N/A')}</span>
                <span>📅 Généré le: ${data.generated_at ? new Date(data.generated_at).toLocaleString('fr-FR') : 'N/A'}</span>
            </div>
        </div>`;

        container.innerHTML = html;
    }

    formatAIContent(content) {
        if (!content) return '<em>Aucun contenu</em>';

        return this.escapeHtml(content)
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/`(.*?)`/g, '<code>$1</code>')
            .replace(/### (.*?)(\n|$)/g, '<h5>$1</h5>')
            .replace(/## (.*?)(\n|$)/g, '<h4>$1</h4>')
            .replace(/# (.*?)(\n|$)/g, '<h3>$1</h3>')
            .replace(/- (.*?)(\n|$)/g, '<li>$1</li>')
            .replace(/\n\n/g, '</p><p>')
            .replace(/\n/g, '<br>');
    }

    // ==================== TIMELINE ====================

    async loadTimeline(filters = {}) {
        if (!this.currentTaskId) {
            console.error('❌ Pas de task_id');
            return;
        }

        console.log('🕐 Chargement de la timeline...', filters);

        let url = `/api/analysis/${this.currentTaskId}/timeline?`;

        if (filters.startTime) url += `start_time=${filters.startTime}&`;
        if (filters.endTime) url += `end_time=${filters.endTime}&`;
        if (filters.protocols && filters.protocols.length > 0) {
            url += `protocols=${filters.protocols.join(',')}&`;
        }
        if (filters.minSize) url += `min_packet_size=${filters.minSize}&`;
        if (filters.maxSize) url += `max_packet_size=${filters.maxSize}&`;

        try {
            const response = await fetch(url);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const data = await response.json();
            console.log('✅ Réponse timeline:', data);

            let timelineData = data.timeline || data;

            if (!timelineData.events || timelineData.events.length === 0) {
                const fallbackTimeline = this.buildTimelineFromPacketsIndex(this.currentResults?.packets_index || []);
                if (fallbackTimeline.events.length > 0) {
                    this.displayTimeline(fallbackTimeline);
                    this.displayTimelineStats(fallbackTimeline.summary || {});
                    return;
                }

                const container = document.getElementById('timelineVis');
                if (container) {
                    container.innerHTML = '<div style="padding: 2rem; text-align: center; color: var(--text-secondary);">Aucun événement à afficher</div>';
                }
                this.displayTimelineStats(timelineData.summary || {});
                return;
            }

            this.displayTimeline(timelineData);
            this.displayTimelineStats(timelineData.summary || {});

        } catch (error) {
            console.error('❌ Erreur timeline:', error);
            const fallbackTimeline = this.buildTimelineFromPacketsIndex(this.currentResults?.packets_index || []);
            if (fallbackTimeline.events.length > 0) {
                this.displayTimeline(fallbackTimeline);
                this.displayTimelineStats(fallbackTimeline.summary || {});
                this.showToast('info', 'Timeline', 'Timeline générée depuis les paquets indexés (fallback)');
                return;
            }

            const container = document.getElementById('timelineVis');
            if (container) {
                container.innerHTML = `
                    <div style="padding: 2rem; text-align: center;">
                        <p style="color: var(--danger);">❌ Erreur lors du chargement</p>
                        <p style="color: var(--text-secondary);">${error.message}</p>
                        <button class="btn btn-primary" onclick="analyzer.loadTimeline()" style="margin-top: 1rem;">🔄 Réessayer</button>
                    </div>
                `;
            }
        }
    }

    displayTimeline(timelineData) {
        const container = document.getElementById('timelineVis');
        if (!container) return;
        if (this.timeline) {
            this.timeline.destroy();
            this.timeline = null;
        }

        if (!timelineData?.events?.length) {
            container.innerHTML = '<div style="padding: 2rem; text-align: center;">Aucun événement</div>';
            return;
        }

        if (typeof vis === 'undefined' || !vis.Timeline || !vis.DataSet) {
            container.innerHTML = '<div style="padding: 2rem; text-align: center; color: var(--warning);">Timeline non disponible (bibliothèque vis.js non chargée)</div>';
            return;
        }

        const items = new vis.DataSet();
        const groups = new vis.DataSet([
            { id: 'TCP', content: '🔵 TCP' },
            { id: 'UDP', content: '🟢 UDP' },
            { id: 'DNS', content: '🔷 DNS' },
            { id: 'HTTP', content: '🟣 HTTP' },
            { id: 'HTTPS', content: '🔒 HTTPS' },
            { id: 'OTHER', content: '⚪ Autres' }
        ]);

        const baseTime = timelineData.time_range?.start || Date.now() / 1000;

        timelineData.events.forEach((event, index) => {
            let group = event.protocol || 'OTHER';
            let eventTime = event.timestamp > 0 ? new Date(event.timestamp * 1000) : new Date((baseTime + index * 0.1) * 1000);

            items.add({
                id: index,
                group: group,
                start: eventTime,
                content: `${event.src?.split('.').slice(-1)} → ${event.dst?.split('.').slice(-1)}`,
                title: `Paquet #${event.packet_num}<br>Source: ${event.src}<br>Dest: ${event.dst}<br>Taille: ${event.length} bytes`
            });
        });

        const colors = this.getThemeColors();
        const options = {
            width: '100%',
            height: '450px',
            stack: true,
            showMajorLabels: true,
            showCurrentTime: false,
            zoomMin: 1000,
            zoomMax: 1000 * 60 * 60 * 24,
            orientation: 'top',
            margin: { item: 10, axis: 5 }
        };

        this.timeline = new vis.Timeline(container, items, groups, options);
    }

    displayTimelineStats(summary) {
        const duration = document.getElementById('timelineDuration');
        const pps = document.getElementById('timelinePacketsPerSec');
        const peak = document.getElementById('timelinePeakTime');
        const total = document.getElementById('timelineTotalEvents');

        if (duration) {
            const d = Number(summary.duration_seconds ?? summary.duration ?? 0);
            duration.textContent = Number.isFinite(d) ? `${d.toFixed(2)}s` : '-';
        }
        if (pps) {
            const rate = Number(summary.packets_per_second ?? 0);
            pps.textContent = Number.isFinite(rate) ? rate.toFixed(2) : '-';
        }
        if (peak) {
            const p = Number(summary.peak_time ?? 0);
            peak.textContent = p > 0 ? new Date(p * 1000).toLocaleTimeString() : '-';
        }
        if (total) {
            const t = summary.total_events ?? summary.total_packets ?? 0;
            total.textContent = this.formatNumber(Number(t) || 0);
        }
    }

    buildTimelineFromPacketsIndex(packets) {
        if (!Array.isArray(packets) || !packets.length) {
            return { events: [], summary: {}, time_range: {} };
        }

        const events = [];
        let startTs = null;
        let endTs = null;

        packets.slice(0, 2000).forEach((pkt, idx) => {
            const ts = Number(pkt.timestamp || 0);
            if (ts > 0) {
                if (startTs === null || ts < startTs) startTs = ts;
                if (endTs === null || ts > endTs) endTs = ts;
            }

            events.push({
                packet_num: pkt.packet_num ?? pkt.idx ?? idx + 1,
                timestamp: ts,
                src: pkt.src_ip || pkt.source || 'N/A',
                dst: pkt.dst_ip || pkt.destination || 'N/A',
                protocol: pkt.protocol || 'OTHER',
                length: pkt.length || pkt.len || 0,
                info: pkt.info || ''
            });
        });

        const duration = startTs !== null && endTs !== null ? Math.max(0, endTs - startTs) : 0;
        const pps = duration > 0 ? events.length / duration : 0;

        return {
            events,
            summary: {
                total_events: events.length,
                duration_seconds: duration,
                packets_per_second: pps,
                peak_time: startTs || 0
            },
            time_range: {
                start: startTs || 0,
                end: endTs || 0
            }
        };
    }

    toggleTimelinePlayback() {
        if (!this.timeline) {
            this.showToast('warning', 'Timeline', 'Aucune timeline chargée');
            return;
        }

        const btn = document.getElementById('timelinePlayBtn');
        if (this.timelinePlayback) {
            clearInterval(this.timelinePlayback);
            this.timelinePlayback = null;
            if (btn) btn.textContent = '▶️';
            return;
        }

        if (btn) btn.textContent = '⏸️';
        this.timelinePlayback = setInterval(() => {
            try {
                this.timeline.fit({ animation: { duration: 350, easingFunction: 'easeInOutQuad' } });
            } catch (_) {
                clearInterval(this.timelinePlayback);
                this.timelinePlayback = null;
                if (btn) btn.textContent = '▶️';
            }
        }, 1200);
    }

    // ==================== STREAMS ====================

    readStreamFilters() {
        const ipFilterEl = document.getElementById('streamIpFilter');
        const typeFilterEl = document.getElementById('streamTypeFilter');
        const sortByEl = document.getElementById('streamSortBy');
        const pageSizeEl = document.getElementById('streamPageSize');
        const problematicOnlyEl = document.getElementById('streamProblematicOnly');

        const pageSize = Math.max(1, parseInt(pageSizeEl?.value || String(this.streamLimit || 100), 10) || 100);
        this.streamLimit = pageSize;

        return {
            ip: String(ipFilterEl?.value || '').trim(),
            type: String(typeFilterEl?.value || '').trim(),
            sortBy: String(sortByEl?.value || 'risk').trim(),
            sortOrder: 'desc',
            offset: this.streamOffset,
            limit: pageSize,
            problematicOnly: Boolean(problematicOnlyEl?.checked),
        };
    }

    buildStreamsRequestKey(filters) {
        const f = filters || this.readStreamFilters();
        const drill = this.globalDrilldownFilter || {};
        return [
            this.currentTaskId || '',
            String(f.type || ''),
            String(f.ip || '').toLowerCase(),
            String(f.sortBy || 'risk'),
            String(f.sortOrder || 'desc'),
            Number(f.offset || 0),
            Number(f.limit || this.streamLimit || 100),
            f.problematicOnly ? '1' : '0',
            String(drill.query || '').toLowerCase(),
            String(drill.protocol || '').toUpperCase(),
            Number(drill.riskMin || 0),
        ].join('|');
    }

    splitHostPort(endpoint) {
        const raw = String(endpoint || '');
        const idx = raw.lastIndexOf(':');
        if (idx <= 0) return { ip: raw, port: '' };
        return { ip: raw.slice(0, idx), port: raw.slice(idx + 1) };
    }

    inferStreamType(stream) {
        const dstPort = Number(stream.dst_port || 0);
        if (stream.is_https || [443, 8443].includes(dstPort)) return 'HTTPS';
        if (stream.is_http || [80, 8080, 8000].includes(dstPort)) return 'HTTP';
        if ([53].includes(dstPort)) return 'DNS';
        if ([22].includes(dstPort)) return 'SSH';
        if ([445].includes(dstPort)) return 'SMB';
        if ([3389].includes(dstPort)) return 'RDP';
        if ([389, 636].includes(dstPort)) return 'LDAP';
        if ([25, 465, 587].includes(dstPort)) return 'SMTP';
        return 'TCP';
    }

    getStreamRiskScore(stream) {
        const packets = Number(stream.packet_count || 0);
        const retransmissions = Number(stream.retransmissions || 0);
        const rstCount = Number(stream.rst_count || 0);
        const state = String(stream.state || '').toUpperCase();

        let score = 0;
        if (rstCount > 0) score += Math.min(65, rstCount * 14);
        if (retransmissions > 0) {
            const retransRatioPercent = (retransmissions / Math.max(1, packets)) * 100;
            score += Math.min(45, Math.round(retransRatioPercent * 3.5));
        }
        if (['SYN_SENT', 'SYN_RECV', 'LAST_ACK', 'CLOSE_WAIT'].includes(state)) score += 15;
        if (state && !['ESTABLISHED', 'CLOSED', 'FIN_WAIT', 'TIME_WAIT'].includes(state)) score += 10;

        return Math.min(100, score);
    }

    getStreamRiskLevel(score) {
        if (score >= 70) return 'HIGH';
        if (score >= 35) return 'MEDIUM';
        if (score > 0) return 'LOW';
        return 'NONE';
    }

    inferProbableCause(stream) {
        const state = String(stream.state || '').toUpperCase();
        const packets = Number(stream.packet_count || 0);
        const retrans = Number(stream.retransmissions || 0);
        const rst = Number(stream.rst_count || 0);
        const syn = Number(stream.syn_count || 0);
        const ack = Number(stream.ack_count || 0);
        const retransRatio = retrans / Math.max(1, packets);

        if (rst >= 2) {
            return 'Reset pair (fermeture distante)';
        }
        if (state === 'SYN_SENT' || state === 'SYN_RECV' || (syn > 0 && ack === 0)) {
            return 'Half-open (handshake incomplet)';
        }
        if (retransRatio >= 0.08 && packets >= 30) {
            return 'Congestion probable (retrans élevée)';
        }
        if (retransRatio >= 0.02 && retrans > 0) {
            return 'Perte paquets probable';
        }
        if (state === 'ESTABLISHED' && retrans === 0 && rst === 0) {
            return 'Flux stable';
        }
        return 'À surveiller';
    }

    getCauseCodeFromLabel(label) {
        const text = String(label || '').toLowerCase();
        if (text.includes('reset')) return 'reset-pair';
        if (text.includes('half-open') || text.includes('handshake')) return 'half-open';
        if (text.includes('congestion')) return 'congestion';
        if (text.includes('perte')) return 'loss';
        if (text.includes('stable')) return 'stable';
        return 'watch';
    }

    getCauseBadgeClass(code) {
        const normalized = this.sanitizeClassToken(code || 'watch');
        return `cause-badge ${normalized || 'watch'}`;
    }

    normalizeStreamEntry(raw, idx) {
        const srcRaw = raw.src || '';
        const dstRaw = raw.dst || '';
        const src = this.splitHostPort(srcRaw);
        const dst = this.splitHostPort(dstRaw);

        const stream = {
            stream_id: Number.isFinite(Number(raw.stream_id)) ? Number(raw.stream_id) : idx,
            src_ip: raw.src_ip || src.ip || '-',
            src_port: raw.src_port || src.port || '-',
            dst_ip: raw.dst_ip || dst.ip || '-',
            dst_port: raw.dst_port || dst.port || '-',
            packet_count: Number(raw.packet_count ?? raw.packets ?? 0) || 0,
            total_bytes: Number(raw.total_bytes ?? raw.bytes ?? 0) || 0,
            state: raw.state || 'UNKNOWN',
            retransmissions: Number(raw.retransmissions || 0) || 0,
            rst_count: Number(raw.rst_count || 0) || 0,
            syn_count: Number(raw.syn_count || 0) || 0,
            ack_count: Number(raw.ack_count || 0) || 0,
            is_http: Boolean(raw.is_http),
            is_https: Boolean(raw.is_https),
            is_tls: Boolean(raw.is_tls),
            stream_identifier: raw.stream_identifier || '',
            probable_cause: raw.probable_cause || '',
            probable_cause_code: raw.probable_cause_code || '',
            cause_details: raw.cause_details || '',
        };

        stream.type = this.inferStreamType(stream);
        stream.risk_score = this.getStreamRiskScore(stream);
        stream.risk_level = this.getStreamRiskLevel(stream.risk_score);
        if (!stream.probable_cause) {
            stream.probable_cause = this.inferProbableCause(stream);
        }
        if (!stream.probable_cause_code) {
            stream.probable_cause_code = this.getCauseCodeFromLabel(stream.probable_cause);
        }
        stream.src_endpoint = `${stream.src_ip}:${stream.src_port}`;
        stream.dst_endpoint = `${stream.dst_ip}:${stream.dst_port}`;
        return stream;
    }

    sortStreams(streams, sortBy) {
        const rows = [...streams];
        if (sortBy === 'packets') {
            rows.sort((a, b) => b.packet_count - a.packet_count);
        } else if (sortBy === 'retrans') {
            rows.sort((a, b) => b.retransmissions - a.retransmissions || b.packet_count - a.packet_count);
        } else if (sortBy === 'bytes') {
            rows.sort((a, b) => b.total_bytes - a.total_bytes || b.packet_count - a.packet_count);
        } else if (sortBy === 'rst') {
            rows.sort((a, b) => b.rst_count - a.rst_count || b.risk_score - a.risk_score);
        } else {
            rows.sort((a, b) => b.risk_score - a.risk_score || b.packet_count - a.packet_count);
        }
        return rows;
    }

    applyStreamsLocalFilters(streams, filters) {
        let rows = [...streams];
        if (filters.type === 'http') rows = rows.filter(s => s.type === 'HTTP');
        if (filters.type === 'https') rows = rows.filter(s => s.type === 'HTTPS');
        if (filters.ip) rows = rows.filter(s => s.src_ip.includes(filters.ip) || s.dst_ip.includes(filters.ip));
        if (filters.problematicOnly) {
            rows = rows.filter(s => s.risk_level !== 'NONE');
        }
        return this.sortStreams(rows, filters.sortBy);
    }

    formatBytesShort(bytes) {
        const n = Number(bytes || 0);
        if (n >= 1024 * 1024 * 1024) return `${(n / (1024 * 1024 * 1024)).toFixed(1)} GB`;
        if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
        if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
        return `${n} B`;
    }

    updateStreamsMetrics(displayed, totalFromApi) {
        const countEl = document.getElementById('streamsCount');
        const suspiciousEl = document.getElementById('streamsSuspiciousCount');
        const retransEl = document.getElementById('streamsRetransTotal');
        const rstEl = document.getElementById('streamsRstTotal');
        const totalLabel = document.getElementById('streamsTotalLabel');

        const suspiciousCount = displayed.filter(s => s.risk_level !== 'NONE').length;
        const retransTotal = displayed.reduce((acc, s) => acc + (s.retransmissions || 0), 0);
        const rstTotal = displayed.reduce((acc, s) => acc + (s.rst_count || 0), 0);

        if (countEl) countEl.textContent = displayed.length.toLocaleString('fr-FR');
        if (suspiciousEl) suspiciousEl.textContent = suspiciousCount.toLocaleString('fr-FR');
        if (retransEl) retransEl.textContent = retransTotal.toLocaleString('fr-FR');
        if (rstEl) rstEl.textContent = rstTotal.toLocaleString('fr-FR');
        if (totalLabel) {
            const total = Number(totalFromApi || 0);
            totalLabel.textContent = total > 0
                ? `(affichés: ${displayed.length.toLocaleString('fr-FR')} / ${total.toLocaleString('fr-FR')})`
                : '';
        }
    }

    updateStreamsPaginationControls(total, offset, limit) {
        const prevBtn = document.getElementById('streamPrevBtn');
        const nextBtn = document.getElementById('streamNextBtn');
        const pageInfo = document.getElementById('streamPageInfo');
        const safeTotal = Math.max(0, Number(total || 0));
        const safeOffset = Math.max(0, Number(offset || 0));
        const safeLimit = Math.max(1, Number(limit || 100));
        const currentPage = safeTotal > 0 ? Math.floor(safeOffset / safeLimit) + 1 : 1;
        const totalPages = Math.max(1, Math.ceil(safeTotal / safeLimit));

        if (pageInfo) {
            pageInfo.textContent = `Page ${currentPage}/${totalPages}`;
        }
        if (prevBtn) prevBtn.disabled = safeOffset <= 0;
        if (nextBtn) nextBtn.disabled = safeOffset + safeLimit >= safeTotal;
    }

    renderStreamsTableRows(rows) {
        const tbody = document.querySelector('#streamsTable tbody');
        if (!tbody) return;

        if (!rows.length) {
            tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--text-tertiary);padding:1rem;">Aucun stream trouvé avec ces filtres.</td></tr>';
            return;
        }

        tbody.innerHTML = rows.map(stream => `
            <tr>
                <td class="stream-id">#${stream.stream_id}</td>
                <td class="stream-endpoints"><div><span class="endpoint-label">SRC</span><code>${this.escapeHtml(stream.src_endpoint)}</code></div><div><span class="endpoint-label">DST</span><code>${this.escapeHtml(stream.dst_endpoint)}</code></div></td>
                <td class="stream-traffic"><strong>${stream.packet_count.toLocaleString('fr-FR')} <small>paquets</small></strong><span>${this.formatBytesShort(stream.total_bytes)}</span></td>
                <td class="stream-connection"><span class="protocol-badge ${this.sanitizeClassToken(stream.type)}">${this.escapeHtml(stream.type)}</span><span class="state-badge ${this.sanitizeClassToken(stream.state || '')}">${this.escapeHtml(stream.state || '-')}</span></td>
                <td class="stream-number">${stream.retransmissions.toLocaleString('fr-FR')}</td>
                <td class="stream-number">${stream.rst_count.toLocaleString('fr-FR')}</td>
                <td><span class="risk-badge ${this.sanitizeClassToken(stream.risk_level)}">${this.escapeHtml(stream.risk_level)}</span></td>
                <td class="stream-cause" title="${this.escapeHtml(stream.cause_details || stream.probable_cause || '-')}"><span class="${this.getCauseBadgeClass(stream.probable_cause_code)}">${this.escapeHtml(stream.probable_cause || '-')}</span></td>
                <td class="stream-actions"><div><button class="action-btn view" onclick='analyzer.showStreamDetails(${stream.stream_id}, ${this.escapeHtml(JSON.stringify(stream.stream_identifier || ""))})' aria-label="Détails du flux ${stream.stream_id}">Ouvrir <span aria-hidden="true">↗</span></button><button class="action-btn view stream-ip-action" onclick='analyzer.showIpSessionModal(${this.escapeHtml(JSON.stringify(stream.src_ip))}, ${stream.stream_id})' aria-label="Sessions IP du flux ${stream.stream_id}">IP</button></div></td>
            </tr>
        `).join('');
    }

    buildFallbackStreamsFromResults() {
        const sessions = this.currentResults?.tcp_analysis?.sessions || [];
        return sessions.map((session, idx) => {
            const src = this.splitHostPort(session.src || '');
            const dst = this.splitHostPort(session.dst || '');
            const streamIdentifier = src.ip && src.port && dst.ip && dst.port
                ? `${src.ip}:${src.port}:${dst.ip}:${dst.port}`
                : '';
            return this.normalizeStreamEntry({
            stream_id: idx,
            src: session.src,
            dst: session.dst,
            packets: session.packets,
            bytes: session.bytes,
            state: session.state,
            retransmissions: session.retransmissions,
            rst_count: session.rst_count,
            syn_count: session?.flags?.syn || 0,
            ack_count: session?.flags?.ack || 0,
            stream_identifier: streamIdentifier,
        }, idx);
        });
    }

    async loadStreams(forceRefresh = false) {
        if (!this.currentTaskId) return;

        const tbody = document.querySelector('#streamsTable tbody');
        if (!tbody) return;

        const filters = this.readStreamFilters();
        const requestKey = this.buildStreamsRequestKey(filters);
        if (!forceRefresh && this.streamsLoadedKey === requestKey) {
            this.renderStreamsTableRows(Array.isArray(this.streamsData) ? this.streamsData : []);
            this.updateStreamsMetrics(this.streamsData || [], this.streamTotal || 0);
            this.updateStreamsPaginationControls(this.streamTotal || 0, this.streamOffset, this.streamLimit);
            const msg = this.streamTotal > 0
                ? `${this.streamTotal.toLocaleString('fr-FR')} flux en cache`
                : 'Aucun flux (cache)';
            this.setMenuHealthStatus('streams', this.streamTotal > 0 ? 'ok' : 'missing', msg);
            return;
        }
        tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--text-tertiary);padding:1rem;">Chargement des streams...</td></tr>';

        try {
            const params = new URLSearchParams();
            if (filters.type === 'http' || filters.type === 'https') params.set('type', filters.type);
            if (filters.ip) params.set('ip', filters.ip);
            params.set('offset', String(filters.offset));
            params.set('limit', String(filters.limit));
            params.set('sort_by', filters.sortBy);
            params.set('sort_order', filters.sortOrder);
            if (filters.problematicOnly) params.set('problematic_only', 'true');
            if (forceRefresh) params.set('_ts', String(Date.now()));

            const query = params.toString();
            const url = `/api/analysis/${this.currentTaskId}/streams${query ? `?${query}` : ''}`;
            const response = await fetch(url, { cache: 'no-store' });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);

            const data = await response.json();
            const apiStreams = Array.isArray(data.streams) ? data.streams : [];
            const normalized = apiStreams.map((stream, idx) => this.normalizeStreamEntry(stream, idx));
            const displayed = normalized;

            this.streamsData = displayed;
            this.streamTotal = Number(data.total || 0);
            this.streamOffset = Number(data.offset || filters.offset || 0);
            this.streamLimit = Number(data.limit || filters.limit || this.streamLimit);
            this.streamsLoadedKey = requestKey;
            this.renderStreamsTableRows(displayed);
            this.updateStreamsMetrics(displayed, this.streamTotal || normalized.length);
            this.updateStreamsPaginationControls(this.streamTotal || normalized.length, this.streamOffset, this.streamLimit);
            this.setMenuHealthStatus('streams', this.streamTotal > 0 ? 'ok' : 'missing', this.streamTotal > 0 ? `${this.streamTotal.toLocaleString('fr-FR')} streams` : 'Aucun stream');
        } catch (error) {
            console.error('Streams API error:', error);

            const fallback = this.buildFallbackStreamsFromResults();
            if (!fallback.length) {
                tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;color:var(--danger);padding:1rem;">Erreur de chargement des streams: ${this.escapeHtml(error.message)}</td></tr>`;
                this.updateStreamsMetrics([], 0);
                this.updateStreamsPaginationControls(0, 0, this.streamLimit);
                this.streamsLoadedKey = '';
                this.setMenuHealthStatus('streams', 'error', `Erreur streams: ${error.message}`);
                return;
            }

            const filtered = this.applyStreamsLocalFilters(fallback, filters);
            const total = filtered.length;
            if (this.streamOffset >= total && total > 0) {
                this.streamOffset = Math.max(0, Math.floor((total - 1) / this.streamLimit) * this.streamLimit);
            }
            const displayed = filtered.slice(this.streamOffset, this.streamOffset + this.streamLimit);

            this.streamsData = displayed;
            this.streamTotal = total;
            this.streamsLoadedKey = requestKey;
            this.renderStreamsTableRows(displayed);
            this.updateStreamsMetrics(displayed, total);
            this.updateStreamsPaginationControls(total, this.streamOffset, this.streamLimit);
            this.setMenuHealthStatus('streams', total > 0 ? 'fallback' : 'missing', total > 0 ? `Fallback local (${total.toLocaleString('fr-FR')} flux)` : 'Fallback local sans flux');
            this.showToast('warning', 'Streams', 'Mode fallback local activé (API streams indisponible)');
        }
    }

    async exportProblematicStreamsCsv() {
        if (!this.currentTaskId) {
            this.showToast('warning', 'Streams', 'Aucune analyse en cours');
            return;
        }

        const filters = this.readStreamFilters();
        const params = new URLSearchParams();
        if (filters.type === 'http' || filters.type === 'https') params.set('type', filters.type);
        if (filters.ip) params.set('ip', filters.ip);
        params.set('sort_by', filters.sortBy);
        params.set('sort_order', filters.sortOrder);
        params.set('problematic_only', 'true');

        try {
            const url = `/api/analysis/${this.currentTaskId}/streams/export/csv?${params.toString()}`;
            const response = await fetch(url, { cache: 'no-store' });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);

            const blob = await response.blob();
            const downloadUrl = URL.createObjectURL(blob);
            const link = document.createElement('a');
            const ts = new Date().toISOString().replace(/[:.]/g, '-');
            link.href = downloadUrl;
            link.download = `streams_problematiques_${this.currentTaskId.slice(0, 8)}_${ts}.csv`;
            document.body.appendChild(link);
            link.click();
            link.remove();
            URL.revokeObjectURL(downloadUrl);
            this.showToast('success', 'Streams', 'Export CSV des flux problématiques terminé');
        } catch (error) {
            console.error('Export problematic streams CSV error:', error);
            this.showToast('error', 'Streams', `Échec export CSV: ${error.message}`);
        }
    }

    async showStreamDetails(streamId, streamIdentifier = '') {
        if (!this.currentTaskId) return;

        this.showToast('info', 'Chargement', 'Récupération des détails du stream...');

        try {
            const urls = [];
            if (streamIdentifier) {
                urls.push(`/api/analysis/${this.currentTaskId}/stream/tcp/${encodeURIComponent(streamIdentifier)}`);
            }
            urls.push(`/api/analysis/${this.currentTaskId}/stream/${streamId}`);

            let data = null;
            let lastError = null;
            for (const url of urls) {
                try {
                    const response = await fetch(url, { cache: 'no-store' });
                    if (!response.ok) throw new Error(`HTTP ${response.status}`);
                    data = await response.json();
                    break;
                } catch (e) {
                    lastError = e;
                }
            }
            if (!data) {
                throw lastError || new Error('Stream indisponible');
            }

            const container = document.getElementById('streamDetailContainer');
            const idSpan = document.getElementById('streamDetailId');
            const conversation = document.getElementById('streamConversation');

            if (container) {
                container.style.display = 'block';
                try {
                    container.scrollIntoView({ behavior: 'smooth', block: 'start' });
                } catch (_) { /* no-op */ }
            }
            if (idSpan) idSpan.textContent = `#${streamId}`;

            if (conversation) {
                const streamInfo = data.stream_info || {
                    src_ip: data.src_ip,
                    src_port: data.src_port,
                    dst_ip: data.dst_ip,
                    dst_port: data.dst_port,
                    packet_count: data.packet_count,
                    state: data.state || 'UNKNOWN',
                    retransmissions: data.retransmissions || 0,
                    duration: data.duration,
                };
                const packets = Array.isArray(data.packets) ? data.packets : [];

                let html = `
                    <div class="stream-info" style="margin-bottom: 1rem; padding: 1rem; background: var(--bg-tertiary); border-radius: var(--radius-md);">
                        <strong>Source:</strong> ${this.escapeHtml(streamInfo.src_ip || '?')}:${this.escapeHtml(streamInfo.src_port || '?')} →
                        <strong>Destination:</strong> ${this.escapeHtml(streamInfo.dst_ip || '?')}:${this.escapeHtml(streamInfo.dst_port || '?')}
                        <br><strong>Paquets:</strong> ${streamInfo.packet_count || packets.length || 0}
                        <strong>État:</strong> <span class="state-badge ${this.sanitizeClassToken(streamInfo.state || '')}">${this.escapeHtml(streamInfo.state || 'UNKNOWN')}</span>
                        <strong>Retransmissions:</strong> ${streamInfo.retransmissions || 0}
                        ${streamInfo.duration ? `<strong>Durée:</strong> ${this.escapeHtml(String(streamInfo.duration))}s` : ''}
                    </div>`;

                if (packets.length > 0) {
                    html += `<div class="stream-conversation">${packets.map(pkt => `
                        <div class="stream-segment ${pkt.direction === 'client_to_server' || pkt.direction === 'client' ? 'client' : 'server'}">
                            <div class="stream-segment-header">
                                <span>${pkt.direction === 'client_to_server' || pkt.direction === 'client' ? '→ Client' : '← Server'}</span>
                                <span>${this.escapeHtml(pkt.flags || '-')} | ${pkt.payload_len || pkt.payload_size || 0} bytes</span>
                            </div>
                            <pre>${this.escapeHtml(pkt.payload || pkt.data || '(payload non disponible)')}</pre>
                        </div>
                    `).join('')}</div>`;
                } else {
                    html += `<div style="text-align: center; padding: 2rem; color: var(--text-tertiary);">
                        <p>📦 Aucun paquet extrait pour ce stream.</p>
                        <p style="font-size: 0.85rem;">Le fichier PCAP original peut ne plus être disponible sur le serveur.</p>
                    </div>`;
                }

                conversation.innerHTML = html;
            }

            this.showToast('success', 'Stream', `Détails du stream #${streamId} chargés`);

        } catch (error) {
            console.error('Stream details error:', error);
            this.showToast('error', 'Erreur', `Impossible de charger les détails du stream: ${error.message}`);

            // Show error in stream detail container
            const conversation = document.getElementById('streamConversation');
            if (conversation) {
                conversation.innerHTML = `<div style="text-align: center; padding: 2rem; color: var(--danger);">
                    <p>❌ Erreur lors du chargement du stream</p>
                    <p style="font-size: 0.85rem;">${error.message}</p>
                </div>`;
            }
            const container = document.getElementById('streamDetailContainer');
            if (container) container.style.display = 'block';
        }
    }

    // ==================== MULTI-PCAP ====================

    addMultiPcapFiles(files) {
        const accepted = files.filter((file) => /\.(pcap|pcapng|cap)$/i.test(file?.name || ''));
        if (!accepted.length) {
            this.showToast('warning', 'Multi-PCAP', 'Aucun fichier valide (.pcap/.pcapng/.cap)');
            return;
        }

        const existingIds = new Set(this.multiPcapFiles.map((f) => f.id));
        accepted.forEach((file) => {
            const id = `${file.name}::${file.size}::${file.lastModified}`;
            if (existingIds.has(id)) return;
            this.multiPcapFiles.push({
                id,
                file,
                filename: file.name,
                size: Number(file.size || 0),
                // Nom déduit du fichier: « 2_FW_DMZ.pcap » -> « FW_DMZ ».
                // Bien plus parlant qu'un « Point N » générique dans les
                // verdicts de chaîne, et l'utilisateur reste libre de l'éditer.
                equipment_name: this.guessEquipmentName(file.name, this.multiPcapFiles.length + 1),
                position: this.multiPcapFiles.length + 1,
                comment: '',
            });
            existingIds.add(id);
        });

        this.normalizeMultiPcapPositions();
        this.renderMultiPcapCaptureTable();
        this.showToast('success', 'Multi-PCAP', `${accepted.length} fichier(s) ajouté(s)`);
    }

    guessEquipmentName(filename, fallbackIndex) {
        // « 2_FW_DMZ.pcapng » -> « FW_DMZ » ; « capture.coeur-reseau.pcap » -> « coeur-reseau »
        // Les underscores sont conservés: ils font partie des noms d'hôtes usuels.
        const base = String(filename || '')
            .replace(/\.(pcapng|pcap|cap)$/i, '')
            .replace(/^\d+[\s._-]+/, '')          // préfixe d'ordre (1_, 02-, ...)
            .replace(/^(capture|pcap|trace|dump)[\s._-]+/i, '')
            .replace(/\.+/g, ' ')
            .trim();
        return base.slice(0, 40) || `Point ${fallbackIndex}`;
    }

    clearMultiPcapSelection() {
        this.multiPcapFiles = [];
        this.multiPcapResults = null;
        this.multiRenderedDetailSessionId = null;
        this.multiPcapTaskId = null;
        this.multiSelectedSessionId = null;
        this.multiCauseFilter = '';
        this.multiSegmentFilter = '';
        this.multiRiskMinFilter = 0;
        this.multiHopFocusedIndex = null;
        this.destroyMultiHopVisuals();
        this.destroyChart('multiEquipmentChainGraph');
        this.destroyChart('multiBandwidthChainChart');
        this.globalDrilldownFilter = { query: '', protocol: '', riskMin: 0 };
        const section = document.getElementById('multiResultsSection');
        if (section) section.style.display = 'none';
        const details = document.getElementById('multiSessionDetailContainer');
        if (details) details.style.display = 'none';
        this.renderMultiPcapCaptureTable();
        this.updateMultiPcapStatus('Sélection vidée');
        this.resetMultiPcapFilters();
    }

    normalizeMultiPcapPositions() {
        this.multiPcapFiles
            .sort((a, b) => Number(a.position || 0) - Number(b.position || 0))
            .forEach((entry, idx) => {
                entry.position = idx + 1;
            });
    }

    updateMultiCaptureField(index, field, value) {
        const row = this.multiPcapFiles[index];
        if (!row) return;
        if (field === 'position') {
            row.position = Math.max(1, Number(value || index + 1));
            this.normalizeMultiPcapPositions();
            this.renderMultiPcapCaptureTable();
            return;
        }
        row[field] = value;
    }

    moveMultiCapture(index, direction) {
        const target = index + direction;
        if (target < 0 || target >= this.multiPcapFiles.length) return;
        const current = this.multiPcapFiles[index];
        this.multiPcapFiles[index] = this.multiPcapFiles[target];
        this.multiPcapFiles[target] = current;
        this.normalizeMultiPcapPositions();
        this.renderMultiPcapCaptureTable();
    }

    removeMultiCapture(index) {
        if (index < 0 || index >= this.multiPcapFiles.length) return;
        this.multiPcapFiles.splice(index, 1);
        this.normalizeMultiPcapPositions();
        this.renderMultiPcapCaptureTable();
    }

    updateMultiPcapStatus(text) {
        const status = document.getElementById('multiAnalyzeStatus');
        if (status) status.textContent = text;
    }

    renderMultiPcapCaptureTable() {
        const tbody = document.querySelector('#multiCaptureTable tbody');
        if (!tbody) return;

        const analysisByPosition = {};
        const points = this.multiPcapResults?.capture_points || [];
        points.forEach((p) => {
            analysisByPosition[Number(p.position || p.capture_index + 1)] = p;
        });

        if (!this.multiPcapFiles.length) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-tertiary);padding:1rem;">Aucun fichier chargé</td></tr>';
            return;
        }

        tbody.innerHTML = this.multiPcapFiles.map((entry, idx) => {
            const point = analysisByPosition[Number(entry.position)] || null;
            const packets = point ? Number(point.packet_count || 0).toLocaleString('fr-FR') : '-';
            const duration = point ? `${Number(point.capture_duration_seconds || 0).toFixed(3)}s` : '-';
            const start = point?.capture_start ? new Date(point.capture_start).toLocaleString('fr-FR') : '-';
            const end = point?.capture_end ? new Date(point.capture_end).toLocaleString('fr-FR') : '-';
            return `
            <tr>
                <td>${idx + 1}</td>
                <td>
                    <div><strong>${this.escapeHtml(entry.filename)}</strong></div>
                    <div style="font-size:0.78rem;color:var(--text-muted)">${this.formatBytesShort(entry.size)}</div>
                </td>
                <td>
                    <div>${packets}</div>
                    <div style="font-size:0.78rem;color:var(--text-muted)">${duration}</div>
                </td>
                <td style="font-size:0.78rem;color:var(--text-muted)">
                    <div>${this.escapeHtml(start)}</div>
                    <div>${this.escapeHtml(end)}</div>
                </td>
                <td>
                    <input class="input" type="text" value="${this.escapeHtml(entry.equipment_name || '')}"
                        oninput="analyzer.updateMultiCaptureField(${idx}, 'equipment_name', this.value)"
                        placeholder="Ex: FW-DC1" />
                </td>
                <td>
                    <input class="input" type="number" min="1" value="${Number(entry.position || idx + 1)}"
                        oninput="analyzer.updateMultiCaptureField(${idx}, 'position', this.value)" />
                </td>
                <td>
                    <input class="input" type="text" value="${this.escapeHtml(entry.comment || '')}"
                        oninput="analyzer.updateMultiCaptureField(${idx}, 'comment', this.value)"
                        placeholder="Commentaire optionnel" />
                </td>
                <td>
                    ${point ? `<button class="action-btn view" onclick='analyzer.filterMultiByEquipment(${JSON.stringify(point.equipment_name || "")})'>📡</button>` : ''}
                    <button class="action-btn view" onclick="analyzer.moveMultiCapture(${idx}, -1)">↑</button>
                    <button class="action-btn view" onclick="analyzer.moveMultiCapture(${idx}, 1)">↓</button>
                    <button class="action-btn delete" onclick="analyzer.removeMultiCapture(${idx})">✕</button>
                </td>
            </tr>
            `;
        }).join('');
    }

    getMultiPcapFormConfig() {
        const toleranceEl = document.getElementById('multiTimeTolerance');
        const maxPacketsEl = document.getElementById('multiMaxPackets');
        const timeTolerance = Math.max(0.2, Number(toleranceEl?.value || 5));
        const maxPackets = Math.max(1000, parseInt(maxPacketsEl?.value || '250000', 10) || 250000);
        const thresholds = {
            retrans_increase_medium: Math.max(0, Math.min(1, Number(document.getElementById('multiThrRetransMedium')?.value || 0.03))),
            retrans_increase_high: Math.max(0, Math.min(1, Number(document.getElementById('multiThrRetransHigh')?.value || 0.08))),
            latency_segment_medium_ms: Math.max(1, Number(document.getElementById('multiThrLatencyMedium')?.value || 60)),
            latency_segment_high_ms: Math.max(1, Number(document.getElementById('multiThrLatencyHigh')?.value || 120)),
            segment_trigger_score: Math.max(1, Math.min(100, Number(document.getElementById('multiThrSegmentTrigger')?.value || 45))),
            bufferbloat_duration_ratio: Math.max(1, Number(document.getElementById('multiThrBufferbloatDuration')?.value || 2.2)),
        };
        if (thresholds.retrans_increase_high < thresholds.retrans_increase_medium) {
            thresholds.retrans_increase_high = thresholds.retrans_increase_medium;
        }
        if (thresholds.latency_segment_high_ms <= thresholds.latency_segment_medium_ms) {
            thresholds.latency_segment_high_ms = thresholds.latency_segment_medium_ms + 5;
        }
        return { timeTolerance, maxPackets, thresholds };
    }

    async analyzeMultiPcap() {
        if (this.multiPcapFiles.length < 2) {
            this.showToast('warning', 'Multi-PCAP', 'Charge au moins 2 captures pour corréler un flux multi-hop');
            return;
        }

        const analyzeBtn = document.getElementById('multiAnalyzeBtn');
        if (analyzeBtn) analyzeBtn.disabled = true;

        const { timeTolerance, maxPackets, thresholds } = this.getMultiPcapFormConfig();
        this.updateMultiPcapStatus('Analyse multi-PCAP en cours...');

        const ordered = [...this.multiPcapFiles].sort((a, b) => Number(a.position || 0) - Number(b.position || 0));
        const metadata = ordered.map((entry) => ({
            filename: entry.filename,
            equipment_name: (entry.equipment_name || '').trim() || 'Point de capture',
            position: Number(entry.position || 0) || 0,
            comment: (entry.comment || '').trim(),
        }));

        const formData = new FormData();
        ordered.forEach((entry) => {
            formData.append('files', entry.file, entry.filename);
        });
        formData.append('metadata_json', JSON.stringify(metadata));
        formData.append('thresholds_json', JSON.stringify(thresholds));
        formData.append('time_tolerance', String(timeTolerance));
        formData.append('max_packets_per_capture', String(maxPackets));

        try {
            const response = await fetch('/api/multi-pcap/analyze', {
                method: 'POST',
                body: formData,
            });

            let data = await response.json();
            if (!response.ok) {
                throw new Error(data?.detail || `HTTP ${response.status}`);
            }
            if (data.status && data.status !== 'completed' && !data.analysis) {
                this.updateMultiPcapStatus('Analyse en arrière-plan sur Vercel...');
                const queuedTaskId = data.task_id;
                for (;;) {
                    await new Promise(resolve => setTimeout(resolve, 2000));
                    const statusResponse = await fetch(`/api/status/${queuedTaskId}`);
                    const status = await statusResponse.json();
                    if (!statusResponse.ok || status.status === 'failed') throw new Error(status.message || status.detail || 'Analyse échouée');
                    if (status.status === 'completed') break;
                    this.updateMultiPcapStatus(status.message || 'Analyse en cours...');
                }
                const resultResponse = await fetch(`/api/multi-pcap/${queuedTaskId}`);
                data = await resultResponse.json();
                if (!resultResponse.ok) throw new Error(data.detail || 'Résultats indisponibles');
            }

            this.multiPcapTaskId = data.task_id;
            this.multiPcapResults = data.analysis || null;
            this.multiSelectedSessionId = null;
            this.multiCauseFilter = '';
            this.multiSegmentFilter = '';
            this.multiRiskMinFilter = 0;
            this.multiHopFocusedIndex = null;
            this.destroyMultiHopVisuals();
            this.destroyChart('multiEquipmentChainGraph');
            this.renderMultiPcapCaptureTable();
            this.renderMultiPcapResults();
            this.showToast('success', 'Multi-PCAP', 'Corrélation multi-PCAP terminée');
            this.updateMultiPcapStatus(`Analyse terminée (task: ${this.multiPcapTaskId})`);
        } catch (error) {
            console.error('Multi-PCAP analyze error:', error);
            this.showToast('error', 'Multi-PCAP', `Échec analyse: ${error.message}`);
            this.updateMultiPcapStatus(`Erreur: ${error.message}`);
        } finally {
            if (analyzeBtn) analyzeBtn.disabled = false;
        }
    }

    async reloadMultiPcapResults() {
        if (!this.multiPcapTaskId) {
            this.showToast('warning', 'Multi-PCAP', 'Aucun résultat multi-PCAP à recharger');
            return;
        }
        try {
            const response = await fetch(`/api/multi-pcap/${this.multiPcapTaskId}`, { cache: 'no-store' });
            const payload = await response.json();
            if (!response.ok) throw new Error(payload?.detail || `HTTP ${response.status}`);
            this.multiPcapResults = payload.analysis || null;
            this.multiSelectedSessionId = null;
            this.multiSegmentFilter = '';
            this.multiRiskMinFilter = 0;
            this.multiHopFocusedIndex = null;
            this.destroyMultiHopVisuals();
            this.destroyChart('multiEquipmentChainGraph');
            this.renderMultiPcapResults();
            this.renderMultiPcapCaptureTable();
            this.showToast('success', 'Multi-PCAP', 'Résultats rechargés');
        } catch (error) {
            console.error('Reload multi-PCAP error:', error);
            this.showToast('error', 'Multi-PCAP', `Échec rechargement: ${error.message}`);
        }
    }

    resetMultiPcapFilters() {
        const searchEl = document.getElementById('multiSessionSearch');
        const protoEl = document.getElementById('multiProtocolFilter');
        const confEl = document.getElementById('multiConfidenceFilter');
        const sortEl = document.getElementById('multiSortBy');
        const problematicEl = document.getElementById('multiProblematicOnly');
        if (searchEl) searchEl.value = '';
        if (protoEl) protoEl.value = '';
        if (confEl) confEl.value = '';
        if (sortEl) sortEl.value = 'risk';
        if (problematicEl) problematicEl.checked = true;
        this.multiCauseFilter = '';
        this.multiSegmentFilter = '';
        this.multiRiskMinFilter = 0;
        this.renderMultiCauseChips();
        this.renderMultiPcapSessionsTable();
        this.renderMultiPcapInsights();
    }

    getMultiPcapSessions() {
        if (!this.multiPcapResults || !Array.isArray(this.multiPcapResults.sessions)) return [];
        return [...this.multiPcapResults.sessions];
    }

    getConfidenceRank(level) {
        const map = { HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
        return map[String(level || '').toUpperCase()] || 0;
    }

    destroyMultiHopTimeline() {
        if (this.multiHopTimeline && typeof this.multiHopTimeline.destroy === 'function') {
            this.multiHopTimeline.destroy();
        }
        this.multiHopTimeline = null;
    }

    destroyMultiHopVisuals() {
        this.destroyMultiHopTimeline();
        this.destroyChart('multiSessionChainGraph');
        this.multiChainNodeByHop = {};
        this.multiChainEdgeByHop = {};
        this.multiChainPrimaryEdgeIndex = null;
        this.multiChainPrimaryToHopIndex = null;
        this.multiGlobalChainNodeByCapture = {};
        this.multiGlobalChainEdgeByPair = {};
    }

    getMultiHopRiskClass(hop) {
        const tcp = hop?.tcp_metrics || {};
        const retrans = Number(tcp.retransmissions || 0);
        const rst = Number(tcp.rst || 0);
        const packets = Number(hop?.packet_count || 0);
        const retransRatio = packets > 0 ? retrans / packets : 0;
        if (rst >= 2 || retransRatio >= 0.08) return 'HIGH';
        if (rst >= 1 || retransRatio >= 0.03) return 'MEDIUM';
        return 'LOW';
    }

    getMultiDegradationSeverityRank(sev) {
        const map = { HIGH: 3, MEDIUM: 2, LOW: 1 };
        return map[String(sev || '').toUpperCase()] || 0;
    }

    getMultiSessionDegradationContext(session) {
        const segments = Array.isArray(session?.degradation_segments) ? session.degradation_segments : [];
        const byPair = new Map();
        const byHop = new Map();
        segments.forEach((seg) => {
            const fromIdx = Number(seg?.from_capture_index);
            const toIdx = Number(seg?.to_capture_index);
            if (!Number.isFinite(fromIdx) || !Number.isFinite(toIdx)) return;
            const key = `${fromIdx}->${toIdx}`;
            byPair.set(key, seg);

            const sevRank = this.getMultiDegradationSeverityRank(seg?.severity);
            [fromIdx, toIdx].forEach((hopIdx) => {
                const prev = byHop.get(hopIdx);
                const prevRank = this.getMultiDegradationSeverityRank(prev?.severity);
                if (!prev || sevRank > prevRank) byHop.set(hopIdx, seg);
            });
        });

        const primary = (session?.degradation_primary && typeof session.degradation_primary === 'object')
            ? session.degradation_primary
            : (segments.find((s) => s?.triggered) || segments[0] || null);

        return { byPair, byHop, primary, segments };
    }

    setMultiAutoDegradationMode(enabled) {
        this.multiAutoDegradationEnabled = Boolean(enabled);
        const session = this.getMultiPcapSessions().find((s) => s.session_id === this.multiSelectedSessionId);
        if (!session) return;
        this.renderMultiSessionTimeline(session);
        this.renderMultiSessionChainGraph(session);

        const degradation = this.getMultiSessionDegradationContext(session);
        const candidate = this.multiAutoDegradationEnabled && degradation.primary
            ? Number(degradation.primary.to_capture_index)
            : Number(this.multiHopFocusedIndex);
        const hopIndex = Number.isFinite(candidate)
            ? candidate
            : Math.min(...(session.hops || []).map((h) => Number(h?.capture_index || 0)));
        this.focusMultiHop(session, hopIndex, { syncTimeline: true, syncChain: true });
    }

    syncTimelineToHop(hopIndex) {
        if (!this.multiHopTimeline) return;
        try {
            this.multiHopTimeline.setSelection([`hop-${Number(hopIndex)}`], { focus: true, animation: { duration: 220 } });
        } catch (_) {
            try {
                this.multiHopTimeline.setSelection([`hop-${Number(hopIndex)}`]);
            } catch (_) { /* no-op */ }
        }
    }

    syncChainToHop(hopIndex) {
        const chart = this.echartsInstances.multiSessionChainGraph;
        if (!chart || chart.isDisposed() || this.multiHopSyncLock) return;
        const nodeIndex = this.multiChainNodeByHop?.[Number(hopIndex)];
        if (nodeIndex === undefined || nodeIndex === null) return;
        const edgeIndexes = this.multiChainEdgeByHop?.[Number(hopIndex)] || [];

        this.multiHopSyncLock = true;
        try {
            chart.dispatchAction({ type: 'downplay', seriesIndex: 0 });
            chart.dispatchAction({ type: 'highlight', seriesIndex: 0, dataIndex: nodeIndex });
            edgeIndexes.forEach((idx) => {
                chart.dispatchAction({ type: 'highlight', seriesIndex: 0, dataType: 'edge', dataIndex: idx });
            });
            if (
                this.multiAutoDegradationEnabled
                && Number.isFinite(this.multiChainPrimaryEdgeIndex)
                && Number(hopIndex) === Number(this.multiChainPrimaryToHopIndex)
            ) {
                chart.dispatchAction({
                    type: 'highlight',
                    seriesIndex: 0,
                    dataType: 'edge',
                    dataIndex: Number(this.multiChainPrimaryEdgeIndex),
                });
            }
        } catch (_) {
            // no-op
        } finally {
            this.multiHopSyncLock = false;
        }
    }

    syncGlobalChainToHop(hopIndex) {
        const chart = this.echartsInstances.multiEquipmentChainGraph;
        if (!chart || chart.isDisposed()) return;
        const nodeIndex = this.multiGlobalChainNodeByCapture?.[Number(hopIndex)];
        if (nodeIndex === undefined || nodeIndex === null) return;
        const edgeIndexes = [];
        const prevKey = `${Number(hopIndex) - 1}->${Number(hopIndex)}`;
        const nextKey = `${Number(hopIndex)}->${Number(hopIndex) + 1}`;
        if (Number.isFinite(this.multiGlobalChainEdgeByPair?.[prevKey])) edgeIndexes.push(Number(this.multiGlobalChainEdgeByPair[prevKey]));
        if (Number.isFinite(this.multiGlobalChainEdgeByPair?.[nextKey])) edgeIndexes.push(Number(this.multiGlobalChainEdgeByPair[nextKey]));

        try {
            chart.dispatchAction({ type: 'downplay', seriesIndex: 0 });
            chart.dispatchAction({ type: 'highlight', seriesIndex: 0, dataIndex: nodeIndex });
            edgeIndexes.forEach((idx) => {
                chart.dispatchAction({ type: 'highlight', seriesIndex: 0, dataType: 'edge', dataIndex: idx });
            });
        } catch (_) { /* no-op */ }
    }

    focusMultiHop(session, hopIndex, options = {}) {
        const opts = {
            syncTimeline: options.syncTimeline !== false,
            syncChain: options.syncChain !== false,
        };
        this.multiHopFocusedIndex = Number(hopIndex);
        document.querySelectorAll('#multiSessionDetailBody .multi-hop-row').forEach((row) => {
            row.classList.toggle('focus', Number(row.dataset.hopIndex) === this.multiHopFocusedIndex);
        });

        const focusEl = document.getElementById('multiTimelineFocus');
        if (!focusEl) return;
        const hops = Array.isArray(session?.hops) ? session.hops : [];
        const hop = hops.find((h) => Number(h?.capture_index) === this.multiHopFocusedIndex);
        const degradation = this.getMultiSessionDegradationContext(session);
        const primarySeg = degradation.primary;
        const primaryHtml = (this.multiAutoDegradationEnabled && primarySeg)
            ? `
                <div class="multi-primary-segment">
                    <span class="stream-kpi-label">Segment déclencheur auto</span>
                    <div>
                        <span class="risk-badge ${this.sanitizeClassToken(primarySeg.severity || 'MEDIUM')}">${Number(primarySeg.score || 0)}</span>
                        <strong>${this.escapeHtml(primarySeg.segment || '-')}</strong>
                        ${primarySeg.latency_ms !== null && primarySeg.latency_ms !== undefined ? `• ${Number(primarySeg.latency_ms).toFixed(2)} ms` : ''}
                    </div>
                </div>
            `
            : '';
        if (!hop) {
            focusEl.innerHTML = `${primaryHtml}<span style="color:var(--text-muted)">Clique un segment de la timeline pour voir le détail hop.</span>`;
            return;
        }
        const tcp = hop.tcp_metrics || {};
        focusEl.innerHTML = `
            <div class="multi-timeline-focus-grid">
                <div><span class="stream-kpi-label">Équipement</span><div>${this.escapeHtml(hop.equipment_name || '-')}</div></div>
                <div><span class="stream-kpi-label">État</span><div><span class="state-badge ${this.sanitizeClassToken(hop.state || '')}">${this.escapeHtml(hop.state || '-')}</span></div></div>
                <div><span class="stream-kpi-label">Paquets</span><div>${Number(hop.packet_count || 0).toLocaleString('fr-FR')}</div></div>
                <div><span class="stream-kpi-label">Retrans/RST</span><div>${Number(tcp.retransmissions || 0)} / ${Number(tcp.rst || 0)}</div></div>
            </div>
            ${primaryHtml}
        `;

        if (opts.syncTimeline) this.syncTimelineToHop(this.multiHopFocusedIndex);
        if (opts.syncChain) this.syncChainToHop(this.multiHopFocusedIndex);
        this.syncGlobalChainToHop(this.multiHopFocusedIndex);
    }

    focusCurrentMultiHop(hopIndex) {
        const session = this.getMultiPcapSessions().find((s) => s.session_id === this.multiSelectedSessionId);
        if (!session) return;
        this.focusMultiHop(session, hopIndex, { syncTimeline: true, syncChain: true });
    }

    renderMultiSessionTimeline(session) {
        this.destroyMultiHopTimeline();
        const timelineContainer = document.getElementById('multiSessionTimelineVis');
        if (!timelineContainer) return;

        const hops = Array.isArray(session?.hops) ? [...session.hops] : [];
        if (!hops.length) {
            timelineContainer.innerHTML = '<div style="padding:1rem;color:var(--text-muted)">Aucun hop disponible pour cette session.</div>';
            return;
        }
        if (typeof vis === 'undefined' || !vis?.Timeline || !vis?.DataSet) {
            timelineContainer.innerHTML = '<div style="padding:1rem;color:var(--warning)">Timeline indisponible (librairie vis.js manquante).</div>';
            return;
        }

        hops.sort((a, b) => Number(a.capture_index || 0) - Number(b.capture_index || 0));
        const degradation = this.getMultiSessionDegradationContext(session);
        const groups = new vis.DataSet(
            hops.map((hop) => ({
                id: Number(hop.capture_index),
                content: this.escapeHtml(hop.equipment_name || `Hop ${Number(hop.capture_index) + 1}`),
            }))
        );

        const toDate = (sec) => new Date(Number(sec || 0) * 1000);
        const items = [];
        hops.forEach((hop) => {
            const idx = Number(hop.capture_index || 0);
            const startSec = Number(hop.first_ts || hop.reference_ts || 0);
            const endSec = Number(hop.last_ts || hop.reference_ts || startSec);
            const start = toDate(startSec);
            const end = toDate(endSec >= startSec ? endSec : startSec);
            const classRisk = this.getMultiHopRiskClass(hop);
            const itemType = end.getTime() > start.getTime() ? 'range' : 'box';
            const segOnHop = degradation.byHop.get(idx);
            const degradeClass = (this.multiAutoDegradationEnabled && segOnHop?.triggered)
                ? ` degrade-${this.sanitizeClassToken(segOnHop.severity || 'medium')}`
                : '';
            const warnPrefix = (this.multiAutoDegradationEnabled && segOnHop?.triggered) ? '⚠ ' : '';
            items.push({
                id: `hop-${idx}`,
                group: idx,
                start,
                end: itemType === 'range' ? end : undefined,
                type: itemType,
                className: `multi-hop-item ${this.sanitizeClassToken(classRisk)}${degradeClass}`,
                content: this.escapeHtml(`${warnPrefix}${hop.equipment_name || `Hop ${idx + 1}`} · ${Number(hop.packet_count || 0).toLocaleString('fr-FR')} pkt`),
                title: this.escapeHtml(
                    `${hop.equipment_name || `Hop ${idx + 1}`}\n` +
                    `Période: ${start.toLocaleTimeString('fr-FR')} - ${end.toLocaleTimeString('fr-FR')}\n` +
                    `Paquets: ${Number(hop.packet_count || 0).toLocaleString('fr-FR')} | Octets: ${Number(hop.byte_count || 0).toLocaleString('fr-FR')}`
                ),
            });
        });

        const dataSet = new vis.DataSet(items);
        const minStart = Math.min(...items.map((i) => i.start.getTime()));
        const maxEnd = Math.max(...items.map((i) => (i.end ? i.end.getTime() : i.start.getTime())));
        const options = {
            stack: false,
            zoomKey: 'ctrlKey',
            zoomMin: 1000,
            orientation: { axis: 'top' },
            tooltip: { followMouse: true, overflowMethod: 'cap' },
            margin: { item: 12, axis: 10 },
            min: new Date(minStart - 200),
            max: new Date(maxEnd + 200),
        };

        this.multiHopTimeline = new vis.Timeline(timelineContainer, dataSet, groups, options);
        this.multiHopTimeline.on('select', (props) => {
            const selected = Array.isArray(props?.items) ? props.items[0] : null;
            if (!selected || typeof selected !== 'string' || !selected.startsWith('hop-')) return;
            const idx = Number(selected.replace('hop-', ''));
            if (Number.isNaN(idx)) return;
            this.focusMultiHop(session, idx, { syncTimeline: false, syncChain: true });
        });
    }

    renderMultiSessionChainGraph(session) {
        this.destroyChart('multiSessionChainGraph');
        this.multiChainNodeByHop = {};
        this.multiChainEdgeByHop = {};
        this.multiChainPrimaryEdgeIndex = null;
        this.multiChainPrimaryToHopIndex = null;

        const container = document.getElementById('multiSessionChainGraph');
        if (!container) return;
        const hops = Array.isArray(session?.hops) ? [...session.hops] : [];
        if (!hops.length) {
            container.innerHTML = '<div style="padding:1rem;color:var(--text-muted)">Aucune chaîne d\'équipements disponible.</div>';
            return;
        }
        if (typeof echarts === 'undefined') {
            container.innerHTML = '<div style="padding:1rem;color:var(--warning)">Graphe indisponible (ECharts non chargé).</div>';
            return;
        }

        hops.sort((a, b) => Number(a.capture_index || 0) - Number(b.capture_index || 0));
        const degradation = this.getMultiSessionDegradationContext(session);
        const latBySegment = new Map(
            (Array.isArray(session.latency_by_hop) ? session.latency_by_hop : []).map((l) => [String(l.segment || ''), l])
        );

        const nodes = hops.map((hop, idx) => {
            const hopIdx = Number(hop.capture_index || idx);
            this.multiChainNodeByHop[hopIdx] = idx;
            const riskClass = this.getMultiHopRiskClass(hop);
            const packets = Number(hop.packet_count || 0);
            const size = Math.max(46, Math.min(72, 46 + Math.log10(Math.max(1, packets)) * 8));
            const color = riskClass === 'HIGH' ? '#ef4444' : (riskClass === 'MEDIUM' ? '#f97316' : '#10b981');

            return {
                name: String(hop.equipment_name || `Hop ${hopIdx + 1}`),
                value: packets,
                hopIndex: hopIdx,
                x: 80 + (idx * 220),
                y: 110 + ((idx % 2 === 0) ? -12 : 12),
                symbolSize: size,
                itemStyle: { color, borderColor: '#0b1220', borderWidth: 2, shadowBlur: 12, shadowColor: `${color}66` },
                label: { color: '#e2e8f0', fontSize: 12, fontWeight: 600 },
                tooltip: {
                    formatter: () => (
                        `<strong>${this.escapeHtml(hop.equipment_name || `Hop ${hopIdx + 1}`)}</strong><br>` +
                        `Paquets: ${packets.toLocaleString('fr-FR')}<br>` +
                        `Volume: ${this.escapeHtml(this.formatBytesShort(Number(hop.byte_count || 0)))}<br>` +
                        `État: ${this.escapeHtml(hop.state || '-')}`
                    )
                },
            };
        });

        const links = [];
        for (let i = 0; i < hops.length - 1; i++) {
            const from = hops[i];
            const to = hops[i + 1];
            const fromName = String(from.equipment_name || `Hop ${i + 1}`);
            const toName = String(to.equipment_name || `Hop ${i + 2}`);
            const key = `${fromName} -> ${toName}`;
            const latency = latBySegment.get(key);
            const degradationSeg = degradation.byPair.get(`${Number(from.capture_index || i)}->${Number(to.capture_index || i + 1)}`);
            const latencyMs = Number(latency?.latency_ms);
            const edgeRisk = Math.max(
                this.getMultiHopRiskClass(from) === 'HIGH' || this.getMultiHopRiskClass(to) === 'HIGH' ? 3 : 0,
                this.getMultiHopRiskClass(from) === 'MEDIUM' || this.getMultiHopRiskClass(to) === 'MEDIUM' ? 2 : 1
            );
            const color = edgeRisk >= 3 ? '#ef4444' : (edgeRisk === 2 ? '#f97316' : '#10b981');
            const degradeSev = String(degradationSeg?.severity || '').toUpperCase();
            const degradeTriggered = Boolean(degradationSeg?.triggered);
            const autoHighlight = this.multiAutoDegradationEnabled && degradeTriggered;
            const degradeColor = degradeSev === 'HIGH' ? '#ef4444' : (degradeSev === 'MEDIUM' ? '#f97316' : '#f59e0b');
            const finalColor = autoHighlight ? degradeColor : color;
            const reasons = Array.isArray(degradationSeg?.reasons) ? degradationSeg.reasons : [];
            const edge = {
                source: nodes[i].name,
                target: nodes[i + 1].name,
                fromHopIndex: Number(from.capture_index || i),
                toHopIndex: Number(to.capture_index || i + 1),
                degradeScore: Number(degradationSeg?.score || 0),
                degradeTriggered,
                degradeSeverity: degradeSev || 'LOW',
                reasons,
                value: Number.isFinite(latencyMs) ? `${latencyMs.toFixed(2)} ms` : 'n/a',
                lineStyle: {
                    color: finalColor,
                    width: autoHighlight
                        ? Math.min(8, (Number.isFinite(latencyMs) ? 2 + Math.abs(latencyMs) / 30 : 2.2) + 1.6)
                        : (Number.isFinite(latencyMs) ? Math.min(6, 2 + Math.abs(latencyMs) / 30) : 2.2),
                    curveness: 0.12,
                    opacity: autoHighlight ? 1 : 0.9,
                },
                label: {
                    show: true,
                    formatter: autoHighlight
                        ? `⚠ ${Number(degradationSeg?.score || 0)}`
                        : (Number.isFinite(latencyMs) ? `${latencyMs.toFixed(1)} ms` : 'n/a'),
                    color: '#94a3b8',
                    fontSize: 10,
                },
                tooltip: {
                    formatter: () => {
                        const lines = [
                            `<strong>${this.escapeHtml(fromName)} → ${this.escapeHtml(toName)}</strong>`,
                            `Latence: ${Number.isFinite(latencyMs) ? `${latencyMs.toFixed(2)} ms` : 'n/a'}`,
                            `Score dégradation: ${Number(degradationSeg?.score || 0)}`,
                            `Sévérité: ${this.escapeHtml(degradeSev || 'LOW')}`,
                        ];
                        if (reasons.length) {
                            lines.push(`Raison: ${this.escapeHtml(this.truncate(reasons[0], 120))}`);
                        }
                        return lines.join('<br>');
                    }
                },
            };
            const edgeIdx = links.length;
            links.push(edge);
            if (
                degradation.primary
                && Number(degradation.primary.from_capture_index) === edge.fromHopIndex
                && Number(degradation.primary.to_capture_index) === edge.toHopIndex
            ) {
                this.multiChainPrimaryEdgeIndex = edgeIdx;
                this.multiChainPrimaryToHopIndex = edge.toHopIndex;
            }
            [edge.fromHopIndex, edge.toHopIndex].forEach((h) => {
                if (!Array.isArray(this.multiChainEdgeByHop[h])) this.multiChainEdgeByHop[h] = [];
                this.multiChainEdgeByHop[h].push(edgeIdx);
            });
        }

        const chart = this.initChart('multiSessionChainGraph');
        if (!chart) return;
        chart.setOption({
            backgroundColor: 'transparent',
            tooltip: { trigger: 'item', confine: true },
            animationDuration: 360,
            animationDurationUpdate: 260,
            series: [{
                type: 'graph',
                layout: 'none',
                coordinateSystem: null,
                roam: true,
                draggable: false,
                data: nodes,
                links,
                edgeSymbol: ['none', 'arrow'],
                edgeSymbolSize: [4, 11],
                lineStyle: { width: 2, curveness: 0.12, opacity: 0.85 },
                emphasis: { focus: 'adjacency' },
                select: { disabled: false },
                selectedMode: 'single',
            }],
            grid: { left: 0, right: 0, top: 0, bottom: 0 },
        });

        chart.off('click');
        chart.on('click', (params) => {
            if (this.multiHopSyncLock) return;
            if (params?.dataType === 'node') {
                const idx = Number(params?.data?.hopIndex);
                if (Number.isFinite(idx)) this.focusMultiHop(session, idx, { syncTimeline: true, syncChain: false });
                return;
            }
            if (params?.dataType === 'edge') {
                const toIdx = Number(params?.data?.toHopIndex);
                const fromIdx = Number(params?.data?.fromHopIndex);
                const idx = Number.isFinite(toIdx) ? toIdx : fromIdx;
                if (Number.isFinite(idx)) this.focusMultiHop(session, idx, { syncTimeline: true, syncChain: false });
            }
        });

        if (this.multiAutoDegradationEnabled && Number.isFinite(this.multiChainPrimaryEdgeIndex)) {
            try {
                chart.dispatchAction({
                    type: 'highlight',
                    seriesIndex: 0,
                    dataType: 'edge',
                    dataIndex: Number(this.multiChainPrimaryEdgeIndex),
                });
            } catch (_) { /* no-op */ }
        }
    }

    setMultiCauseFilter(cause) {
        this.multiCauseFilter = this.multiCauseFilter === cause ? '' : cause;
        this.renderMultiCauseChips();
        this.renderMultiPcapSessionsTable();
        this.renderMultiPcapInsights();
    }

    setMultiSegmentFilter(segment) {
        const next = String(segment || '').trim();
        this.multiSegmentFilter = (this.multiSegmentFilter === next) ? '' : next;
        this.renderMultiPcapSessionsTable();
        this.renderMultiPcapInsights();
    }

    filterMultiByEquipment(equipmentName) {
        const searchEl = document.getElementById('multiSessionSearch');
        if (searchEl) searchEl.value = equipmentName || '';
        this.renderMultiPcapSessionsTable();
    }

    applyGlobalDrilldownFromControls(silent = false) {
        const query = String(document.getElementById('multiGlobalSearch')?.value || '').trim();
        const protocol = String(document.getElementById('multiGlobalProtocol')?.value || '').trim().toUpperCase();
        const riskMin = Math.max(0, Number(document.getElementById('multiGlobalRiskMin')?.value || 0));
        this.globalDrilldownFilter = { query, protocol, riskMin };

        this.multiRiskMinFilter = riskMin;

        const multiSearch = document.getElementById('multiSessionSearch');
        const multiProto = document.getElementById('multiProtocolFilter');
        if (multiSearch) multiSearch.value = query;
        if (multiProto) {
            const wanted = protocol && ['TCP', 'UDP'].includes(protocol) ? protocol : '';
            multiProto.value = wanted;
        }

        const streamIp = document.getElementById('streamIpFilter');
        const streamType = document.getElementById('streamTypeFilter');
        const streamProblemOnly = document.getElementById('streamProblematicOnly');
        if (streamIp) streamIp.value = query;
        if (streamType) {
            if (protocol === 'HTTP') streamType.value = 'http';
            else if (protocol === 'HTTPS' || protocol === 'TCP') streamType.value = '';
        }
        if (streamProblemOnly) streamProblemOnly.checked = riskMin >= 40;

        const packetInput = document.getElementById('packetFilterInput');
        const packetProto = document.getElementById('protoFilter');
        if (packetInput) packetInput.value = query;
        if (packetProto) packetProto.value = (protocol && ['TCP', 'UDP', 'DNS', 'HTTP'].includes(protocol)) ? protocol : '';

        this.renderMultiPcapSessionsTable();
        this.renderMultiPcapInsights();
        if (this.currentTaskId) {
            this.loadStreams();
            this.applyPacketFilters();
            this.displayDnsResults(this.currentResults?.dns_analysis || {});
            this.displayHttpResults(this.currentResults?.http_analysis || {});
            if (typeof window.advApplyGlobalDrilldown === 'function') {
                window.advApplyGlobalDrilldown(this.globalDrilldownFilter);
            }
        }

        if (!silent) {
            this.showToast(
                'success',
                'Drilldown global',
                `Filtres appliqués: query="${query || '*'}", proto="${protocol || '*'}", risque≥${riskMin}`
            );
        }
    }

    resetGlobalDrilldownControls() {
        const search = document.getElementById('multiGlobalSearch');
        const proto = document.getElementById('multiGlobalProtocol');
        const riskMin = document.getElementById('multiGlobalRiskMin');
        if (search) search.value = '';
        if (proto) proto.value = '';
        if (riskMin) riskMin.value = '0';
        this.multiRiskMinFilter = 0;
        this.globalDrilldownFilter = { query: '', protocol: '', riskMin: 0 };
        this.resetMultiPcapFilters();

        const streamIp = document.getElementById('streamIpFilter');
        const streamType = document.getElementById('streamTypeFilter');
        const streamProblemOnly = document.getElementById('streamProblematicOnly');
        if (streamIp) streamIp.value = '';
        if (streamType) streamType.value = '';
        if (streamProblemOnly) streamProblemOnly.checked = false;

        const packetInput = document.getElementById('packetFilterInput');
        const packetProto = document.getElementById('protoFilter');
        if (packetInput) packetInput.value = '';
        if (packetProto) packetProto.value = '';

        if (this.currentTaskId) {
            this.loadStreams();
            this.applyPacketFilters();
            this.displayDnsResults(this.currentResults?.dns_analysis || {});
            this.displayHttpResults(this.currentResults?.http_analysis || {});
            if (typeof window.advApplyGlobalDrilldown === 'function') {
                window.advApplyGlobalDrilldown(this.globalDrilldownFilter);
            }
        }
        this.showToast('info', 'Drilldown global', 'Filtres réinitialisés');
    }

    collectGlobalDrilldownSnapshot() {
        const multiSessions = this.getMultiFilteredSessions();
        const streamsDisplayed = Array.isArray(this.streamsData) ? this.streamsData.slice() : [];
        const packetsDisplayed = Array.isArray(this.filteredPackets) ? this.filteredPackets.slice(0, 2000) : [];
        return {
            generatedAt: new Date().toISOString(),
            multiSessions,
            streamsDisplayed,
            packetsDisplayed,
        };
    }

    async exportGlobalDrilldownSnapshotCsv() {
        const snapshot = this.collectGlobalDrilldownSnapshot();
        this.globalDrilldownSnapshot = snapshot;
        const rows = [];
        rows.push('section;id;field1;field2;field3;field4;field5');
        snapshot.multiSessions.forEach((s) => {
            rows.push([
                'multi_session',
                `"${String(s.session_id || '').replace(/"/g, '""')}"`,
                `"${String(s.flow_label || '').replace(/"/g, '""')}"`,
                Number(s.risk_score || 0),
                `"${String(s.confidence_level || '').replace(/"/g, '""')}"`,
                `"${String(s.probable_cause || '').replace(/"/g, '""')}"`,
                Number(s.latency_total_ms || 0),
            ].join(';'));
        });
        snapshot.streamsDisplayed.forEach((s) => {
            rows.push([
                'stream',
                Number(s.stream_id || 0),
                `"${String(s.src_ip || '').replace(/"/g, '""')}:${Number(s.src_port || 0)}"`,
                `"${String(s.dst_ip || '').replace(/"/g, '""')}:${Number(s.dst_port || 0)}"`,
                `"${String(s.type || '').replace(/"/g, '""')}"`,
                Number(s.total_packets || 0),
                `"${String(s.probable_cause || '').replace(/"/g, '""')}"`,
            ].join(';'));
        });
        snapshot.packetsDisplayed.slice(0, 800).forEach((p, idx) => {
            rows.push([
                'packet',
                Number(p.number || idx + 1),
                `"${String(p.src_ip || '').replace(/"/g, '""')}"`,
                `"${String(p.dst_ip || '').replace(/"/g, '""')}"`,
                `"${String(p.protocol || '').replace(/"/g, '""')}"`,
                Number(p.length || p.len || 0),
                `"${String(p.info || '').replace(/"/g, '""')}"`,
            ].join(';'));
        });

        const blob = new Blob([rows.join('\n')], { type: 'text/csv;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        link.download = `global_drilldown_${ts}.csv`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
        this.showToast('success', 'Export', 'Snapshot drilldown global exporté');
    }

    getMultiFilteredSessions() {
        const sessions = this.getMultiPcapSessions();
        const onlyProblems = Boolean(document.getElementById('multiProblematicOnly')?.checked);
        const query = String(document.getElementById('multiSessionSearch')?.value || '').trim().toLowerCase();
        const protocol = String(document.getElementById('multiProtocolFilter')?.value || '').toUpperCase();
        const confidence = String(document.getElementById('multiConfidenceFilter')?.value || '').toUpperCase();
        const sortBy = String(document.getElementById('multiSortBy')?.value || 'risk').toLowerCase();
        const causeFilter = String(this.multiCauseFilter || '').trim();
        const segmentFilter = String(this.multiSegmentFilter || '').trim().toLowerCase();
        const riskMin = Math.max(0, Number(this.multiRiskMinFilter || 0));

        let rows = sessions.filter((session) => {
            if (onlyProblems && !Boolean(session.problematic)) return false;
            if (protocol && String(session.protocol || '').toUpperCase() !== protocol) return false;
            if (confidence && String(session.confidence_level || '').toUpperCase() !== confidence) return false;
            if (Number(session.risk_score || 0) < riskMin) return false;
            if (causeFilter && String(session.probable_cause || '') !== causeFilter) return false;
            if (segmentFilter) {
                const segRows = Array.isArray(session.degradation_segments) ? session.degradation_segments : [];
                const hit = segRows.some((seg) => String(seg?.segment || '').toLowerCase() === segmentFilter);
                if (!hit) return false;
            }

            if (query) {
                const presence = Array.isArray(session.presence)
                    ? session.presence.map((p) => p.equipment_name || '').join(' ')
                    : '';
                const haystack = [
                    session.flow_label || '',
                    session.probable_cause || '',
                    session.cause_details || '',
                    session.protocol || '',
                    session.session_id || '',
                    presence,
                    Array.isArray(session.root_cause_signals)
                        ? session.root_cause_signals.map((r) => `${r.label || ''} ${r.code || ''}`).join(' ')
                        : '',
                ].join(' ').toLowerCase();
                if (!haystack.includes(query)) return false;
            }
            return true;
        });

        rows.sort((a, b) => {
            if (sortBy === 'changes') {
                return (b.changes?.length || 0) - (a.changes?.length || 0) || Number(b.risk_score || 0) - Number(a.risk_score || 0);
            }
            if (sortBy === 'latency') {
                return Number(b.latency_total_ms || -999999) - Number(a.latency_total_ms || -999999);
            }
            if (sortBy === 'confidence') {
                return this.getConfidenceRank(b.confidence_level) - this.getConfidenceRank(a.confidence_level)
                    || Number(b.risk_score || 0) - Number(a.risk_score || 0);
            }
            return Number(b.risk_score || 0) - Number(a.risk_score || 0)
                || (b.changes?.length || 0) - (a.changes?.length || 0);
        });

        return rows;
    }

    renderMultiCauseChips() {
        const container = document.getElementById('multiCauseChips');
        if (!container) return;

        const sessions = this.getMultiPcapSessions();
        if (!sessions.length) {
            container.innerHTML = '';
            return;
        }

        const causeMap = new Map();
        sessions.forEach((s) => {
            const cause = String(s.probable_cause || 'Inconnu').trim() || 'Inconnu';
            causeMap.set(cause, (causeMap.get(cause) || 0) + 1);
        });
        const causes = Array.from(causeMap.entries())
            .map(([cause, count]) => ({ cause, count }))
            .sort((a, b) => b.count - a.count)
            .slice(0, 10);

        container.innerHTML = causes.map((item) => {
            const active = this.multiCauseFilter === item.cause ? ' active' : '';
            return `<button class="multi-cause-chip${active}" onclick='analyzer.setMultiCauseFilter(${JSON.stringify(item.cause)})'>
                ${this.escapeHtml(this.truncate(item.cause, 40))} <span>${item.count}</span>
            </button>`;
        }).join('');
    }

    // ==================== MULTI-PCAP : CHAÎNE & GOULOT D'ÉTRANGLEMENT ====================

    /**
     * Lit une variable CSS du design system pour colorer les graphes ECharts
     * (évite les couleurs en dur et suit le thème clair/sombre).
     */
    getCssVar(name, fallback) {
        try {
            const value = getComputedStyle(document.documentElement).getPropertyValue(name);
            const trimmed = String(value || '').trim();
            return trimmed || fallback;
        } catch (_) {
            return fallback;
        }
    }

    /** Libellés FR explicites des classes de limitation de flux. */
    getFlowLimitationLabel(cls) {
        const labels = {
            RECEIVER_LIMITED: 'Limité par le récepteur (fenêtre)',
            NETWORK_LIMITED: 'Limité par le réseau (pertes)',
            APPLICATION_LIMITED: "Limité par l'application (émetteur)",
            UNDETERMINED: 'Facteur limitant indéterminé',
            UNKNOWN: 'Non classé',
        };
        return labels[String(cls || '').toUpperCase()] || String(cls || 'Non classé');
    }

    /** Ramène une sévérité backend à un token CSS connu (high / medium / low). */
    getBottleneckSeverityToken(severity) {
        const token = String(severity || '').trim().toUpperCase();
        return ['HIGH', 'MEDIUM', 'LOW'].includes(token) ? token.toLowerCase() : 'low';
    }

    /** Formate une métrique numérique éventuellement nulle, avec unité. */
    formatBottleneckMetric(value, unit = '', digits = 2) {
        const num = Number(value);
        if (value === null || value === undefined || !Number.isFinite(num)) return '-';
        return unit ? `${num.toFixed(digits)} ${unit}` : num.toFixed(digits);
    }

    /**
     * Extrait et normalise les blocs bottleneck des résultats multi-PCAP.
     * Tolère l'absence complète des clés (résultats en cache antérieurs).
     */
    getMultiBottleneckData() {
        const results = this.multiPcapResults || {};
        const bandwidth = (results.bandwidth_chain && typeof results.bandwidth_chain === 'object')
            ? results.bandwidth_chain
            : {};
        const packetMatch = (results.packet_match && typeof results.packet_match === 'object')
            ? results.packet_match
            : {};
        return {
            verdicts: Array.isArray(results.bottleneck_verdicts) ? results.bottleneck_verdicts : [],
            points: Array.isArray(bandwidth.per_capture_point) ? bandwidth.per_capture_point : [],
            bandwidthSegments: Array.isArray(bandwidth.segments) ? bandwidth.segments : [],
            packetSegments: Array.isArray(packetMatch.segments) ? packetMatch.segments : [],
            worstLossSegment: packetMatch.worst_loss_segment || results.summary?.worst_loss_segment || '',
            worstDelaySegment: packetMatch.worst_delay_segment || results.summary?.worst_delay_segment || '',
            method: String(packetMatch.method || ''),
            summary: results.summary || {},
        };
    }

    /** Clé de segment stable: index amont -> index aval. */
    getBottleneckPairKey(from, to) {
        return `${Number(from ?? -1)}->${Number(to ?? -1)}`;
    }

    /** Orchestrateur de la section « Chaîne & goulot d'étranglement ». */
    renderMultiBottleneckSection() {
        const section = document.getElementById('multiBottleneckSection');
        if (!section) return;

        const data = this.getMultiBottleneckData();

        const methodEl = document.getElementById('multiBottleneckMethod');
        if (methodEl) {
            methodEl.textContent = data.method
                || (data.verdicts.length
                    ? 'Corrélation amont/aval des flux communs entre points de capture.'
                    : 'Analyse de goulot non disponible pour ces résultats.');
        }

        this.renderMultiClockWarning(data.packetSegments);
        this.renderMultiFlowLimitationChips(data.summary);
        this.renderMultiChainWaterfall(data);
        this.renderMultiBottleneckVerdict(data);
        this.renderMultiBandwidthChainChart(data.points);
    }

    /** Avertissement horloges non synchronisées (délais relatifs uniquement). */
    renderMultiClockWarning(packetSegments) {
        const el = document.getElementById('multiClockWarning');
        if (!el) return;

        const impacted = (Array.isArray(packetSegments) ? packetSegments : [])
            .filter((seg) => seg && seg.clock_offset_warning === true);

        if (!impacted.length) {
            el.style.display = 'none';
            el.innerHTML = '';
            return;
        }

        const details = impacted.map((seg) => {
            const label = seg.segment
                || `#${Number(seg.from_capture_index || 0) + 1} → #${Number(seg.to_capture_index || 0) + 1}`;
            const offset = Number(seg.clock_offset_seconds);
            const offsetTxt = Number.isFinite(offset) ? ` (décalage ≈ ${offset.toFixed(3)} s)` : '';
            return `${this.escapeHtml(label)}${this.escapeHtml(offsetTxt)}`;
        }).join(' • ');

        el.style.display = 'flex';
        el.innerHTML = `
            <span class="bnk-alert-icon">⏱️</span>
            <div class="bnk-alert-body">
                <strong>Horloges non synchronisées&nbsp;: les délais sont relatifs.</strong>
                <div class="bnk-alert-detail">
                    Le décalage médian a été retiré segment par segment. Les valeurs de délai
                    traduisent une <em>variation</em> (mise en file d'attente, gigue), pas une latence absolue.
                </div>
                <div class="bnk-alert-detail">Segment(s) concerné(s)&nbsp;: ${details}</div>
            </div>`;
    }

    /** Pastilles de répartition des facteurs limitants (flow_limitation_breakdown). */
    renderMultiFlowLimitationChips(summary) {
        const el = document.getElementById('multiFlowLimitationChips');
        if (!el) return;

        const breakdown = (summary && typeof summary.flow_limitation_breakdown === 'object' && summary.flow_limitation_breakdown)
            ? summary.flow_limitation_breakdown
            : {};
        const entries = Object.entries(breakdown)
            .map(([cls, count]) => ({ cls: String(cls || 'UNKNOWN'), count: Number(count || 0) }))
            .filter((entry) => entry.count > 0)
            .sort((a, b) => b.count - a.count);

        if (!entries.length) {
            el.style.display = 'none';
            el.innerHTML = '';
            return;
        }

        el.style.display = 'flex';
        el.innerHTML = `<span class="bnk-flow-legend">Pourquoi les flux ne vont pas plus vite&nbsp;:</span>`
            + entries.map((entry) => `
                <span class="bnk-flow-chip bnk-flow-${this.sanitizeClassToken(entry.cls)}" title="${this.escapeHtml(entry.cls)}">
                    ${this.escapeHtml(this.getFlowLimitationLabel(entry.cls))}
                    <span class="bnk-flow-count">${entry.count.toLocaleString('fr-FR')}</span>
                </span>`).join('');
    }

    /** Waterfall: un rang par point de capture, une barre par segment. */
    renderMultiChainWaterfall(data) {
        const el = document.getElementById('multiChainWaterfall');
        if (!el) return;

        const verdicts = Array.isArray(data.verdicts) ? data.verdicts : [];
        if (!verdicts.length) {
            el.innerHTML = `
                <div class="adv-empty">
                    <span>🚦</span>
                    <p>Analyse de goulot indisponible pour ces résultats.<br>
                    Relancez la corrélation multi-PCAP pour la calculer.</p>
                </div>`;
            return;
        }

        // Points de capture: bandwidth_chain en priorité, sinon capture_points,
        // sinon reconstruction depuis les verdicts eux-mêmes.
        let points = Array.isArray(data.points) ? data.points.slice() : [];
        if (points.length < 2) {
            const fallback = Array.isArray(this.multiPcapResults?.capture_points)
                ? this.multiPcapResults.capture_points
                : [];
            if (fallback.length >= 2) {
                points = fallback.map((p, i) => ({
                    capture_index: Number(p.capture_index ?? i),
                    equipment_name: p.equipment_name,
                }));
            }
        }
        if (points.length < 2) {
            const derived = new Map();
            verdicts.forEach((v) => {
                const from = Number(v.from_capture_index || 0);
                const to = Number(v.to_capture_index || from + 1);
                if (!derived.has(from)) derived.set(from, { capture_index: from, equipment_name: v.from_equipment });
                if (!derived.has(to)) derived.set(to, { capture_index: to, equipment_name: v.to_equipment });
            });
            points = Array.from(derived.values());
        }
        points.sort((a, b) => Number(a.capture_index || 0) - Number(b.capture_index || 0));

        // Rang de chaque segment dans le classement par score décroissant
        const verdictByPair = new Map();
        const rankByPair = new Map();
        verdicts.forEach((v, idx) => {
            const key = this.getBottleneckPairKey(v.from_capture_index, v.to_capture_index);
            if (!verdictByPair.has(key)) {
                verdictByPair.set(key, v);
                rankByPair.set(key, idx + 1);
            }
        });

        const rows = [];
        points.forEach((point, i) => {
            rows.push(this.buildBottleneckNodeRow(point, i));
            const next = points[i + 1];
            if (!next) return;
            const key = this.getBottleneckPairKey(point.capture_index ?? i, next.capture_index ?? (i + 1));
            const verdict = verdictByPair.get(key);
            rows.push(verdict
                ? this.buildBottleneckSegmentRow(verdict, rankByPair.get(key))
                : this.buildBottleneckEmptySegmentRow(point, next));
        });

        el.innerHTML = rows.join('');
    }

    /** Rang « point de capture » du waterfall. */
    buildBottleneckNodeRow(point, order) {
        const rawIndex = Number(point?.capture_index);
        const displayIndex = (Number.isFinite(rawIndex) ? rawIndex : order) + 1;
        const label = point?.equipment_name || `Point ${displayIndex}`;
        const metrics = [
            (point?.avg_mbps ?? null) !== null ? `moy ${this.formatBottleneckMetric(point.avg_mbps, 'Mbps')}` : '',
            (point?.p95_mbps ?? null) !== null ? `p95 ${this.formatBottleneckMetric(point.p95_mbps, 'Mbps')}` : '',
            (point?.peak_mbps ?? null) !== null ? `pic ${this.formatBottleneckMetric(point.peak_mbps, 'Mbps')}` : '',
            (point?.active_seconds ?? null) !== null ? `${Number(point.active_seconds || 0).toLocaleString('fr-FR')} s actives` : '',
        ].filter(Boolean).join(' • ');

        return `
        <div class="bnk-node">
            <span class="bnk-node-index">${displayIndex}</span>
            <div class="bnk-node-body">
                <div class="bnk-node-name">${this.escapeHtml(label)}</div>
                <div class="bnk-node-metrics">${this.escapeHtml(metrics || 'Débit non mesuré à ce point')}</div>
            </div>
        </div>`;
    }

    /** Barre de segment colorée par sévérité, mise en avant si goulot n°1. */
    buildBottleneckSegmentRow(verdict, rank) {
        const sev = this.getBottleneckSeverityToken(verdict.severity);
        const score = Number(verdict.bottleneck_score || 0);
        const isPrimary = Number(rank) === 1;
        const segLabel = verdict.segment
            || `${verdict.from_equipment || '?'} -> ${verdict.to_equipment || '?'}`;
        const signature = verdict.traffic_shaping_signature
            ? `<span class="bnk-signature bnk-signature-${this.sanitizeClassToken(verdict.traffic_shaping_signature)}">${this.escapeHtml(verdict.traffic_shaping_signature)}</span>`
            : '';
        const width = Math.max(3, Math.min(100, Number.isFinite(score) ? score : 0));

        return `
        <div class="bnk-segment bnk-sev-${sev}${isPrimary ? ' bnk-primary' : ''}"
             role="button" tabindex="0"
             title="Filtrer les sessions sur ce segment"
             onclick='analyzer.setMultiSegmentFilter(${this.escapeHtml(JSON.stringify(segLabel))})'
             onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();this.click();}">
            <div class="bnk-seg-head">
                <span class="bnk-seg-rank">#${Number(rank || 0)}</span>
                <span class="bnk-seg-title">${this.escapeHtml(segLabel)}</span>
                ${isPrimary ? '<span class="bnk-primary-flag">Goulot principal</span>' : ''}
                <span class="bnk-score">${score.toFixed(1)}</span>
                <span class="bnk-sev-tag">${this.escapeHtml(String(verdict.severity || 'LOW').toUpperCase())}</span>
                ${signature}
            </div>
            <div class="bnk-seg-bar"><span style="width:${width.toFixed(1)}%"></span></div>
            <div class="bnk-seg-metrics">
                <span>Perte paquets <strong>${this.formatBottleneckMetric(verdict.packet_loss_pct, '%')}</strong></span>
                <span>Délai ajouté p95 <strong>${this.formatBottleneckMetric(verdict.added_delay_p95_ms, 'ms', 1)}</strong></span>
                <span>Perte goodput <strong>${this.formatBottleneckMetric(verdict.goodput_loss_pct, '%')}</strong></span>
                <span>Gigue file <strong>${this.formatBottleneckMetric(verdict.queuing_jitter_ms, 'ms', 1)}</strong></span>
                <span>Confiance <strong>${this.escapeHtml(String(verdict.confidence || '-').toUpperCase())}</strong></span>
            </div>
        </div>`;
    }

    /** Segment sans verdict calculé (flux non corrélés des deux côtés). */
    buildBottleneckEmptySegmentRow(fromPoint, toPoint) {
        const label = `${fromPoint?.equipment_name || '?'} -> ${toPoint?.equipment_name || '?'}`;
        return `
        <div class="bnk-segment bnk-segment-empty">
            <div class="bnk-seg-head">
                <span class="bnk-seg-title">${this.escapeHtml(label)}</span>
            </div>
            <div class="bnk-seg-metrics"><span>Aucun flux commun corrélé sur ce segment</span></div>
        </div>`;
    }

    /** Panneau verdict: raisons + recommandations du segment n°1. */
    renderMultiBottleneckVerdict(data) {
        const el = document.getElementById('multiBottleneckVerdict');
        if (!el) return;

        const verdict = Array.isArray(data.verdicts) ? data.verdicts[0] : null;
        if (!verdict) {
            el.innerHTML = `
                <div class="adv-empty">
                    <span>🧭</span>
                    <p>Aucun verdict de goulot disponible.<br>Relancez une corrélation multi-PCAP.</p>
                </div>`;
            return;
        }

        const sev = this.getBottleneckSeverityToken(verdict.severity);
        const segLabel = verdict.segment || `${verdict.from_equipment || '?'} -> ${verdict.to_equipment || '?'}`;
        const reasons = Array.isArray(verdict.reasons) ? verdict.reasons : [];
        const recommendations = Array.isArray(verdict.recommendations) ? verdict.recommendations : [];
        const pktSegment = (Array.isArray(data.packetSegments) ? data.packetSegments : []).find((seg) => (
            Number(seg?.from_capture_index) === Number(verdict.from_capture_index)
            && Number(seg?.to_capture_index) === Number(verdict.to_capture_index)
        ));

        const reasonsHtml = reasons.length
            ? `<ul class="bnk-list">${reasons.map((r) => `<li>${this.escapeHtml(r)}</li>`).join('')}</ul>`
            : '<p class="bnk-muted">Aucun motif détaillé fourni.</p>';
        const recoHtml = recommendations.length
            ? `<ul class="bnk-list bnk-list-reco">${recommendations.map((r) => `<li>${this.escapeHtml(r)}</li>`).join('')}</ul>`
            : '<p class="bnk-muted">Aucune action corrective spécifique proposée: le segment ne présente pas de signature nette.</p>';

        const signature = verdict.traffic_shaping_signature
            ? `<span class="bnk-signature bnk-signature-${this.sanitizeClassToken(verdict.traffic_shaping_signature)}">${this.escapeHtml(verdict.traffic_shaping_signature)}</span>`
            : '<span class="bnk-muted">aucune</span>';

        const worstLoss = data.worstLossSegment ? this.escapeHtml(data.worstLossSegment) : '-';
        const worstDelay = data.worstDelaySegment ? this.escapeHtml(data.worstDelaySegment) : '-';

        el.innerHTML = `
            <div class="bnk-verdict-head bnk-sev-${sev}">
                <div class="bnk-verdict-segment">${this.escapeHtml(segLabel)}</div>
                <div class="bnk-verdict-badges">
                    <span class="bnk-score">${Number(verdict.bottleneck_score || 0).toFixed(1)} / 100</span>
                    <span class="bnk-sev-tag">${this.escapeHtml(String(verdict.severity || 'LOW').toUpperCase())}</span>
                    <span class="bnk-conf-tag">Confiance ${this.escapeHtml(String(verdict.confidence || '-').toUpperCase())}</span>
                </div>
            </div>
            <div class="bnk-verdict-metrics">
                <div><span>Perte de paquets</span><strong>${this.formatBottleneckMetric(verdict.packet_loss_pct, '%')}</strong></div>
                <div><span>Perte de goodput</span><strong>${this.formatBottleneckMetric(verdict.goodput_loss_pct, '%')}</strong></div>
                <div><span>Délai ajouté p95</span><strong>${this.formatBottleneckMetric(verdict.added_delay_p95_ms, 'ms', 1)}</strong></div>
                <div><span>Gigue de file</span><strong>${this.formatBottleneckMetric(verdict.queuing_jitter_ms, 'ms', 1)}</strong></div>
                <div><span>Signature trafic</span><strong>${signature}</strong></div>
                <div><span>Paquets appariés</span><strong>${pktSegment ? Number(pktSegment.matched_packets || 0).toLocaleString('fr-FR') : '-'}</strong></div>
            </div>
            <h5 class="bnk-verdict-title">Pourquoi ce segment est incriminé</h5>
            ${reasonsHtml}
            <h5 class="bnk-verdict-title">Ce qu'il faut vérifier</h5>
            ${recoHtml}
            <div class="bnk-verdict-footer">
                <span>Pire segment en pertes&nbsp;: <strong>${worstLoss}</strong></span>
                <span>Pire segment en délai&nbsp;: <strong>${worstDelay}</strong></span>
            </div>`;
    }

    /** Barres avg_mbps / p95_mbps par point de capture: la lecture « où ça chute ». */
    renderMultiBandwidthChainChart(points) {
        const dom = document.getElementById('multiBandwidthChainChart');
        if (!dom) return;

        const rows = (Array.isArray(points) ? points.slice() : [])
            .sort((a, b) => Number(a.capture_index || 0) - Number(b.capture_index || 0));

        if (!rows.length || typeof echarts === 'undefined') {
            this.destroyChart('multiBandwidthChainChart');
            dom.innerHTML = '<div class="adv-empty"><span>📉</span><p>Débit par point de capture indisponible</p></div>';
            return;
        }

        // Purger un éventuel état vide avant d'initialiser le canvas
        if (!echarts.getInstanceByDom(dom)) dom.innerHTML = '';

        const chart = this.initChart('multiBandwidthChainChart');
        if (!chart) return;

        const theme = this.getEChartsTheme();
        const primary = this.getCssVar('--primary', '#4cc3e0');
        const accent = this.getCssVar('--accent', '#f0954e');
        const info = this.getCssVar('--info', '#6aa5f8');

        const labels = rows.map((r, i) => this.truncate(String(r.equipment_name || `Point ${Number(r.capture_index ?? i) + 1}`), 24));
        const avg = rows.map((r) => Number(r.avg_mbps || 0));
        const p95 = rows.map((r) => Number(r.p95_mbps || 0));
        const peak = rows.map((r) => Number(r.peak_mbps || 0));

        chart.setOption({
            backgroundColor: 'transparent',
            tooltip: {
                trigger: 'axis',
                axisPointer: { type: 'shadow' },
                backgroundColor: theme.tooltip.backgroundColor,
                borderColor: theme.tooltip.borderColor,
                textStyle: theme.tooltip.textStyle,
                confine: true,
            },
            legend: { top: 0, textStyle: { color: theme.textColor } },
            xAxis: {
                type: 'category',
                data: labels,
                axisLabel: { color: theme.textColor, fontSize: 10, interval: 0, rotate: labels.length > 5 ? 22 : 0 },
                axisLine: { lineStyle: { color: theme.grid } },
            },
            yAxis: {
                type: 'value',
                name: 'Mbps',
                nameTextStyle: { color: theme.textColor },
                axisLabel: { color: theme.textColor },
                splitLine: { lineStyle: { color: theme.grid } },
            },
            series: [
                { name: 'Débit moyen', type: 'bar', data: avg, itemStyle: { color: primary, borderRadius: [3, 3, 0, 0] }, barMaxWidth: 26 },
                { name: 'Débit p95', type: 'bar', data: p95, itemStyle: { color: accent, borderRadius: [3, 3, 0, 0] }, barMaxWidth: 26 },
                {
                    name: 'Pic', type: 'line', data: peak, smooth: true, symbolSize: 6,
                    lineStyle: { width: 2, color: info, type: 'dashed' }, itemStyle: { color: info },
                },
            ],
            grid: { top: 34, right: 20, bottom: labels.length > 5 ? 52 : 30, left: 58 },
        });

        chart.off('click');
        chart.on('click', (params) => {
            const idx = Number(params?.dataIndex);
            if (!Number.isFinite(idx) || idx < 0 || idx >= rows.length) return;
            const equipment = rows[idx]?.equipment_name || '';
            if (equipment) this.filterMultiByEquipment(equipment);
        });
    }

    renderMultiPcapInsights() {
        if (!this.multiPcapResults) return;
        const summary = this.multiPcapResults.summary || {};
        const captureVol = Array.isArray(this.multiPcapResults.capture_volumetry)
            ? this.multiPcapResults.capture_volumetry
            : (Array.isArray(summary.capture_volumetry) ? summary.capture_volumetry : []);
        const segmentHealth = Array.isArray(this.multiPcapResults.segment_health)
            ? this.multiPcapResults.segment_health
            : (Array.isArray(summary.segment_health_top) ? summary.segment_health_top : []);
        const culprits = Array.isArray(this.multiPcapResults.culprit_ranking)
            ? this.multiPcapResults.culprit_ranking
            : (Array.isArray(summary.culprit_ranking_top) ? summary.culprit_ranking_top : []);
        const equipmentChain = (this.multiPcapResults.equipment_chain && typeof this.multiPcapResults.equipment_chain === 'object')
            ? this.multiPcapResults.equipment_chain
            : { nodes: [], links: [] };

        const filterInfoEl = document.getElementById('multiSegmentFilterInfo');
        if (filterInfoEl) {
            const active = String(this.multiSegmentFilter || '').trim();
            filterInfoEl.innerHTML = active
                ? `Filtre segment actif: <strong>${this.escapeHtml(active)}</strong> <button class="multi-inline-btn" onclick="analyzer.setMultiSegmentFilter('')">Réinitialiser</button>`
                : 'Clique un segment pour filtrer les sessions.';
        }

        const volDom = document.getElementById('multiCaptureVolChart');
        if (volDom && captureVol.length && typeof echarts !== 'undefined') {
            const volChart = this.initChart('multiCaptureVolChart');
            if (!volChart) return;
            const labels = captureVol.map((r) => this.truncate(r.equipment_name || `Point ${Number(r.capture_index || 0) + 1}`, 26));
            const packets = captureVol.map((r) => Number(r.packet_count || 0));
            const throughput = captureVol.map((r) => Number(r.throughput_mbps || 0));
            volChart.setOption({
                backgroundColor: 'transparent',
                tooltip: { trigger: 'axis' },
                legend: { top: 0, textStyle: { color: '#94a3b8' } },
                xAxis: { type: 'category', data: labels, axisLabel: { color: '#94a3b8' } },
                yAxis: [
                    { type: 'value', name: 'Paquets', axisLabel: { color: '#94a3b8' } },
                    { type: 'value', name: 'Mbps', axisLabel: { color: '#94a3b8' } }
                ],
                series: [
                    {
                        name: 'Paquets',
                        type: 'bar',
                        data: packets,
                        itemStyle: { color: 'rgba(56,189,248,0.52)' },
                        barMaxWidth: 22
                    },
                    {
                        name: 'Débit (Mbps)',
                        type: 'line',
                        yAxisIndex: 1,
                        smooth: true,
                        data: throughput,
                        lineStyle: { width: 2, color: '#34d399' },
                        itemStyle: { color: '#34d399' }
                    }
                ],
                grid: { top: 30, right: 42, bottom: 26, left: 56 }
            });
            volChart.off('click');
            volChart.on('click', (params) => {
                const idx = Number(params?.dataIndex);
                if (!Number.isFinite(idx) || idx < 0 || idx >= captureVol.length) return;
                const eq = captureVol[idx]?.equipment_name || '';
                if (eq) this.filterMultiByEquipment(eq);
            });
        } else {
            this.destroyChart('multiCaptureVolChart');
            if (volDom) volDom.innerHTML = '<div class="adv-empty"><span>📦</span><p>Volumétrie indisponible</p></div>';
        }

        const segRows = segmentHealth.slice(0, 12);
        const segDom = document.getElementById('multiSegmentHealthChart');
        if (segDom && segRows.length && typeof echarts !== 'undefined') {
            const segChart = this.initChart('multiSegmentHealthChart');
            if (!segChart) return;
            const labels = segRows.map((r) => this.truncate(r.segment || '-', 34));
            const scores = segRows.map((r) => Number(r.avg_score || 0));
            const latency = segRows.map((r) => Number(r.latency_p95_ms || 0));
            segChart.setOption({
                backgroundColor: 'transparent',
                tooltip: { trigger: 'axis' },
                legend: { top: 0, textStyle: { color: '#94a3b8' } },
                xAxis: { type: 'category', data: labels, axisLabel: { color: '#94a3b8', fontSize: 10 } },
                yAxis: [
                    { type: 'value', name: 'Score', axisLabel: { color: '#94a3b8' } },
                    { type: 'value', name: 'p95 ms', axisLabel: { color: '#94a3b8' } }
                ],
                series: [
                    {
                        name: 'Score dégradation',
                        type: 'bar',
                        data: scores,
                        itemStyle: {
                            color: (p) => {
                                const v = Number(p.value || 0);
                                if (v >= 70) return 'rgba(239,68,68,0.72)';
                                if (v >= 45) return 'rgba(249,115,22,0.72)';
                                return 'rgba(16,185,129,0.72)';
                            }
                        },
                        barMaxWidth: 20
                    },
                    {
                        name: 'Latence p95 (ms)',
                        type: 'line',
                        yAxisIndex: 1,
                        smooth: true,
                        data: latency,
                        lineStyle: { width: 2, color: '#a78bfa' },
                        itemStyle: { color: '#a78bfa' }
                    }
                ],
                grid: { top: 30, right: 42, bottom: 38, left: 52 }
            });
            segChart.off('click');
            segChart.on('click', (params) => {
                const idx = Number(params?.dataIndex);
                if (!Number.isFinite(idx) || idx < 0 || idx >= segRows.length) return;
                const segName = segRows[idx]?.segment || '';
                this.setMultiSegmentFilter(segName);
            });
        } else {
            this.destroyChart('multiSegmentHealthChart');
            if (segDom) segDom.innerHTML = '<div class="adv-empty"><span>🧪</span><p>Santé segments indisponible</p></div>';
        }

        const chainDom = document.getElementById('multiEquipmentChainGraph');
        const chainNodes = Array.isArray(equipmentChain.nodes) ? equipmentChain.nodes : [];
        const chainLinks = Array.isArray(equipmentChain.links) ? equipmentChain.links : [];
        this.multiGlobalChainNodeByCapture = {};
        this.multiGlobalChainEdgeByPair = {};
        if (chainDom && chainNodes.length && typeof echarts !== 'undefined') {
            const chart = this.initChart('multiEquipmentChainGraph');
            if (chart) {
                const nodes = chainNodes
                    .slice()
                    .sort((a, b) => Number(a.capture_index || 0) - Number(b.capture_index || 0))
                    .map((n, idx) => {
                        const cIdx = Number(n.capture_index || idx);
                        this.multiGlobalChainNodeByCapture[cIdx] = idx;
                        const p = Number(n.packet_count || 0);
                        const symbolSize = Math.max(44, Math.min(70, 44 + Math.log10(Math.max(1, p)) * 8));
                        return {
                            name: String(n.equipment_name || `Point ${cIdx + 1}`),
                            captureIndex: cIdx,
                            value: p,
                            x: 76 + idx * 220,
                            y: 122 + ((idx % 2 === 0) ? -10 : 10),
                            symbolSize,
                            itemStyle: {
                                color: '#38bdf8',
                                borderWidth: 2,
                                borderColor: '#0b1220',
                                shadowBlur: 10,
                                shadowColor: 'rgba(56,189,248,0.5)',
                            },
                            label: { color: '#e2e8f0', fontSize: 12, fontWeight: 600 },
                        };
                    });

                const links = chainLinks.map((l, idx) => {
                    const fromIdx = Number(l.from_capture_index || 0);
                    const toIdx = Number(l.to_capture_index || fromIdx + 1);
                    this.multiGlobalChainEdgeByPair[`${fromIdx}->${toIdx}`] = idx;
                    const avg = Number(l.avg_score || 0);
                    const color = avg >= 70 ? '#ef4444' : (avg >= 45 ? '#f97316' : '#10b981');
                    const latency = Number(l.latency_p95_ms || 0);
                    const triggerRatio = Number(l.trigger_ratio || 0);
                    return {
                        source: String(l.from_equipment || ''),
                        target: String(l.to_equipment || ''),
                        fromCaptureIndex: fromIdx,
                        toCaptureIndex: toIdx,
                        avgScore: avg,
                        triggerRatio,
                        value: Number.isFinite(latency) ? `${latency.toFixed(1)} ms` : 'n/a',
                        lineStyle: {
                            color,
                            width: Math.max(2.2, Math.min(8, 2 + avg / 22)),
                            opacity: Math.max(0.55, Math.min(1, 0.55 + triggerRatio * 0.55)),
                            curveness: 0.08,
                        },
                        label: {
                            show: true,
                            formatter: `${Math.round(avg)}`,
                            color: '#94a3b8',
                            fontSize: 10,
                        },
                    };
                });

                chart.setOption({
                    backgroundColor: 'transparent',
                    tooltip: { trigger: 'item', confine: true },
                    animationDuration: 320,
                    series: [{
                        type: 'graph',
                        layout: 'none',
                        roam: true,
                        data: nodes,
                        links,
                        edgeSymbol: ['none', 'arrow'],
                        edgeSymbolSize: [4, 10],
                        lineStyle: { width: 2, opacity: 0.9, curveness: 0.08 },
                        emphasis: { focus: 'adjacency' },
                    }],
                    grid: { left: 0, right: 0, top: 0, bottom: 0 },
                });

                chart.off('click');
                chart.on('click', (params) => {
                    if (params?.dataType === 'node') {
                        const eq = String(params?.data?.name || '').trim();
                        const cIdx = Number(params?.data?.captureIndex);
                        if (eq) this.filterMultiByEquipment(eq);
                        const session = this.getMultiPcapSessions().find((s) => s.session_id === this.multiSelectedSessionId);
                        if (session && Number.isFinite(cIdx)) this.focusMultiHop(session, cIdx, { syncTimeline: true, syncChain: true });
                        return;
                    }
                    if (params?.dataType === 'edge') {
                        const seg = `${String(params?.data?.source || '')} -> ${String(params?.data?.target || '')}`;
                        this.setMultiSegmentFilter(seg);
                        const session = this.getMultiPcapSessions().find((s) => s.session_id === this.multiSelectedSessionId);
                        const toIdx = Number(params?.data?.toCaptureIndex);
                        if (session && Number.isFinite(toIdx)) this.focusMultiHop(session, toIdx, { syncTimeline: true, syncChain: true });
                    }
                });
            }
        } else {
            this.destroyChart('multiEquipmentChainGraph');
            if (chainDom) chainDom.innerHTML = '<div class="adv-empty"><span>🕸️</span><p>Chaîne globale indisponible</p></div>';
        }

        const culpritBody = document.querySelector('#multiCulpritTable tbody');
        if (culpritBody) {
            if (!culprits.length) {
                culpritBody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-tertiary);padding:1rem;">Aucun suspect consolidé</td></tr>';
            } else {
                culpritBody.innerHTML = culprits.slice(0, 20).map((row) => {
                    const causes = Array.isArray(row.top_causes) ? row.top_causes : [];
                    const ips = Array.isArray(row.top_ips) ? row.top_ips : [];
                    const confidence = Number(row.confidence || 0);
                    const confClass = confidence >= 75 ? 'HIGH' : (confidence >= 45 ? 'MEDIUM' : 'LOW');
                    return `
                    <tr>
                        <td><strong>${this.escapeHtml(row.equipment_name || '-')}</strong></td>
                        <td><span class="risk-badge ${this.sanitizeClassToken(Number(row.score || 0) >= 70 ? 'HIGH' : (Number(row.score || 0) >= 40 ? 'MEDIUM' : 'LOW'))}">${Number(row.score || 0)}</span></td>
                        <td><span class="state-badge ${this.sanitizeClassToken(confClass)}">${confidence}%</span></td>
                        <td>${Number(row.sessions || 0)}</td>
                        <td>${Number(row.high_risk_sessions || 0)}</td>
                        <td>${this.escapeHtml(causes.map((c) => `${c.code}:${c.count}`).join(' | ') || '-')}</td>
                        <td>${this.escapeHtml(ips.join(', ') || '-')}</td>
                        <td>
                            <button class="action-btn view" onclick='analyzer.filterMultiByEquipment(${JSON.stringify(row.equipment_name || '')})'>🎯 Filtrer</button>
                        </td>
                    </tr>
                    `;
                }).join('');
            }
        }
    }

    hydrateMultiFilterSelects() {
        const protoSelect = document.getElementById('multiProtocolFilter');
        if (!protoSelect) return;

        const sessions = this.getMultiPcapSessions();
        const current = protoSelect.value || '';
        const protocols = Array.from(new Set(sessions.map((s) => String(s.protocol || '').toUpperCase()).filter(Boolean))).sort();
        protoSelect.innerHTML = `<option value="">Tous protocoles</option>${protocols.map((p) => `<option value="${this.escapeHtml(p)}">${this.escapeHtml(p)}</option>`).join('')}`;
        if (protocols.includes(current)) protoSelect.value = current;
    }

    applyMultiPcapToGlobalSummaryCards(summary) {
        const packets = Number(summary.total_packets_observed || 0);
        const bytes = Number(summary.total_bytes_observed || 0);
        const sessions = Number(summary.correlated_sessions || 0);
        const problematic = Number(summary.problematic_sessions || 0);
        const riskRatio = sessions > 0 ? (problematic / sessions) : 0;
        const riskLevel = riskRatio >= 0.35 ? 'HIGH' : (riskRatio >= 0.15 ? 'MEDIUM' : (problematic > 0 ? 'LOW' : 'NONE'));

        const setText = (id, value) => {
            const el = document.getElementById(id);
            if (el) el.textContent = value;
        };

        setText('totalPackets', packets.toLocaleString('fr-FR'));
        setText('totalBytes', this.formatBytesShort(bytes));
        setText('tcpSessions', sessions.toLocaleString('fr-FR'));
        setText('riskLevel', riskLevel);
        setText('anomalyCount', `${problematic.toLocaleString('fr-FR')} sessions problématiques`);

        const riskCard = document.getElementById('riskCard');
        if (riskCard) riskCard.setAttribute('data-risk', riskLevel);

        setText('signalPackets', `Paquets: ${packets.toLocaleString('fr-FR')}`);
        setText('signalRisk', `Risque: ${riskLevel}`);
        const topProto = Object.entries(summary.sessions_by_protocol || {}).sort((a, b) => Number(b[1] || 0) - Number(a[1] || 0))[0]?.[0] || '-';
        setText('signalDominantProto', `Top protocole: ${topProto}`);
        const topCause = Array.isArray(summary.top_causes) ? summary.top_causes[0]?.cause : '';
        if (topCause) {
            setText('anomalyCount', `${problematic.toLocaleString('fr-FR')} sessions problématiques • cause #1: ${this.truncate(topCause, 42)}`);
        }
        this.updateNetworkVisualStateFromMultiSummary(summary, riskLevel, problematic, sessions);

        const metaLabel = document.getElementById('analysisMetaLabel');
        if (metaLabel) {
            metaLabel.textContent = `Analyse multi-PCAP: ${sessions.toLocaleString('fr-FR')} sessions corrélées, ${problematic.toLocaleString('fr-FR')} problématiques.`;
        }

        // Si pas d'analyse mono-PCAP chargée, éviter les tirets sur les cartes secondaires.
        if (!this.currentResults) {
            setText('dnsQueries', '-');
            setText('httpRequests', '-');
            setText('tlsSessions', '-');
            setText('uniqueDomains', '-');
        }

        this.applyFocusInvestigation();
    }

    updateMultiFilteredStats(filteredSessions) {
        const setText = (id, value) => {
            const el = document.getElementById(id);
            if (el) el.textContent = String(value ?? '-');
        };

        const filteredCount = filteredSessions.length;
        const avgRisk = filteredCount
            ? (filteredSessions.reduce((acc, s) => acc + Number(s.risk_score || 0), 0) / filteredCount)
            : 0;
        const latencyValues = filteredSessions
            .map((s) => Number(s.latency_total_ms))
            .filter((v) => Number.isFinite(v));
        const avgLatency = latencyValues.length
            ? latencyValues.reduce((acc, v) => acc + v, 0) / latencyValues.length
            : null;

        setText('multiFilteredSessions', filteredCount.toLocaleString('fr-FR'));
        setText('multiAvgRisk', avgRisk.toFixed(1));
        const slowest = latencyValues.length ? Math.max(...latencyValues) : null;
        if (slowest !== null) {
            setText('multiSlowestSegment', `${slowest.toFixed(1)} ms`);
        } else {
            setText('multiSlowestSegment', this.multiPcapResults?.latency?.slowest_segment || '-');
        }

        const avgLatencyEl = document.getElementById('multiAnalyzeStatus');
        if (avgLatencyEl && avgLatency !== null) {
            avgLatencyEl.textContent = `Analyse terminée (task: ${this.multiPcapTaskId}) • Latence moyenne filtrée: ${avgLatency.toFixed(2)} ms`;
        }
    }

    renderMultiPcapResults() {
        const section = document.getElementById('multiResultsSection');
        if (!section) return;

        if (!this.multiPcapResults) {
            section.style.display = 'none';
            this.destroyMultiHopVisuals();
            this.destroyChart('multiEquipmentChainGraph');
            this.destroyChart('multiBandwidthChainChart');
            return;
        }

        section.style.display = 'block';
        const summary = this.multiPcapResults.summary || {};
        const latency = this.multiPcapResults.latency || {};

        const setText = (id, value) => {
            const el = document.getElementById(id);
            if (el) el.textContent = String(value ?? '-');
        };

        setText('multiTotalCaptures', Number(summary.total_capture_points || 0).toLocaleString('fr-FR'));
        setText('multiCorrelatedSessions', Number(summary.correlated_sessions || 0).toLocaleString('fr-FR'));
        setText('multiProblemSessions', Number(summary.problematic_sessions || 0).toLocaleString('fr-FR'));
        setText('multiSlowestSegment', latency.slowest_segment || '-');
        const packetsObserved = Number(summary.total_packets_observed || 0);
        const bytesObserved = Number(summary.total_bytes_observed || 0);
        setText('multiTotalPacketsObserved', packetsObserved.toLocaleString('fr-FR'));
        setText('multiTotalBytesObserved', this.formatBytesShort(bytesObserved));
        const thr = this.multiPcapResults?.thresholds_applied || summary.thresholds_applied || {};
        const thrInfo = document.getElementById('multiThresholdInfo');
        if (thrInfo) {
            thrInfo.textContent = `Seuils actifs: retrans ${((Number(thr.retrans_increase_medium || 0.03)) * 100).toFixed(1)}%/${((Number(thr.retrans_increase_high || 0.08)) * 100).toFixed(1)}% • latence ${Number(thr.latency_segment_medium_ms || 60)}ms/${Number(thr.latency_segment_high_ms || 120)}ms • trigger ${Number(thr.segment_trigger_score || 45)}`;
        }

        this.hydrateMultiFilterSelects();
        this.renderMultiCauseChips();
        this.renderMultiBottleneckSection();
        this.renderMultiPcapInsights();
        this.applyMultiPcapToGlobalSummaryCards(summary);
        this.renderMultiPcapSessionsTable();
    }

    renderMultiPcapSessionsTable() {
        const tbody = document.querySelector('#multiSessionsTable tbody');
        if (!tbody) return;
        if (!this.multiPcapResults) {
            tbody.innerHTML = '<tr><td colspan="10" style="text-align:center;color:var(--text-tertiary);padding:1rem;">Aucun résultat multi-PCAP</td></tr>';
            return;
        }

        let sessions = this.getMultiFilteredSessions();
        this.updateMultiFilteredStats(sessions);

        if (!sessions.length) {
            tbody.innerHTML = '<tr><td colspan="10" style="text-align:center;color:var(--text-tertiary);padding:1rem;">Aucune session à afficher</td></tr>';
            const detailContainer = document.getElementById('multiSessionDetailContainer');
            if (detailContainer) detailContainer.style.display = 'none';
            this.destroyMultiHopVisuals();
            return;
        }

        // Borner le rendu: au-delà de 200 lignes le DOM devient le goulot
        const MAX_ROWS = 200;
        const truncated = sessions.length > MAX_ROWS;
        const visibleSessions = truncated ? sessions.slice(0, MAX_ROWS) : sessions;

        tbody.innerHTML = visibleSessions.map((s) => {
            const presenceList = Array.isArray(s.presence) ? s.presence : [];
            const present = presenceList.filter((p) => p.present).map((p) => p.equipment_name).filter(Boolean);
            const presenceLabel = present.length ? present.join(' → ') : '-';
            const presenceBadges = present.map((name) => (
                `<button class="multi-presence-chip" onclick='event.stopPropagation(); analyzer.filterMultiByEquipment(${JSON.stringify(name)})'>${this.escapeHtml(name)}</button>`
            )).join('');
            const changesCount = Array.isArray(s.changes) ? s.changes.length : 0;
            const risk = Number(s.risk_score || 0);
            const riskLevel = risk >= 70 ? 'HIGH' : (risk >= 40 ? 'MEDIUM' : (risk > 0 ? 'LOW' : 'NONE'));
            const causeCode = s.probable_cause_code || this.getCauseCodeFromLabel(s.probable_cause || '');
            const causeClass = this.getCauseBadgeClass(causeCode);
            const latencyMs = s.latency_total_ms === null || s.latency_total_ms === undefined
                ? '-'
                : `${Number(s.latency_total_ms).toFixed(2)} ms`;
            const selectedClass = this.multiSelectedSessionId === s.session_id ? ' selected' : '';
            return `
            <tr class="multi-session-row${selectedClass}" onclick='analyzer.showMultiSessionDetails(${JSON.stringify(s.session_id)})'>
                <td>${this.escapeHtml(s.session_id || '-')}</td>
                <td title="${this.escapeHtml(s.flow_label || '-')}"><code>${this.escapeHtml(this.truncate(s.flow_label || '-', 70))}</code></td>
                <td><span class="protocol-badge ${this.sanitizeClassToken(s.protocol || '')}">${this.escapeHtml(s.protocol || '-')}</span></td>
                <td title="${this.escapeHtml(presenceLabel)}">${presenceBadges || this.escapeHtml(this.truncate(presenceLabel, 65))}</td>
                <td><span class="risk-badge ${this.sanitizeClassToken(riskLevel)}">${risk}</span></td>
                <td title="${this.escapeHtml(s.probable_cause || '-')}">
                    <button class="multi-cause-link" onclick='event.stopPropagation(); analyzer.setMultiCauseFilter(${JSON.stringify(s.probable_cause || "")})'>
                        <span class="${causeClass}">${this.escapeHtml(this.truncate(s.probable_cause || '-', 75))}</span>
                    </button>
                </td>
                <td>${this.escapeHtml(latencyMs)}</td>
                <td><span class="state-badge ${this.sanitizeClassToken(s.confidence_level || '')}">${this.escapeHtml(s.confidence_level || '-')}</span></td>
                <td>${changesCount}</td>
                <td>
                    <button class="action-btn view" onclick='event.stopPropagation(); analyzer.showMultiSessionDetails(${JSON.stringify(s.session_id)})'>📦 Détails</button>
                </td>
            </tr>
            `;
        }).join('') + (truncated
            ? `<tr><td colspan="10" style="text-align:center;color:var(--text-tertiary);padding:0.75rem;">${sessions.length - MAX_ROWS} sessions supplémentaires — affinez les filtres pour les voir</td></tr>`
            : '');

        const selected = this.multiSelectedSessionId
            ? sessions.find((s) => s.session_id === this.multiSelectedSessionId)
            : sessions[0];
        // Ne reconstruire le panneau détail (vis.Timeline + ECharts) que si
        // la sélection change réellement — pas à chaque frappe de filtre
        if (selected && selected.session_id !== this.multiRenderedDetailSessionId) {
            this.showMultiSessionDetails(selected.session_id, true);
        }
    }

    /**
     * Fenêtre de réception effective maximale d'un hop, toutes directions
     * confondues (windows.client_to_server / server_to_client).
     */
    getHopEffectiveWindowMax(hop) {
        const windows = (hop && typeof hop.windows === 'object' && hop.windows) ? hop.windows : {};
        const values = ['client_to_server', 'server_to_client']
            .map((dir) => Number((windows[dir] || {}).effective_max))
            .filter((v) => Number.isFinite(v) && v > 0);
        return values.length ? Math.max(...values) : null;
    }

    /**
     * Panneau « facteur limitant » d'une session: classe, raison, débit observé
     * face aux bornes théoriques (fenêtre / pertes), RTT et fenêtre effective.
     */
    buildSessionFlowLimitationHtml(session) {
        const limitation = (session && typeof session.flow_limitation === 'object' && session.flow_limitation)
            ? session.flow_limitation
            : null;
        if (!limitation) {
            return '<p class="bnk-muted">Classification du facteur limitant indisponible pour ces résultats.</p>';
        }

        const cls = String(limitation.class || 'UNKNOWN').toUpperCase();
        const hops = Array.isArray(session.hops) ? session.hops : [];
        const rtts = hops
            .map((h) => Number(h?.handshake_rtt_ms))
            .filter((v) => Number.isFinite(v) && v > 0);
        const windowMaxes = hops
            .map((h) => this.getHopEffectiveWindowMax(h))
            .filter((v) => Number.isFinite(v) && v > 0);

        const observed = Number(limitation.observed_mbps);
        const windowLimit = Number(limitation.window_limited_mbps);
        const lossLimit = Number(limitation.loss_limited_mbps);
        // Jauge: part du débit observé par rapport à la borne fenêtre
        const ratio = (Number.isFinite(observed) && Number.isFinite(windowLimit) && windowLimit > 0)
            ? Math.max(2, Math.min(100, (observed / windowLimit) * 100))
            : null;

        return `
            <div class="bnk-flow-panel">
                <div class="bnk-flow-class bnk-flow-${this.sanitizeClassToken(cls)}">
                    ${this.escapeHtml(this.getFlowLimitationLabel(cls))}
                </div>
                <p class="bnk-flow-reason">${this.escapeHtml(limitation.reason || 'Aucune explication fournie.')}</p>
                <div class="bnk-flow-metrics">
                    <div><span>Débit observé</span><strong>${this.formatBottleneckMetric(limitation.observed_mbps, 'Mbps')}</strong></div>
                    <div><span>Borne fenêtre (rwnd/RTT)</span><strong>${this.formatBottleneckMetric(limitation.window_limited_mbps, 'Mbps')}</strong></div>
                    <div><span>Borne pertes (Mathis)</span><strong>${this.formatBottleneckMetric(limitation.loss_limited_mbps, 'Mbps')}</strong></div>
                    <div><span>RTT handshake (min)</span><strong>${rtts.length ? `${Math.min(...rtts).toFixed(2)} ms` : '-'}</strong></div>
                    <div><span>Fenêtre effective max</span><strong>${windowMaxes.length ? this.formatBytesShort(Math.max(...windowMaxes)) : '-'}</strong></div>
                </div>
                ${ratio === null ? '' : `
                <div class="bnk-flow-gauge" title="Part du débit observé par rapport à la borne fenêtre">
                    <span style="width:${ratio.toFixed(1)}%"></span>
                </div>
                <div class="bnk-muted">${ratio.toFixed(0)} % de la borne fenêtre atteints</div>`}
            </div>`;
    }

    showMultiSessionDetails(sessionId, silent = false) {
        const sessions = this.getMultiPcapSessions();
        const session = sessions.find((s) => s.session_id === sessionId);
        if (!session) {
            if (!silent) this.showToast('warning', 'Multi-PCAP', `Session introuvable: ${sessionId}`);
            return;
        }
        this.multiSelectedSessionId = sessionId;
        this.multiRenderedDetailSessionId = sessionId;

        const title = document.getElementById('multiSessionDetailTitle');
        if (title) title.textContent = `#${session.session_id}`;

        const container = document.getElementById('multiSessionDetailContainer');
        const body = document.getElementById('multiSessionDetailBody');
        if (!container || !body) return;

        const hops = Array.isArray(session.hops) ? session.hops : [];
        const changes = Array.isArray(session.changes) ? session.changes : [];
        const latencyRows = Array.isArray(session.latency_by_hop) ? session.latency_by_hop : [];
        const rootSignals = Array.isArray(session.root_cause_signals) ? session.root_cause_signals : [];
        const degradation = this.getMultiSessionDegradationContext(session);
        const degradationSegments = degradation.segments || [];
        const primaryDegradation = degradation.primary;
        const causeCode = session.probable_cause_code || this.getCauseCodeFromLabel(session.probable_cause || '');

        const hopRows = hops.map((hop) => {
            const tcp = hop.tcp_metrics || {};
            const windowAvg = tcp.window?.avg !== undefined ? Number(tcp.window.avg).toFixed(1) : '-';
            const mss = Array.isArray(tcp.mss_values) ? tcp.mss_values.join(', ') : '-';
            const dscp = Array.isArray(hop.dscp_values) ? hop.dscp_values.join(', ') : '-';
            const ttl = hop.ttl?.avg !== undefined ? Number(hop.ttl.avg).toFixed(1) : '-';
            // RTT du handshake et fenêtre effective max observés à ce point
            const rttMs = Number(hop.handshake_rtt_ms);
            const rttLabel = Number.isFinite(rttMs) && hop.handshake_rtt_ms !== null ? `${rttMs.toFixed(2)} ms` : '-';
            const effMax = this.getHopEffectiveWindowMax(hop);
            const effLabel = effMax === null ? '-' : this.formatBytesShort(effMax);
            return `
            <tr class="multi-hop-row" data-hop-index="${Number(hop.capture_index || 0)}" onclick="analyzer.focusCurrentMultiHop(${Number(hop.capture_index || 0)})">
                <td>${this.escapeHtml(hop.equipment_name || '-')}</td>
                <td><span class="state-badge ${this.sanitizeClassToken(hop.state || '')}">${this.escapeHtml(hop.state || '-')}</span></td>
                <td>${Number(hop.packet_count || 0).toLocaleString('fr-FR')}</td>
                <td>${this.formatBytesShort(Number(hop.byte_count || 0))}</td>
                <td>${ttl}</td>
                <td>${this.escapeHtml(dscp || '-')}</td>
                <td>${this.escapeHtml(mss || '-')}</td>
                <td>${windowAvg}</td>
                <td>${this.escapeHtml(effLabel)}</td>
                <td>${this.escapeHtml(rttLabel)}</td>
                <td>${Number(tcp.retransmissions || 0)}</td>
                <td>${Number(tcp.rst || 0)}</td>
                <td>${Number(hop.duration_seconds || 0).toFixed(3)}s</td>
            </tr>`;
        }).join('');

        const flowLimitationHtml = this.buildSessionFlowLimitationHtml(session);

        const changesHtml = changes.length
            ? `<ul class="multi-session-list">${changes.map((c) => (
                `<li><span class="risk-badge ${this.sanitizeClassToken(c.severity || '')}">${this.escapeHtml(c.severity || '-')}</span> 
                <strong>${this.escapeHtml(c.hop || '')}</strong> — ${this.escapeHtml(c.description || '')}</li>`
            )).join('')}</ul>`
            : '<p style="color:var(--text-muted);">Aucun changement significatif détecté.</p>';

        const latencyHtml = latencyRows.length
            ? `<ul class="multi-session-list">${latencyRows.map((l) => (
                `<li><strong>${this.escapeHtml(l.segment || '-')}</strong>: ${Number(l.latency_ms || 0).toFixed(2)} ms 
                <span class="state-badge ${this.sanitizeClassToken(l.confidence || '')}">${this.escapeHtml(l.confidence || '-')}</span></li>`
            )).join('')}</ul>`
            : '<p style="color:var(--text-muted);">Latence indisponible (pas assez de points corrélés).</p>';

        const rootSignalsHtml = rootSignals.length
            ? `<ul class="multi-session-list">${rootSignals.map((r) => (
                `<li><span class="${this.getCauseBadgeClass(r.code || 'watch')}">${this.escapeHtml(r.label || '-')}</span>
                <strong>+${Number(r.weight || 0)}</strong> • ${this.escapeHtml(r.severity || 'LOW')}<br>
                <span style="color:var(--text-muted)">${this.escapeHtml(r.evidence || '')}</span></li>`
            )).join('')}</ul>`
            : '<p style="color:var(--text-muted);">Aucun signal root-cause déclenché.</p>';

        const degradationHtml = degradationSegments.length
            ? `<ul class="multi-session-list">${degradationSegments.slice(0, 6).map((d) => (
                `<li>
                    <span class="risk-badge ${this.sanitizeClassToken(d.severity || 'LOW')}">${Number(d.score || 0)}</span>
                    <strong>${this.escapeHtml(d.segment || '-')}</strong>
                    ${d.triggered ? '<span class="state-badge HIGH">TRIGGER</span>' : ''}
                    ${d.latency_ms !== null && d.latency_ms !== undefined ? `• ${Number(d.latency_ms).toFixed(2)} ms` : ''}<br>
                    <span style="color:var(--text-muted)">${this.escapeHtml((Array.isArray(d.reasons) ? d.reasons[0] : '') || '')}</span>
                </li>`
            )).join('')}</ul>`
            : '<p style="color:var(--text-muted);">Aucun segment scoré.</p>';

        body.innerHTML = `
            <div class="multi-session-summary-grid">
                <div><span class="stream-kpi-label">Flux</span><div><code>${this.escapeHtml(session.flow_label || '-')}</code></div></div>
                <div><span class="stream-kpi-label">Risque</span><div><span class="risk-badge ${this.sanitizeClassToken(session.risk_score >= 70 ? 'HIGH' : session.risk_score >= 40 ? 'MEDIUM' : 'LOW')}">${Number(session.risk_score || 0)}</span></div></div>
                <div><span class="stream-kpi-label">Cause probable</span><div><span class="${this.getCauseBadgeClass(causeCode)}">${this.escapeHtml(session.probable_cause || '-')}</span></div></div>
                <div><span class="stream-kpi-label">Latence cumulée</span><div>${session.latency_total_ms === null || session.latency_total_ms === undefined ? '-' : `${Number(session.latency_total_ms).toFixed(2)} ms`}</div></div>
                <div><span class="stream-kpi-label">Segment déclencheur</span><div>${this.escapeHtml(primaryDegradation?.segment || '-')}</div></div>
                <div><span class="stream-kpi-label">Facteur limitant</span><div>${this.escapeHtml(this.getFlowLimitationLabel((session.flow_limitation || {}).class || 'UNKNOWN'))}</div></div>
            </div>
            <h4>Vue multi-hop synchronisée</h4>
            <div class="multi-session-timeline-wrap">
                <div class="multi-visual-controls">
                    <label class="filter-toggle">
                        <input type="checkbox" id="multiAutoDegradationToggle" ${this.multiAutoDegradationEnabled ? 'checked' : ''}>
                        <span>Mode dégradation auto</span>
                    </label>
                    <span class="stream-subtitle">Surbrillance automatique du segment déclencheur selon score root-cause + seuils latence</span>
                </div>
                <div class="multi-session-visual-grid">
                    <div>
                        <h5 class="multi-visual-title">Timeline</h5>
                        <div id="multiSessionTimelineVis" class="multi-session-timeline"></div>
                    </div>
                    <div>
                        <h5 class="multi-visual-title">Chaîne d'équipements</h5>
                        <div id="multiSessionChainGraph" class="multi-session-chain-graph"></div>
                    </div>
                </div>
                <div id="multiTimelineFocus" class="multi-timeline-focus"></div>
            </div>
            <h4>Présence et métriques par point</h4>
            <div class="table-wrapper">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Équipement</th>
                            <th>État</th>
                            <th>Paquets</th>
                            <th>Volume</th>
                            <th>TTL(avg)</th>
                            <th>DSCP</th>
                            <th>MSS</th>
                            <th>Window(avg)</th>
                            <th title="Fenêtre de réception effective maximale (scale appliqué)">Fenêtre eff. max</th>
                            <th title="RTT mesuré sur le handshake TCP à ce point">RTT handshake</th>
                            <th>Retrans</th>
                            <th>RST</th>
                            <th>Durée</th>
                        </tr>
                    </thead>
                    <tbody>${hopRows || '<tr><td colspan="13">Aucune donnée</td></tr>'}</tbody>
                </table>
            </div>
            <div class="multi-session-detail-grid">
                <div>
                    <h4>Pourquoi ce flux ne va pas plus vite&nbsp;?</h4>
                    ${flowLimitationHtml}
                </div>
                <div>
                    <h4>Changements détectés (${changes.length})</h4>
                    ${changesHtml}
                </div>
                <div>
                    <h4>Latence par segment</h4>
                    ${latencyHtml}
                </div>
                <div>
                    <h4>Root-cause scoring</h4>
                    ${rootSignalsHtml}
                </div>
                <div>
                    <h4>Dégradation auto (segments)</h4>
                    ${degradationHtml}
                </div>
            </div>
        `;

        container.style.display = 'block';
        this.renderMultiSessionTimeline(session);
        this.renderMultiSessionChainGraph(session);
        const firstHopIndex = (this.multiAutoDegradationEnabled && primaryDegradation)
            ? Number(primaryDegradation.to_capture_index)
            : (hops.length ? Math.min(...hops.map((h) => Number(h?.capture_index || 0))) : 0);
        this.focusMultiHop(session, firstHopIndex, { syncTimeline: true, syncChain: true });

        const autoToggle = document.getElementById('multiAutoDegradationToggle');
        if (autoToggle) {
            autoToggle.onchange = () => this.setMultiAutoDegradationMode(Boolean(autoToggle.checked));
        }
        if (!silent) {
            this.renderMultiPcapSessionsTable();
            try {
                container.scrollIntoView({ behavior: 'smooth', block: 'start' });
            } catch (_) { /* no-op */ }
            this.showToast('info', 'Multi-PCAP', `Détails ${session.session_id}`);
        }
    }

    async exportMultiPcapCsv() {
        if (!this.multiPcapTaskId) {
            this.showToast('warning', 'Multi-PCAP', 'Aucun résultat à exporter');
            return;
        }
        const onlyProblems = Boolean(document.getElementById('multiProblematicOnly')?.checked);
        try {
            const response = await fetch(
                `/api/multi-pcap/${this.multiPcapTaskId}/export/csv?problematic_only=${onlyProblems ? 'true' : 'false'}`,
                { cache: 'no-store' }
            );
            if (!response.ok) {
                const err = await response.json().catch(() => ({}));
                throw new Error(err?.detail || `HTTP ${response.status}`);
            }

            const blob = await response.blob();
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            const ts = new Date().toISOString().replace(/[:.]/g, '-');
            link.href = url;
            link.download = `multi_pcap_${this.multiPcapTaskId.slice(0, 8)}_${ts}.csv`;
            document.body.appendChild(link);
            link.click();
            link.remove();
            URL.revokeObjectURL(url);
            this.showToast('success', 'Multi-PCAP', 'Export CSV terminé');
        } catch (error) {
            console.error('Multi-PCAP export error:', error);
            this.showToast('error', 'Multi-PCAP', `Échec export CSV: ${error.message}`);
        }
    }

    async exportMultiPcapDfirJson() {
        if (!this.multiPcapTaskId) {
            this.showToast('warning', 'Multi-PCAP', 'Aucun résultat à exporter');
            return;
        }
        try {
            const response = await fetch(`/api/multi-pcap/${this.multiPcapTaskId}/export/dfir-report-json`, { cache: 'no-store' });
            const payload = await response.json().catch(() => ({}));
            if (!response.ok) {
                throw new Error(payload?.detail || `HTTP ${response.status}`);
            }
            const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            const ts = new Date().toISOString().replace(/[:.]/g, '-');
            link.href = url;
            link.download = `dfir_multi_pcap_${this.multiPcapTaskId.slice(0, 8)}_${ts}.json`;
            document.body.appendChild(link);
            link.click();
            link.remove();
            URL.revokeObjectURL(url);
            this.showToast('success', 'DFIR Export', 'Export DFIR JSON multi-PCAP terminé');
        } catch (error) {
            console.error('DFIR multi export error:', error);
            this.showToast('error', 'DFIR Export', `Échec export DFIR: ${error.message}`);
        }
    }

    // ==================== PACKETS ====================

    async loadPackets(forceRefresh = false) {
        if (!this.currentTaskId) return;
        if (!this.virtualScroll) {
            const container = document.getElementById('packetVirtualContainer');
            const spacer = document.getElementById('packetVirtualSpacer');
            const tbody = document.getElementById('packetTableBody');
            if (!container || !spacer || !tbody) return;
            this.virtualScroll = new VirtualScroll(container, spacer, tbody, 38);
        }

        if (!forceRefresh && this.packetsLoadedTaskId === this.currentTaskId && Array.isArray(this.allPackets)) {
            this.applyPacketFilters();
            this.updateFilterStats();
            const count = this.allPackets.length;
            this.setMenuHealthStatus('packets', count > 0 ? 'ok' : 'missing', count > 0 ? `${count.toLocaleString('fr-FR')} paquets (cache)` : 'Aucun paquet');
            return;
        }

        try {
            const response = await fetch(`/api/analysis/${this.currentTaskId}/packets?limit=10000`, { cache: 'no-store' });
            const data = await response.json();
            this.allPackets = data.packets || data || [];

            // Pre-compute index for fast filtering
            this.packetIndex = { byProto: {}, byIp: {} };
            this.allPackets.forEach((pkt, i) => {
                const proto = (pkt.protocol || '').toUpperCase();
                if (!this.packetIndex.byProto[proto]) this.packetIndex.byProto[proto] = [];
                this.packetIndex.byProto[proto].push(i);
                // Haystack précalculé une fois: évite JSON.stringify sur
                // 10 000 paquets à chaque frappe dans le filtre texte
                pkt._search = `${pkt.src_ip || ''} ${pkt.dst_ip || ''} ${pkt.src_mac || ''} ${pkt.dst_mac || ''} ` +
                    `${pkt.src_port || ''} ${pkt.dst_port || ''} ${pkt.protocol || ''} ${pkt.info || ''} ${pkt.length || ''}`.toLowerCase();
            });

            this.filteredPackets = this.allPackets;
            this.virtualScroll.setData(this.allPackets, (pkt, idx) => this.renderPacketRow(pkt, idx));
            this.updateFilterStats();
            this.setupResizableColumns();
            this.packetsLoadedTaskId = this.currentTaskId;
            this.setMenuHealthStatus('packets', this.allPackets.length > 0 ? 'ok' : 'missing', this.allPackets.length > 0 ? `${this.allPackets.length.toLocaleString('fr-FR')} paquets` : 'Aucun paquet');
        } catch (e) {
            console.error('Error loading packets:', e);
            this.packetsLoadedTaskId = '';
            this.setMenuHealthStatus('packets', 'error', `Erreur paquets: ${e.message}`);
        }
    }

    updateFilterStats() {
        const el = document.getElementById('filterStats');
        if (!el) return;
        const total = this.allPackets ? this.allPackets.length : 0;
        const filtered = this.filteredPackets ? this.filteredPackets.length : 0;
        el.textContent = filtered < total
            ? `${filtered.toLocaleString()} paquets affichés sur ${total.toLocaleString()}`
            : `${total.toLocaleString()} paquets`;
    }

    renderPacketRow(pkt, idx) {
        const proto = (pkt.protocol || 'other').toLowerCase();
        const protoClass = this.sanitizeClassToken(proto);
        const flags = pkt.tcp_flags || pkt.flags || '';
        const flagBadges = this.renderFlagBadges(flags);
        const packetNumber = this.escapeHtml(pkt.number || idx + 1);
        const packetTime = pkt.timestamp ? new Date(pkt.timestamp * 1000).toISOString().substring(11, 23) : (pkt.time || '-');
        const src = this.escapeHtml(pkt.src_ip || pkt.source || '-');
        const dst = this.escapeHtml(pkt.dst_ip || pkt.destination || '-');
        const protoLabel = this.escapeHtml((pkt.protocol || '-').toUpperCase());
        const length = this.escapeHtml(pkt.length || pkt.len || '-');
        const info = this.escapeHtml(pkt.info || '-');

        const tr = document.createElement('tr');
        tr.className = 'packet-row';
        tr.innerHTML = `
            <td style="font-family:monospace;font-size:0.8rem;color:var(--text-muted)">${packetNumber}</td>
            <td style="font-family:monospace;font-size:0.8rem">${this.escapeHtml(packetTime)}</td>
            <td style="font-family:monospace;font-size:0.8rem">${src}</td>
            <td style="font-family:monospace;font-size:0.8rem">${dst}</td>
            <td><span class="proto-badge ${protoClass}">${protoLabel}</span></td>
            <td style="font-size:0.8rem">${length}</td>
            <td>${flagBadges}</td>
            <td style="font-size:0.8rem;color:var(--text-muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${info}</td>
        `;
        tr.addEventListener('click', () => this.togglePacketDetail(tr, pkt));
        return tr;
    }

    renderFlagBadges(flags) {
        if (!flags) return '';
        const flagList = typeof flags === 'string' ? flags.split(/[,\s]+/) : Object.keys(flags).filter(f => flags[f]);
        return flagList.filter(Boolean).map(f =>
            `<span class="flag-badge ${this.sanitizeClassToken(f)}">${this.escapeHtml(String(f).toUpperCase())}</span>`
        ).join('');
    }

    togglePacketDetail(tr, pkt) {
        const packetNum = pkt.idx !== undefined ? pkt.idx :
            (pkt.packet_num !== undefined ? pkt.packet_num : null);
        if (packetNum !== null) {
            this.showPacketDetails(packetNum);
        }
    }

    // displayPackets/renderPagination/goToPacketPage supprimés:
    // remplacés par le virtual scroll (VirtualScroll + applyPacketFilters)

    filterPackets() {
        this.currentPacketPage = 1;
        this.loadPackets();
    }

    resetPacketFilters() {
        document.getElementById('packetProtocolFilter').value = '';
        document.getElementById('packetIpFilter').value = '';
        this.currentPacketPage = 1;
        this.loadPackets();
    }

    onPacketFilterInput(value) {
        clearTimeout(this._filterTimer);
        this._filterTimer = setTimeout(() => this.applyPacketFilters(), 150);
    }

    applyPacketFilters() {
        if (!this.allPackets || !this.virtualScroll) return;

        const text = (document.getElementById('packetFilterInput')?.value || '').trim();
        const protoFilter = document.getElementById('protoFilter')?.value || '';
        const useRegex = document.getElementById('regexToggle')?.checked || false;

        let results = this.allPackets;

        // Protocol filter (pre-computed index)
        if (protoFilter) {
            const indices = this.packetIndex?.byProto[protoFilter.toUpperCase()] || [];
            results = indices.map(i => this.allPackets[i]);
        }

        // Text filter (haystack précalculé au chargement)
        if (text) {
            try {
                const pattern = useRegex ? new RegExp(text, 'i') : null;
                const needle = text.toLowerCase();
                results = results.filter(pkt => {
                    const haystack = pkt._search !== undefined ? pkt._search : JSON.stringify(pkt).toLowerCase();
                    return pattern ? pattern.test(haystack) : haystack.includes(needle);
                });
            } catch (e) {
                // Invalid regex — ignore
            }
        }

        this.filteredPackets = results;
        this.virtualScroll.setFilteredData(results);
        this.updateFilterStats();
    }

    filterPacketsByProtocol(proto) {
        const select = document.getElementById('protoFilter');
        if (select) select.value = proto;
        const input = document.getElementById('packetFilterInput');
        if (input) input.value = '';
        this.applyPacketFilters();
        this.switchTab('packets');
    }

    filterPacketsByIp(ip) {
        const input = document.getElementById('packetFilterInput');
        if (input) input.value = ip;
        this.applyPacketFilters();
        this.switchTab('packets');
    }

    saveCurrentFilter() {
        const text = document.getElementById('packetFilterInput')?.value || '';
        const proto = document.getElementById('protoFilter')?.value || '';
        if (!text && !proto) return;

        const name = prompt('Nom du filtre:');
        if (!name) return;

        const filters = JSON.parse(sessionStorage.getItem('savedFilters') || '[]');
        filters.push({ name, text, proto });
        sessionStorage.setItem('savedFilters', JSON.stringify(filters));
        this.renderSavedFilters();
    }

    renderSavedFilters() {
        const container = document.getElementById('savedFilters');
        if (!container) return;
        const filters = JSON.parse(sessionStorage.getItem('savedFilters') || '[]');
        container.innerHTML = filters.map((f, i) => `
            <span class="filter-tag" onclick="analyzer.applySavedFilter(${i})">
                ${f.name}
                <span class="remove" onclick="event.stopPropagation();analyzer.removeSavedFilter(${i})">✕</span>
            </span>
        `).join('');
    }

    applySavedFilter(index) {
        const filters = JSON.parse(sessionStorage.getItem('savedFilters') || '[]');
        const f = filters[index];
        if (!f) return;
        const input = document.getElementById('packetFilterInput');
        const select = document.getElementById('protoFilter');
        if (input) input.value = f.text;
        if (select) select.value = f.proto;
        this.applyPacketFilters();
    }

    removeSavedFilter(index) {
        const filters = JSON.parse(sessionStorage.getItem('savedFilters') || '[]');
        filters.splice(index, 1);
        sessionStorage.setItem('savedFilters', JSON.stringify(filters));
        this.renderSavedFilters();
    }

    setupResizableColumns() {
        const table = document.getElementById('packetTable');
        if (!table) return;

        table.querySelectorAll('th').forEach(th => {
            const resizer = th.querySelector('.col-resizer');
            if (!resizer) return;
            // Ne pas empiler un listener à chaque rechargement des paquets
            if (resizer.dataset.bound === '1') return;
            resizer.dataset.bound = '1';

            let startX, startWidth;
            resizer.addEventListener('mousedown', (e) => {
                e.preventDefault();
                startX = e.clientX;
                startWidth = th.offsetWidth;
                resizer.classList.add('resizing');

                const onMove = (e) => {
                    th.style.width = Math.max(60, startWidth + e.clientX - startX) + 'px';
                    this.virtualScroll?.render();
                };
                const onUp = () => {
                    resizer.classList.remove('resizing');
                    document.removeEventListener('mousemove', onMove);
                    document.removeEventListener('mouseup', onUp);
                };
                document.addEventListener('mousemove', onMove);
                document.addEventListener('mouseup', onUp);
            });
        });
    }

    // ==================== ECHARTS HELPERS ====================

    getEChartsTheme() {
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        return {
            isDark,
            textColor: isDark ? '#94a3b8' : '#64748b',
            textPrimary: isDark ? '#f8fafc' : '#0f172a',
            grid: isDark ? 'rgba(148,163,184,0.08)' : 'rgba(100,116,139,0.1)',
            tooltip: {
                backgroundColor: isDark ? 'rgba(15,23,42,0.92)' : 'rgba(255,255,255,0.96)',
                borderColor: isDark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.08)',
                textStyle: { color: isDark ? '#f8fafc' : '#0f172a', fontFamily: 'Space Grotesk, sans-serif', fontSize: 13 }
            },
            colors: ['#0ea5a4', '#f97316', '#10b981', '#f59e0b', '#ef4444', '#ec4899', '#0ea5e9', '#64748b']
        };
    }

    initChart(domId) {
        const dom = document.getElementById(domId);
        if (!dom) return null;
        const existing = echarts.getInstanceByDom(dom);
        if (existing && !existing.isDisposed()) {
            existing.clear();
            this.echartsInstances[domId] = existing;
            return existing;
        }
        const chart = echarts.init(dom, null, { renderer: 'canvas' });
        this.echartsInstances[domId] = chart;
        return chart;
    }

    destroyChart(domId) {
        if (this.echartsInstances[domId]) {
            this.echartsInstances[domId].dispose();
            delete this.echartsInstances[domId];
        }
    }

    resetZoom(chartKey) {
        // Try by key first, then by domId
        const chart = this.echartsInstances[chartKey] || this.echartsInstances[chartKey + 'Chart'];
        if (chart && !chart.isDisposed()) {
            chart.dispatchAction({ type: 'dataZoom', start: 0, end: 100 });
        }
    }

    fullscreenChart(domId) {
        const dom = document.getElementById(domId);
        if (!dom) return;
        if (!document.fullscreenElement) {
            dom.requestFullscreen().then(() => {
                const chart = echarts.getInstanceByDom(dom);
                if (chart) setTimeout(() => chart.resize(), 200);
            }).catch(() => { });
        } else {
            document.exitFullscreen();
        }
    }

    // ==================== CHARTS ====================

    buildTimeSeries(packetsIndex) {
        if (!packetsIndex || !packetsIndex.length) return [];
        // Group packets into 1-second buckets, then format for ECharts
        const buckets = {};
        packetsIndex.forEach(pkt => {
            const ts = pkt.timestamp;
            if (!ts) return;
            const sec = Math.floor(ts);
            buckets[sec] = (buckets[sec] || 0) + 1;
        });
        return Object.entries(buckets)
            .sort(([a], [b]) => Number(a) - Number(b))
            .map(([ts, count]) => ({
                timestamp: new Date(Number(ts) * 1000).toISOString().substring(11, 19),
                count
            }));
    }

    createProtocolChart(protocols) {
        const chart = this.initChart('protocolChart');
        if (!chart) return;
        if (!protocols || typeof protocols !== 'object') return;
        this.echartsInstances.protocol = chart;

        const t = this.getEChartsTheme();
        const data = Object.entries(protocols)
            .map(([name, value]) => ({ name, value }))
            .filter((d) => Number(d.value || 0) > 0)
            .sort((a, b) => b.value - a.value);

        if (!data.length) {
            this.setNoDataChart(chart, 'Aucune donnée protocolaire');
            return;
        }

        chart.setOption({
            backgroundColor: 'transparent',
            tooltip: {
                trigger: 'item',
                formatter: '{b}: {c} paquets ({d}%)',
                ...t.tooltip
            },
            legend: {
                orient: 'vertical',
                right: '5%',
                top: 'center',
                textStyle: { color: t.textColor, fontFamily: 'Space Grotesk, sans-serif', fontSize: 12 }
            },
            series: [{
                type: 'pie',
                radius: ['45%', '72%'],
                center: ['40%', '50%'],
                avoidLabelOverlap: true,
                itemStyle: {
                    borderRadius: 6,
                    borderColor: 'transparent',
                    borderWidth: 2
                },
                label: { show: false },
                emphasis: {
                    scale: true,
                    scaleSize: 8,
                    itemStyle: { shadowBlur: 20, shadowColor: 'rgba(6,182,212,0.4)' }
                },
                data: data.map((d, i) => ({
                    ...d,
                    itemStyle: { color: t.colors[i % t.colors.length] }
                }))
            }]
        });

        // Drill-down: clic filtre la vue paquets
        chart.on('click', (params) => {
            if (!params.name) return;
            this.filterPacketsByProtocol(params.name);
            this.showToast('info', 'Filtre appliqué', `Protocole: ${params.name}`);
        });
    }

    createFlagsChart(flags) {
        const chart = this.initChart('flagsChart');
        if (!chart) return;
        if (!flags || typeof flags !== 'object') return;
        this.echartsInstances.flags = chart;

        const t = this.getEChartsTheme();
        const entries = Object.entries(flags).sort((a, b) => b[1] - a[1]);
        if (!entries.length) {
            this.setNoDataChart(chart, 'Aucun flag TCP');
            return;
        }

        chart.setOption({
            backgroundColor: 'transparent',
            tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, ...t.tooltip },
            grid: { left: '3%', right: '4%', top: '8%', bottom: '3%', containLabel: true },
            xAxis: {
                type: 'category',
                data: entries.map(e => e[0]),
                axisLabel: { color: t.textColor, fontFamily: 'Space Grotesk, sans-serif' },
                axisLine: { lineStyle: { color: t.grid } }
            },
            yAxis: {
                type: 'value',
                axisLabel: { color: t.textColor },
                splitLine: { lineStyle: { color: t.grid } }
            },
            series: [{
                type: 'bar',
                data: entries.map((e, i) => ({
                    value: e[1],
                    itemStyle: {
                        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                            { offset: 0, color: t.colors[i % t.colors.length] },
                            { offset: 1, color: t.colors[i % t.colors.length] + '44' }
                        ]),
                        borderRadius: [4, 4, 0, 0]
                    }
                })),
                emphasis: { itemStyle: { shadowBlur: 10, shadowColor: 'rgba(6,182,212,0.3)' } }
            }]
        });
    }

    createTopIpsChart(ipStats) {
        const chart = this.initChart('topIpsChart');
        if (!chart) return;
        if (!ipStats || typeof ipStats !== 'object') return;
        this.echartsInstances.topIps = chart;

        const t = this.getEChartsTheme();
        const topIps = (ipStats.top_sources || []).slice(0, 10).reverse();
        if (!topIps.length) {
            this.setNoDataChart(chart, 'Aucune IP source');
            return;
        }

        chart.setOption({
            backgroundColor: 'transparent',
            tooltip: {
                trigger: 'axis',
                axisPointer: { type: 'shadow' },
                formatter: (params) => {
                    const p = params[0];
                    return `<div style="font-family:Space Grotesk,sans-serif">
                        <strong>${p.name}</strong><br/>
                        Paquets: <strong>${p.value.toLocaleString()}</strong>
                    </div>`;
                },
                ...t.tooltip
            },
            grid: { left: '3%', right: '8%', top: '4%', bottom: '3%', containLabel: true },
            xAxis: {
                type: 'value',
                axisLabel: { color: t.textColor },
                splitLine: { lineStyle: { color: t.grid } }
            },
            yAxis: {
                type: 'category',
                data: topIps.map(ip => ip.ip || ip[0]),
                axisLabel: { color: t.textColor, fontFamily: 'monospace', fontSize: 11 }
            },
            series: [{
                type: 'bar',
                data: topIps.map(ip => ip.count || ip[1]),
                itemStyle: {
                    color: new echarts.graphic.LinearGradient(1, 0, 0, 0, [
                        { offset: 0, color: '#06b6d4' },
                        { offset: 1, color: '#f97316' }
                    ]),
                    borderRadius: [0, 4, 4, 0]
                },
                emphasis: { itemStyle: { shadowBlur: 10 } },
                label: {
                    show: true,
                    position: 'right',
                    color: t.textColor,
                    fontSize: 11,
                    formatter: (p) => p.value.toLocaleString()
                }
            }]
        });

        chart.on('click', (params) => {
            if (!params.name) return;
            this.filterPacketsByIp(params.name);
            this.showToast('info', 'Filtre appliqué', `IP: ${params.name}`);
        });
    }

    createAnomaliesChart(byType) {
        const chart = this.initChart('anomaliesChart');
        if (!chart) return;
        if (!byType || typeof byType !== 'object') return;
        this.echartsInstances.anomalies = chart;

        const t = this.getEChartsTheme();
        const data = Object.entries(byType)
            .map(([name, value]) => ({ name, value }))
            .filter((d) => Number(d.value || 0) > 0);
        if (!data.length) {
            this.setNoDataChart(chart, 'Aucune anomalie');
            return;
        }

        chart.setOption({
            backgroundColor: 'transparent',
            tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)', ...t.tooltip },
            legend: {
                bottom: '0%',
                textStyle: { color: t.textColor }
            },
            series: [{
                type: 'pie',
                radius: ['35%', '65%'],
                roseType: 'radius',
                itemStyle: { borderRadius: 5, borderColor: 'transparent', borderWidth: 2 },
                label: { color: t.textColor, fontSize: 11 },
                emphasis: { itemStyle: { shadowBlur: 15, shadowColor: 'rgba(239,68,68,0.4)' } },
                data: data.map((d, i) => ({
                    ...d,
                    itemStyle: { color: ['#ef4444', '#f59e0b', '#f97316', '#06b6d4', '#10b981'][i % 5] }
                }))
            }]
        });
    }

    createTrafficTimelineChart(timeSeriesData) {
        const chart = this.initChart('trafficTimelineChart');
        if (!chart) return;
        this.echartsInstances.trafficTimeline = chart;

        const t = this.getEChartsTheme();
        if (!timeSeriesData || !timeSeriesData.length) {
            chart.setOption({
                backgroundColor: 'transparent', graphic: [{
                    type: 'text', left: 'center', top: 'center',
                    style: { text: 'Pas de données temporelles', fill: t.textColor }
                }]
            });
            return;
        }

        const times = timeSeriesData.map(d => d.timestamp || d.time || d[0]);
        const counts = timeSeriesData.map(d => d.count || d.packets || d[1]);

        chart.setOption({
            backgroundColor: 'transparent',
            tooltip: {
                trigger: 'axis',
                axisPointer: { type: 'cross', label: { backgroundColor: '#06b6d4' } },
                ...t.tooltip
            },
            toolbox: {
                right: '10%',
                feature: {
                    dataZoom: { yAxisIndex: 'none', title: { zoom: 'Zoom', back: 'Reset' } },
                    saveAsImage: { title: 'Export PNG', backgroundColor: t.isDark ? '#0f172a' : '#fff' }
                },
                iconStyle: { borderColor: t.textColor }
            },
            grid: { left: '3%', right: '4%', top: '8%', bottom: '20%', containLabel: true },
            dataZoom: [
                { type: 'inside', start: 0, end: 100 },
                {
                    type: 'slider', start: 0, end: 100, height: 24,
                    borderColor: t.grid, textStyle: { color: t.textColor }
                }
            ],
            xAxis: {
                type: 'category', data: times,
                axisLabel: { color: t.textColor, rotate: 30, fontSize: 10 },
                axisLine: { lineStyle: { color: t.grid } }
            },
            yAxis: {
                type: 'value',
                name: 'Paquets',
                nameTextStyle: { color: t.textColor },
                axisLabel: { color: t.textColor },
                splitLine: { lineStyle: { color: t.grid } }
            },
            series: [{
                type: 'line',
                data: counts,
                smooth: true,
                symbol: 'none',
                lineStyle: { color: '#06b6d4', width: 2 },
                areaStyle: {
                    color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                        { offset: 0, color: 'rgba(6,182,212,0.4)' },
                        { offset: 1, color: 'rgba(6,182,212,0.02)' }
                    ])
                }
            }]
        });
    }

    createTemporalHeatmap(packets) {
        const chart = this.initChart('heatmapChart');
        if (!chart) return;
        this.echartsInstances.heatmap = chart;

        const t = this.getEChartsTheme();

        // Build grid: hour (0-23) x 5-minute slot (0-11)
        const grid = {};
        (packets || []).forEach(pkt => {
            const ts = pkt.timestamp || pkt.time;
            if (!ts) return;
            const d = new Date(ts * 1000);
            const key = `${d.getHours()}-${Math.floor(d.getMinutes() / 5) * 5}`;
            grid[key] = (grid[key] || 0) + 1;
        });

        const data = Object.entries(grid).map(([key, count]) => {
            const [hour, minute] = key.split('-').map(Number);
            return [hour, minute / 5, count];
        });

        if (!data.length) {
            chart.setOption({
                backgroundColor: 'transparent', graphic: [{
                    type: 'text', left: 'center', top: 'center',
                    style: { text: 'Pas de données temporelles', fill: t.textColor }
                }]
            });
            return;
        }

        const maxVal = Math.max(...data.map(d => d[2]), 1);

        chart.setOption({
            backgroundColor: 'transparent',
            tooltip: {
                formatter: (p) => `${p.data[0]}h${p.data[1] * 5}min — ${p.data[2]} paquets`,
                ...t.tooltip
            },
            grid: { left: '5%', right: '5%', top: '5%', bottom: '15%', containLabel: true },
            xAxis: {
                type: 'category',
                data: Array.from({ length: 24 }, (_, i) => `${i}h`),
                axisLabel: { color: t.textColor, fontSize: 10 },
                splitArea: { show: true }
            },
            yAxis: {
                type: 'category',
                data: Array.from({ length: 12 }, (_, i) => `${i * 5}min`),
                axisLabel: { color: t.textColor, fontSize: 10 },
                splitArea: { show: true }
            },
            visualMap: {
                min: 0, max: maxVal,
                calculable: true,
                orient: 'horizontal',
                left: 'center',
                bottom: '0%',
                inRange: { color: ['#0f172a', '#06b6d4', '#f97316'] },
                textStyle: { color: t.textColor }
            },
            series: [{
                type: 'heatmap',
                data: data,
                label: { show: false },
                emphasis: { itemStyle: { shadowBlur: 10, shadowColor: 'rgba(6,182,212,0.5)' } }
            }]
        });
    }

    createProtocolTreemap(protocols, _ipStats) {
        const chart = this.initChart('treemapChart');
        if (!chart) return;
        if (!protocols || typeof protocols !== 'object') return;
        this.echartsInstances.treemap = chart;

        const t = this.getEChartsTheme();
        const data = Object.entries(protocols).map(([name, value], i) => ({
            name, value,
            itemStyle: { color: t.colors[i % t.colors.length] }
        }));

        if (!data.length) {
            chart.setOption({
                backgroundColor: 'transparent', graphic: [{
                    type: 'text', left: 'center', top: 'center',
                    style: { text: 'Aucune donnée protocole', fill: t.textColor }
                }]
            });
            return;
        }

        chart.setOption({
            backgroundColor: 'transparent',
            tooltip: {
                formatter: (p) => `<strong>${p.name}</strong><br/>Paquets: ${p.value.toLocaleString()}`,
                ...t.tooltip
            },
            series: [{
                type: 'treemap',
                data: data,
                width: '100%',
                height: '90%',
                roam: false,
                nodeClick: 'zoomToNode',
                label: {
                    show: true,
                    formatter: '{b}\n{c}',
                    color: '#fff',
                    fontFamily: 'Space Grotesk, sans-serif',
                    fontSize: 12
                },
                breadcrumb: {
                    show: true,
                    itemStyle: { color: t.isDark ? '#1e293b' : '#f1f5f9', textStyle: { color: t.textColor } }
                },
                emphasis: { itemStyle: { shadowBlur: 20 } }
            }]
        });

        chart.on('click', (params) => {
            if (!params.name) return;
            this.filterPacketsByProtocol(params.name);
        });
    }

    createSankeyChart(ipStats, protocols) {
        const chart = this.initChart('sankeyChart');
        if (!chart) return;
        this.echartsInstances.sankey = chart;

        const t = this.getEChartsTheme();

        const topSrc = (ipStats.top_sources || []).slice(0, 5);
        const topDst = (ipStats.top_destinations || []).slice(0, 5);
        const protoList = Object.keys(protocols).slice(0, 5);

        if (!topSrc.length || !protoList.length) {
            chart.setOption({
                backgroundColor: 'transparent', graphic: [{
                    type: 'text', left: 'center', top: 'center',
                    style: { text: 'Données insuffisantes pour Sankey', fill: t.textColor }
                }]
            });
            return;
        }

        const nodes = [
            ...topSrc.map(ip => ({ name: `src:${ip.ip || ip[0]}` })),
            ...protoList.map(p => ({ name: `proto:${p}` })),
            ...topDst.map(ip => ({ name: `dst:${ip.ip || ip[0]}` }))
        ];

        const links = [];
        topSrc.forEach(src => {
            protoList.forEach((proto, pi) => {
                const val = Math.floor((src.count || src[1]) / (pi + 1));
                if (val > 0) links.push({ source: `src:${src.ip || src[0]}`, target: `proto:${proto}`, value: val });
            });
        });
        protoList.forEach(proto => {
            topDst.forEach((dst, di) => {
                const val = Math.floor((protocols[proto] || 0) / (di + 2));
                if (val > 0) links.push({ source: `proto:${proto}`, target: `dst:${dst.ip || dst[0]}`, value: val });
            });
        });

        chart.setOption({
            backgroundColor: 'transparent',
            tooltip: { trigger: 'item', ...t.tooltip, formatter: '{b}: {c}' },
            series: [{
                type: 'sankey',
                layout: 'none',
                emphasis: { focus: 'adjacency' },
                data: nodes,
                links: links,
                lineStyle: { color: 'gradient', curveness: 0.5, opacity: 0.4 },
                label: {
                    color: t.textColor,
                    fontFamily: 'Space Grotesk, sans-serif',
                    fontSize: 11,
                    formatter: (p) => p.name.replace('src:', '').replace('dst:', '').replace('proto:', '')
                },
                itemStyle: { borderWidth: 0 },
                nodeWidth: 16,
                nodeGap: 12
            }]
        });
    }

    applyGlobalFilterToDns(dns) {
        const filter = this.globalDrilldownFilter || {};
        const query = String(filter.query || '').trim().toLowerCase();
        const proto = String(filter.protocol || '').trim().toUpperCase();
        if (proto && proto !== 'DNS') {
            return { ...(dns || {}), top_domains: [], queries: [], responses: [], anomalies: [] };
        }
        if (!query) return dns || {};

        const topDomains = (Array.isArray(dns?.top_domains) ? dns.top_domains : []).filter((d) => {
            const domain = String(d?.domain || (Array.isArray(d) ? d[0] : '')).toLowerCase();
            return domain.includes(query);
        });
        const queries = (Array.isArray(dns?.queries) ? dns.queries : []).filter((q) => {
            const domain = String(q?.domain || q?.query || '').toLowerCase();
            const src = String(q?.src_ip || '').toLowerCase();
            const dst = String(q?.dst_ip || '').toLowerCase();
            return domain.includes(query) || src.includes(query) || dst.includes(query);
        });
        const responses = (Array.isArray(dns?.responses) ? dns.responses : []).filter((r) => {
            const domain = String(r?.queried_domain || r?.domain || '').toLowerCase();
            return domain.includes(query);
        });
        const anomalies = (Array.isArray(dns?.anomalies) ? dns.anomalies : []).filter((a) => {
            const txt = `${a?.type || ''} ${a?.description || ''} ${a?.recommendation || ''}`.toLowerCase();
            return txt.includes(query);
        });
        return {
            ...(dns || {}),
            top_domains: topDomains,
            queries,
            responses,
            anomalies,
        };
    }

    applyGlobalFilterToHttp(http) {
        const filter = this.globalDrilldownFilter || {};
        const query = String(filter.query || '').trim().toLowerCase();
        const proto = String(filter.protocol || '').trim().toUpperCase();
        if (proto === 'DNS' || proto === 'UDP') {
            return {
                ...(http || {}),
                requests: [],
                hosts: [],
                top_urls: [],
                user_agents: [],
                anomalies: [],
                tls: { ...(http?.tls || {}), sni_hosts: [] },
            };
        }
        let requests = Array.isArray(http?.requests) ? http.requests : [];
        let hosts = Array.isArray(http?.hosts) ? http.hosts : [];
        let topUrls = Array.isArray(http?.top_urls) ? http.top_urls : [];
        let userAgents = Array.isArray(http?.user_agents) ? http.user_agents : [];
        let sniHosts = Array.isArray(http?.tls?.sni_hosts) ? http.tls.sni_hosts : [];
        let anomalies = Array.isArray(http?.anomalies) ? http.anomalies : [];

        if (proto === 'HTTPS') {
            requests = [];
            topUrls = [];
            userAgents = [];
        } else if (proto === 'HTTP') {
            sniHosts = [];
        }

        if (query) {
            requests = requests.filter((r) => {
                const txt = `${r?.host || ''} ${r?.path || r?.url || ''} ${r?.src_ip || ''} ${r?.dst_ip || ''} ${r?.user_agent || ''}`.toLowerCase();
                return txt.includes(query);
            });
            hosts = hosts.filter((h) => String(h?.name || h?.host || (Array.isArray(h) ? h[0] : '')).toLowerCase().includes(query));
            topUrls = topUrls.filter((u) => String(u?.name || u?.url || (Array.isArray(u) ? u[0] : '')).toLowerCase().includes(query));
            userAgents = userAgents.filter((ua) => String(ua?.name || ua?.user_agent || (Array.isArray(ua) ? ua[0] : '')).toLowerCase().includes(query));
            sniHosts = sniHosts.filter((s) => String(s?.name || s?.host || (Array.isArray(s) ? s[0] : '')).toLowerCase().includes(query));
            anomalies = anomalies.filter((a) => `${a?.type || ''} ${a?.description || ''}`.toLowerCase().includes(query));
        }

        return {
            ...(http || {}),
            requests,
            hosts,
            top_urls: topUrls,
            user_agents: userAgents,
            anomalies,
            tls: {
                ...(http?.tls || {}),
                sni_hosts: sniHosts,
            },
        };
    }

    getGlobalFilterSignature() {
        const filter = this.globalDrilldownFilter || {};
        return [
            String(filter.query || '').trim().toLowerCase(),
            String(filter.protocol || '').trim().toUpperCase(),
            Number(filter.riskMin || 0),
            this.currentTaskId || '',
        ].join('|');
    }

    buildDnsRenderSignature(dns) {
        const summary = dns?.summary || {};
        const topDomains = Array.isArray(dns?.top_domains) ? dns.top_domains : [];
        const anomalies = Array.isArray(dns?.anomalies) ? dns.anomalies : [];
        const queryTypes = dns?.query_types && typeof dns.query_types === 'object' ? dns.query_types : {};
        const responseCodes = dns?.response_codes && typeof dns.response_codes === 'object' ? dns.response_codes : {};
        const domainSample = topDomains.slice(0, 3).map((d) => `${d?.domain || d?.[0] || ''}:${d?.count || d?.[1] || 0}`).join(',');
        const anomalySample = anomalies.slice(0, 2).map((a) => `${a?.type || ''}:${a?.severity || ''}`).join(',');
        return [
            this.getGlobalFilterSignature(),
            Number(summary.total_queries || 0),
            topDomains.length,
            anomalies.length,
            Object.keys(queryTypes).sort().join(','),
            Object.keys(responseCodes).sort().join(','),
            domainSample,
            anomalySample,
        ].join('::');
    }

    buildHttpRenderSignature(http) {
        const summary = http?.summary || {};
        const requests = Array.isArray(http?.requests) ? http.requests : [];
        const hosts = Array.isArray(http?.hosts) ? http.hosts : [];
        const topUrls = Array.isArray(http?.top_urls) ? http.top_urls : [];
        const userAgents = Array.isArray(http?.user_agents) ? http.user_agents : [];
        const anomalies = Array.isArray(http?.anomalies) ? http.anomalies : [];
        const sniHosts = Array.isArray(http?.tls?.sni_hosts) ? http.tls.sni_hosts : [];
        const statusCodes = http?.status_codes && typeof http.status_codes === 'object' ? http.status_codes : {};
        const hostSample = hosts.slice(0, 2).map((h) => `${h?.name || h?.host || h?.[0] || ''}:${h?.count || h?.[1] || 0}`).join(',');
        const reqSample = requests.slice(0, 2).map((r) => `${r?.method || ''}:${r?.host || r?.dst_ip || ''}`).join(',');
        return [
            this.getGlobalFilterSignature(),
            Number(summary.total_requests || requests.length || 0),
            Number(summary.total_tls_sessions || 0),
            requests.length,
            hosts.length,
            topUrls.length,
            userAgents.length,
            anomalies.length,
            sniHosts.length,
            Object.keys(statusCodes).sort().join(','),
            hostSample,
            reqSample,
        ].join('::');
    }

    // ==================== DNS DISPLAY ====================

    displayDnsResults(dns) {
        dns = this.applyGlobalFilterToDns(dns || {});
        const signature = this.buildDnsRenderSignature(dns);
        const dnsSummary = dns.summary || {};
        const dnsCount = Number(dnsSummary.total_queries || (Array.isArray(dns.queries) ? dns.queries.length : 0));
        if (this.renderSignatures?.dns === signature) {
            this.setMenuHealthStatus('dns', dnsCount > 0 ? 'ok' : 'missing', dnsCount > 0 ? `${dnsCount.toLocaleString('fr-FR')} requêtes DNS` : 'Aucune requête DNS');
            return;
        }
        this.renderSignatures.dns = signature;

        // Charts
        this.createDnsDomainsChart(dns.top_domains || []);
        this.createDnsTypesChart(dns.query_types || {});
        this.createDnsResponseCodesChart(dns.response_codes || {});

        // Stats — backend uses _ms suffix
        const summary = dnsSummary;
        const avgTime = document.getElementById('dnsAvgTime');
        const minTime = document.getElementById('dnsMinTime');
        const maxTime = document.getElementById('dnsMaxTime');

        const avg = summary.avg_response_time_ms ?? summary.avg_response_time;
        const min = summary.min_response_time_ms ?? summary.min_response_time;
        const max = summary.max_response_time_ms ?? summary.max_response_time;

        if (avgTime) avgTime.textContent = avg ? `${Number(avg).toFixed(2)} ms` : '-';
        if (minTime) minTime.textContent = min ? `${Number(min).toFixed(2)} ms` : '-';
        if (maxTime) maxTime.textContent = max ? `${Number(max).toFixed(2)} ms` : '-';

        // Tables
        this.populateDnsDomainsTable(dns.top_domains || []);
        this.populateDnsAnomaliesTable(dns.anomalies || []);
        this.setMenuHealthStatus('dns', dnsCount > 0 ? 'ok' : 'missing', dnsCount > 0 ? `${dnsCount.toLocaleString('fr-FR')} requêtes DNS` : 'Aucune requête DNS');
    }

    createDnsDomainsChart(topDomains) {
        const chart = this.initChart('dnsDomainsChart');
        if (!chart) return;
        if (!Array.isArray(topDomains)) return;
        this.echartsInstances.dnsDomains = chart;

        const t = this.getEChartsTheme();
        const domains = topDomains.slice(0, 10).reverse();

        chart.setOption({
            backgroundColor: 'transparent',
            tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, ...t.tooltip },
            grid: { left: '3%', right: '8%', containLabel: true },
            xAxis: { type: 'value', axisLabel: { color: t.textColor }, splitLine: { lineStyle: { color: t.grid } } },
            yAxis: { type: 'category', data: domains.map(d => d.domain || d[0]), axisLabel: { color: t.textColor, fontSize: 11 } },
            series: [{
                type: 'bar',
                data: domains.map(d => d.count || d[1]),
                itemStyle: {
                    color: new echarts.graphic.LinearGradient(1, 0, 0, 0, [
                        { offset: 0, color: '#10b981' }, { offset: 1, color: '#06b6d4' }
                    ]),
                    borderRadius: [0, 4, 4, 0]
                }
            }]
        });
    }

    createDnsTypesChart(types) {
        const chart = this.initChart('dnsTypesChart');
        if (!chart) return;
        if (!types || typeof types !== 'object') return;
        this.echartsInstances.dnsTypes = chart;

        const t = this.getEChartsTheme();
        const data = Object.entries(types).map(([name, value]) => ({ name, value }));

        chart.setOption({
            backgroundColor: 'transparent',
            tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)', ...t.tooltip },
            legend: { orient: 'vertical', right: '5%', top: 'center', textStyle: { color: t.textColor, fontSize: 12 } },
            series: [{
                type: 'pie',
                radius: ['40%', '68%'],
                center: ['40%', '50%'],
                avoidLabelOverlap: true,
                itemStyle: { borderRadius: 4, borderColor: 'transparent', borderWidth: 2 },
                label: { show: false },
                emphasis: { scale: true, scaleSize: 6 },
                data: data.map((d, i) => ({ ...d, itemStyle: { color: t.colors[i % t.colors.length] } }))
            }]
        });
    }

    createDnsResponseCodesChart(codes) {
        const chart = this.initChart('dnsResponseCodesChart');
        if (!chart) return;
        if (!codes || typeof codes !== 'object') return;
        this.echartsInstances.dnsResponseCodes = chart;

        const t = this.getEChartsTheme();
        const rCodeColors = { 'NOERROR': '#10b981', 'NXDOMAIN': '#ef4444', 'SERVFAIL': '#f59e0b', 'REFUSED': '#f97316' };
        const data = Object.entries(codes).map(([name, value]) => ({
            name, value,
            itemStyle: { color: rCodeColors[name] || t.colors[Object.keys(codes).indexOf(name) % t.colors.length] }
        }));

        chart.setOption({
            backgroundColor: 'transparent',
            tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)', ...t.tooltip },
            legend: { orient: 'vertical', right: '5%', top: 'center', textStyle: { color: t.textColor, fontSize: 12 } },
            series: [{
                type: 'pie',
                radius: ['40%', '68%'],
                center: ['40%', '50%'],
                itemStyle: { borderRadius: 4, borderColor: 'transparent', borderWidth: 2 },
                label: { show: false },
                data
            }]
        });
    }

    populateDnsDomainsTable(domains) {
        const tbody = document.querySelector('#dnsDomainsTable tbody');
        if (!tbody) return;

        if (!domains || domains.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;color:var(--text-tertiary);padding:1rem;">Aucun domaine DNS trouvé</td></tr>`;
            return;
        }

        tbody.innerHTML = domains.slice(0, 20).map(d => {
            const domain = d.domain || (Array.isArray(d) ? d[0] : '?');
            const count = d.count || (Array.isArray(d) ? d[1] : 0);
            // types can be a dict {A: 3} or an array ['A','AAAA'] or undefined
            let typesStr = 'A';
            if (d.types) {
                if (Array.isArray(d.types)) {
                    typesStr = d.types.join(', ');
                } else if (typeof d.types === 'object') {
                    typesStr = Object.keys(d.types).join(', ');
                } else {
                    typesStr = String(d.types);
                }
            }
            return `
            <tr>
                <td><code>${this.escapeHtml(domain)}</code></td>
                <td>${count}</td>
                <td>${this.escapeHtml(typesStr)}</td>
                <td>
                    <button class="btn-ai-small" onclick="analyzer.analyzeWithAI('dns')">🤖</button>
                </td>
            </tr>`;
        }).join('');
    }

    populateDnsAnomaliesTable(anomalies) {
        const tbody = document.querySelector('#dnsAnomaliesTable tbody');
        if (!tbody) return;

        tbody.innerHTML = anomalies.slice(0, 10).map(a => `
            <tr>
                <td>${this.escapeHtml(a.type || '-')}</td>
                <td><span class="severity-badge ${this.sanitizeClassToken(a.severity || '')}">${this.escapeHtml(a.severity || '-')}</span></td>
                <td>${this.escapeHtml(a.description || '-')}</td>
                <td>${this.escapeHtml(a.recommendation || '-')}</td>
            </tr>
        `).join('');
    }

    // ==================== HTTP DISPLAY ====================

    displayHttpResults(http) {
        http = this.applyGlobalFilterToHttp(http || {});
        const signature = this.buildHttpRenderSignature(http);
        const httpSummary = http.summary || {};
        const reqCount = Number(httpSummary.total_requests || (Array.isArray(http.requests) ? http.requests.length : 0));
        const tlsCount = Number(httpSummary.total_tls_sessions || 0);
        if (this.renderSignatures?.http === signature) {
            this.setMenuHealthStatus('http', (reqCount > 0 || tlsCount > 0) ? 'ok' : 'missing', (reqCount > 0 || tlsCount > 0) ? `${reqCount.toLocaleString('fr-FR')} HTTP / ${tlsCount.toLocaleString('fr-FR')} TLS` : 'Aucune donnée HTTP/TLS');
            return;
        }
        this.renderSignatures.http = signature;

        const requests = Array.isArray(http.requests) ? http.requests : [];
        const responses = Array.isArray(http.responses) ? http.responses : [];

        const methods = { ...(http.methods || {}) };
        if (!Object.keys(methods).length && requests.length) {
            requests.forEach(req => {
                const method = String(req.method || 'UNKNOWN').toUpperCase();
                methods[method] = (methods[method] || 0) + 1;
            });
        }
        this.createHttpMethodsChart(methods);

        // status_codes can be a dict of {count, description} objects or plain ints
        const statusCodesRaw = http.status_codes || {};
        const statusCodesSimple = {};
        Object.entries(statusCodesRaw).forEach(([k, v]) => {
            statusCodesSimple[k] = typeof v === 'object' ? (v.count || 0) : v;
        });
        if (!Object.keys(statusCodesSimple).length && responses.length) {
            responses.forEach(resp => {
                const code = String(resp.status_code || '').trim();
                if (code) statusCodesSimple[code] = (statusCodesSimple[code] || 0) + 1;
            });
        }
        this.createHttpStatusChart(statusCodesSimple);

        // hosts is usually an array of {name, count} from _get_top_items
        let hostsArr = Array.isArray(http.hosts) && http.hosts.length ? http.hosts : (http.top_hosts || []);
        if ((!Array.isArray(hostsArr) || !hostsArr.length) && requests.length) {
            const hostCounts = {};
            requests.forEach(req => {
                const host = req.host || req.dst_ip || 'unknown';
                hostCounts[host] = (hostCounts[host] || 0) + 1;
            });
            hostsArr = Object.entries(hostCounts)
                .map(([name, count]) => ({ name, count }))
                .sort((a, b) => b.count - a.count);
        }
        this.createHttpHostsChart(hostsArr);
        this.createTlsVersionsChart(http.tls?.versions || {});

        let userAgents = Array.isArray(http.user_agents) ? http.user_agents : [];
        if (!userAgents.length && requests.length) {
            const uaCounts = {};
            requests.forEach(req => {
                const ua = req.user_agent || '';
                if (!ua) return;
                uaCounts[ua] = (uaCounts[ua] || 0) + 1;
            });
            userAgents = Object.entries(uaCounts)
                .map(([name, count]) => ({ name, count }))
                .sort((a, b) => b.count - a.count);
        }

        let topUrls = Array.isArray(http.top_urls) ? http.top_urls : [];
        if (!topUrls.length && requests.length) {
            const urlCounts = {};
            requests.forEach(req => {
                const key = req.path || req.url || '/';
                urlCounts[key] = (urlCounts[key] || 0) + 1;
            });
            topUrls = Object.entries(urlCounts)
                .map(([name, count]) => ({ name, count }))
                .sort((a, b) => b.count - a.count);
        }

        this.renderHttpDataHint({
            requestsCount: requests.length,
            tlsSessions: http?.summary?.total_tls_sessions || 0,
            hostsCount: Array.isArray(hostsArr) ? hostsArr.length : 0,
            urlsCount: topUrls.length,
            userAgentsCount: userAgents.length
        });

        this.populateUserAgentsTable(userAgents);
        this.populateUrlsTable(topUrls);
        this.populateSniHostsTable(http?.tls?.sni_hosts || []);
        this.populateHttpRequestsTable(requests);
        this.populateHttpAnomaliesTable(http.anomalies || []);
        this.setMenuHealthStatus('http', (reqCount > 0 || tlsCount > 0) ? 'ok' : 'missing', (reqCount > 0 || tlsCount > 0) ? `${reqCount.toLocaleString('fr-FR')} HTTP / ${tlsCount.toLocaleString('fr-FR')} TLS` : 'Aucune donnée HTTP/TLS');
    }

    renderHttpDataHint({ requestsCount = 0, tlsSessions = 0, hostsCount = 0, urlsCount = 0, userAgentsCount = 0 }) {
        const hint = document.getElementById('httpDataHint');
        if (!hint) return;

        if (requestsCount === 0 && tlsSessions > 0 && hostsCount > 0) {
            hint.textContent = 'Trafic majoritairement HTTPS détecté: les Hosts TLS (SNI) sont visibles, mais URL/User-Agent ne sont pas lisibles sans déchiffrement TLS.';
            return;
        }

        if (requestsCount === 0) {
            hint.textContent = 'Aucune requête HTTP décodée dans cette capture.';
            return;
        }

        const extra = [];
        if (!urlsCount) extra.push('URLs non extraites');
        if (!userAgentsCount) extra.push('User-Agents non extraits');
        hint.textContent = extra.length
            ? `${requestsCount} requêtes HTTP décodées (${extra.join(', ')}).`
            : `${requestsCount} requêtes HTTP décodées.`;
    }

    setNoDataChart(chart, message) {
        const t = this.getEChartsTheme();
        chart.clear();
        chart.setOption({
            backgroundColor: 'transparent',
            graphic: [{
                type: 'text',
                left: 'center',
                top: 'middle',
                style: {
                    text: message,
                    fill: t.textColor,
                    font: '13px Space Grotesk, sans-serif'
                }
            }]
        });
    }

    createHttpMethodsChart(methods) {
        const chart = this.initChart('httpMethodsChart');
        if (!chart) return;
        if (!methods || typeof methods !== 'object') return;
        this.echartsInstances.httpMethods = chart;

        const t = this.getEChartsTheme();
        const methodColors = { 'GET': '#10b981', 'POST': '#06b6d4', 'PUT': '#f59e0b', 'DELETE': '#ef4444', 'PATCH': '#f97316', 'OPTIONS': '#64748b' };
        const data = Object.entries(methods).map(([name, value]) => ({
            name, value,
            itemStyle: { color: methodColors[name] || t.colors[Object.keys(methods).indexOf(name) % t.colors.length] }
        }));
        if (!data.length) {
            this.setNoDataChart(chart, 'Aucune méthode HTTP');
            return;
        }

        chart.setOption({
            backgroundColor: 'transparent',
            tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)', ...t.tooltip },
            legend: { orient: 'vertical', right: '5%', top: 'center', textStyle: { color: t.textColor, fontSize: 12 } },
            series: [{
                type: 'pie',
                radius: ['40%', '68%'],
                center: ['40%', '50%'],
                itemStyle: { borderRadius: 4, borderColor: 'transparent', borderWidth: 2 },
                label: { show: false },
                emphasis: { scale: true, scaleSize: 6 },
                data
            }]
        });
    }

    createHttpStatusChart(codes) {
        const chart = this.initChart('httpStatusChart');
        if (!chart) return;
        if (!codes || typeof codes !== 'object') return;
        this.echartsInstances.httpStatus = chart;

        const t = this.getEChartsTheme();
        const statusColor = (code) => {
            const n = parseInt(code);
            if (n < 300) return '#10b981';
            if (n < 400) return '#06b6d4';
            if (n < 500) return '#f59e0b';
            return '#ef4444';
        };
        const entries = Object.entries(codes).sort((a, b) => parseInt(a[0]) - parseInt(b[0]));
        if (!entries.length) {
            this.setNoDataChart(chart, 'Aucun status code HTTP');
            return;
        }

        chart.setOption({
            backgroundColor: 'transparent',
            tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, ...t.tooltip },
            grid: { left: '3%', right: '4%', top: '8%', bottom: '3%', containLabel: true },
            xAxis: {
                type: 'category',
                data: entries.map(e => e[0]),
                axisLabel: { color: t.textColor },
                axisLine: { lineStyle: { color: t.grid } }
            },
            yAxis: { type: 'value', axisLabel: { color: t.textColor }, splitLine: { lineStyle: { color: t.grid } } },
            series: [{
                type: 'bar',
                data: entries.map(e => ({
                    value: e[1],
                    itemStyle: { color: statusColor(e[0]), borderRadius: [4, 4, 0, 0] }
                })),
                emphasis: { itemStyle: { shadowBlur: 10, shadowColor: 'rgba(0,0,0,0.3)' } }
            }]
        });
    }

    createHttpHostsChart(hosts) {
        const chart = this.initChart('httpHostsChart');
        if (!chart) return;
        if (!Array.isArray(hosts)) return;
        this.echartsInstances.httpHosts = chart;

        const t = this.getEChartsTheme();
        const topHosts = hosts.slice(0, 10).reverse();
        if (!topHosts.length) {
            this.setNoDataChart(chart, 'Aucun host HTTP/TLS');
            return;
        }

        chart.setOption({
            backgroundColor: 'transparent',
            tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, ...t.tooltip },
            grid: { left: '3%', right: '8%', containLabel: true },
            xAxis: { type: 'value', axisLabel: { color: t.textColor }, splitLine: { lineStyle: { color: t.grid } } },
            yAxis: {
                type: 'category',
                data: topHosts.map(h => h.host || h.name || (Array.isArray(h) ? h[0] : '?')),
                axisLabel: { color: t.textColor, fontSize: 10 }
            },
            series: [{
                type: 'bar',
                data: topHosts.map(h => h.count || (Array.isArray(h) ? h[1] : 0)),
                itemStyle: {
                    color: new echarts.graphic.LinearGradient(1, 0, 0, 0, [
                        { offset: 0, color: '#f97316' }, { offset: 1, color: '#06b6d4' }
                    ]),
                    borderRadius: [0, 4, 4, 0]
                }
            }]
        });
    }

    createTlsVersionsChart(versions) {
        const chart = this.initChart('tlsVersionsChart');
        if (!chart) return;
        this.echartsInstances.tlsVersions = chart;

        const t = this.getEChartsTheme();
        const tlsColors = { 'TLSv1.3': '#10b981', 'TLSv1.2': '#06b6d4', 'TLSv1.1': '#f59e0b', 'TLSv1.0': '#ef4444', 'SSLv3': '#64748b' };
        const hasData = versions && Object.keys(versions).length > 0;
        const data = hasData
            ? Object.entries(versions).map(([name, value]) => ({
                name, value,
                itemStyle: { color: tlsColors[name] || t.colors[Object.keys(versions).indexOf(name) % t.colors.length] }
            }))
            : [{ name: 'Aucune donnée', value: 1, itemStyle: { color: t.grid } }];

        chart.setOption({
            backgroundColor: 'transparent',
            tooltip: { trigger: 'item', formatter: hasData ? '{b}: {c} ({d}%)' : '{b}', ...t.tooltip },
            legend: { orient: 'vertical', right: '5%', top: 'center', textStyle: { color: t.textColor, fontSize: 12 } },
            series: [{
                type: 'pie',
                radius: ['40%', '68%'],
                center: ['40%', '50%'],
                itemStyle: { borderRadius: 4, borderColor: 'transparent', borderWidth: 2 },
                label: { show: false },
                data
            }]
        });
    }

    populateUserAgentsTable(userAgents) {
        const tbody = document.querySelector('#userAgentsTable tbody');
        if (!tbody) return;

        if (!userAgents || userAgents.length === 0) {
            tbody.innerHTML = `<tr><td colspan="3" style="text-align:center;color:var(--text-tertiary);padding:1rem;">Aucun user-agent détecté (trafic probablement chiffré)</td></tr>`;
            return;
        }

        tbody.innerHTML = userAgents.slice(0, 15).map(ua => {
            // backend returns {name, count} from _get_top_items; fallback to ua.user_agent or array
            const label = ua.user_agent || ua.name || (Array.isArray(ua) ? ua[0] : '-');
            const count = ua.count || (Array.isArray(ua) ? ua[1] : 0);
            const safeLabel = this.escapeHtml(label);
            return `
            <tr>
                <td title="${safeLabel}">${this.escapeHtml(this.truncate(label, 60))}</td>
                <td>${count}</td>
                <td><button class="btn-ai-small" onclick="analyzer.analyzeWithAI('user_agent')">🤖</button></td>
            </tr>`;
        }).join('');
    }

    populateUrlsTable(urls) {
        const tbody = document.querySelector('#urlsTable tbody');
        if (!tbody) return;

        if (!urls || urls.length === 0) {
            tbody.innerHTML = `<tr><td colspan="2" style="text-align:center;color:var(--text-tertiary);padding:1rem;">Aucune URL détectée (HTTPS chiffré ou capture partielle)</td></tr>`;
            return;
        }

        tbody.innerHTML = urls.slice(0, 15).map(u => {
            // backend returns {name, count} for top_urls; name is the path
            const label = u.url || u.name || (Array.isArray(u) ? u[0] : '-');
            const count = u.count || (Array.isArray(u) ? u[1] : 0);
            const safeLabel = this.escapeHtml(label);
            return `
            <tr>
                <td title="${safeLabel}"><code>${this.escapeHtml(this.truncate(label, 50))}</code></td>
                <td>${count}</td>
            </tr>`;
        }).join('');
    }

    populateSniHostsTable(sniHosts) {
        const tbody = document.querySelector('#sniHostsTable tbody');
        if (!tbody) return;

        if (!Array.isArray(sniHosts) || sniHosts.length === 0) {
            tbody.innerHTML = `<tr><td colspan="2" style="text-align:center;color:var(--text-tertiary);padding:1rem;">Aucun SNI HTTPS détecté</td></tr>`;
            return;
        }

        tbody.innerHTML = sniHosts.slice(0, 20).map(item => {
            const label = item.name || item.host || (Array.isArray(item) ? item[0] : '-');
            const count = item.count || (Array.isArray(item) ? item[1] : 0);
            return `
            <tr>
                <td><code>${this.escapeHtml(label)}</code></td>
                <td>${this.formatNumber(Number(count) || 0)}</td>
            </tr>`;
        }).join('');
    }

    populateHttpRequestsTable(requests) {
        const tbody = document.querySelector('#httpRequestsTable tbody');
        if (!tbody) return;

        if (!Array.isArray(requests) || requests.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--text-tertiary);padding:1rem;">Aucune requête HTTP décodée</td></tr>`;
            return;
        }

        tbody.innerHTML = requests.slice(0, 100).map(req => {
            const tsRaw = req.timestamp;
            const ts = tsRaw ? new Date(tsRaw * 1000).toLocaleTimeString('fr-FR') : '-';
            const method = String(req.method || 'GET').toUpperCase();
            const methodClass = method.replace(/[^A-Z0-9_-]/g, '');
            const host = req.host || req.dst_ip || '-';
            const path = req.path || req.url || '-';
            const source = `${req.src_ip || '-'}:${req.src_port || '-'}`;
            const ua = req.user_agent || '-';

            return `
            <tr>
                <td>${this.escapeHtml(ts)}</td>
                <td><span class="method-badge ${methodClass}">${this.escapeHtml(method)}</span></td>
                <td><code>${this.escapeHtml(host)}</code></td>
                <td><code title="${this.escapeHtml(path)}">${this.escapeHtml(this.truncate(path, 90))}</code></td>
                <td><code>${this.escapeHtml(source)}</code></td>
                <td title="${this.escapeHtml(ua)}">${this.escapeHtml(this.truncate(ua, 80))}</td>
            </tr>`;
        }).join('');
    }

    populateHttpAnomaliesTable(anomalies) {
        const tbody = document.querySelector('#httpAnomaliesTable tbody');
        if (!tbody) return;

        if (!anomalies || anomalies.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;color:var(--text-tertiary);padding:1rem;">Aucune anomalie HTTP détectée</td></tr>`;
            return;
        }

        tbody.innerHTML = anomalies.slice(0, 10).map(a => `
            <tr>
                <td>${this.escapeHtml(a.type || '-')}</td>
                <td><span class="severity-badge ${this.sanitizeClassToken(a.severity || '')}">${this.escapeHtml(a.severity || '-')}</span></td>
                <td>${this.escapeHtml(a.description || '-')}</td>
                <td>${this.escapeHtml(a.recommendation || '-')}</td>
            </tr>
        `).join('');
    }

    // ==================== TABLES ====================

    populateSessionsTable(sessions) {
        const tbody = document.querySelector('#sessionsTable tbody');
        if (!tbody) return;

        tbody.innerHTML = sessions.slice(0, 20).map((session, idx) => {
            const retrans = Number(session?.retransmissions || 0);
            const rst = Number(session?.rst_count || 0);
            const state = String(session?.state || '').toUpperCase();
            const isHalfOpen = ['SYN_SENT', 'SYN_RECEIVED', 'INIT'].includes(state);
            const rowClass = (rst > 0 || retrans >= 12 || isHalfOpen)
                ? 'problematic-row critical'
                : (retrans >= 3 ? 'problematic-row warning' : '');

            return `
            <tr class="${rowClass}">
                <td><code>${this.escapeHtml(session.src || '-')}</code></td>
                <td><code>${this.escapeHtml(session.dst || '-')}</code></td>
                <td><span class="state-badge ${this.sanitizeClassToken(session.state || '')}">${this.escapeHtml(session.state || '-')}</span></td>
                <td>${session.packets || 0}</td>
                <td>${session.retransmissions || 0}</td>
                <td>${session.rst_count || 0}</td>
                <td>
                    <button class="action-btn view" onclick='analyzer.showIpSessionModal(${JSON.stringify((session.src || "").split(":")[0])}, ${idx})'>👁️</button>
                </td>
            </tr>
        `;
        }).join('');
    }

    populateAnomaliesTable(anomalies) {
        const tbody = document.querySelector('#anomaliesTable tbody');
        if (!tbody) return;

        tbody.innerHTML = anomalies.slice(0, 15).map(a => {
            const sev = String(a?.severity || '').toUpperCase();
            const rowClass = (sev === 'CRITICAL' || sev === 'HIGH')
                ? 'problematic-row critical'
                : (sev === 'MEDIUM' ? 'problematic-row warning' : '');
            return `
            <tr class="${rowClass}">
                <td>${this.escapeHtml(a.type || '-')}</td>
                <td><span class="severity-badge ${this.sanitizeClassToken(a.severity || '')}">${this.escapeHtml(a.severity || '-')}</span></td>
                <td>${this.escapeHtml(a.score || '-')}</td>
                <td>${this.escapeHtml(this.truncate(a.description || '-', 50))}</td>
                <td><code>${this.escapeHtml(a.src_ip || '-')}</code></td>
                <td>
                    <button class="btn-ai-small" onclick="analyzer.analyzeWithAI('anomaly')">🤖</button>
                </td>
            </tr>
        `;
        }).join('');
    }

    populateMacVendorsTable(macStats) {
        const tbody = document.querySelector('#macVendorsTable tbody');
        if (!tbody) return;

        const rows = Array.isArray(macStats?.top_macs) ? macStats.top_macs : [];
        if (!rows.length) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text-tertiary);padding:1rem;">Aucune donnée MAC exploitable</td></tr>`;
            return;
        }

        tbody.innerHTML = rows.slice(0, 20).map(item => {
            const mac = item.mac || '-';
            const vendor = item.vendor || 'Inconnu';
            const count = Number(item.count) || 0;
            const role = item.role || '-';
            const macType = item.mac_type || '-';
            return `
            <tr>
                <td><code>${this.escapeHtml(mac)}</code></td>
                <td title="${this.escapeHtml(vendor)}">${this.escapeHtml(this.truncate(vendor, 34))}</td>
                <td>${this.formatNumber(count)}</td>
                <td>${this.escapeHtml(role)}</td>
                <td>${this.escapeHtml(macType)}</td>
            </tr>`;
        }).join('');
    }

    // ==================== HISTORY ====================

    async loadHistory() {
        try {
            const response = await fetch('/api/history');
            const data = await response.json();

            this.displayHistory(data.history || []);
        } catch (error) {
            console.error('Load history error:', error);
        }
    }

    displayHistory(history) {
        const tbody = document.querySelector('#historyTable tbody');
        const emptyState = document.getElementById('historyEmpty');

        if (!history.length) {
            if (tbody) tbody.innerHTML = '';
            if (emptyState) emptyState.style.display = 'block';
            return;
        }

        if (emptyState) emptyState.style.display = 'none';

        if (tbody) {
            tbody.innerHTML = history.map(item => `
                <tr>
                    <td>${this.escapeHtml(item.filename || '-')}</td>
                    <td>${item.timestamp ? new Date(item.timestamp).toLocaleString('fr-FR') : '-'}</td>
                    <td>${this.formatNumber(item.total_packets || 0)}</td>
                    <td>${item.anomalies_count || 0}</td>
                    <td><span class="risk-badge ${this.sanitizeClassToken(item.risk_level || 'NONE')}">${this.escapeHtml(item.risk_level || 'NONE')}</span></td>
                    <td>
                        <button class="action-btn view" onclick='analyzer.loadHistoryItem(${JSON.stringify(item.task_id || "")})'>👁️</button>
                        <button class="action-btn delete" onclick='analyzer.deleteHistoryItem(${JSON.stringify(item.task_id || "")})'>🗑️</button>
                    </td>
                </tr>
            `).join('');
        }
    }

    async loadHistoryItem(taskId) {
        this.currentTaskId = taskId;
        this.renderSignatures = { dns: '', http: '' };
        this.streamsLoadedKey = '';
        this.packetsLoadedTaskId = '';
        this.streamsData = [];
        this.allPackets = [];
        this.filteredPackets = [];
        this.packetIndex = { byProto: {}, byIp: {} };
        this.showToast('info', 'Chargement', 'Récupération de l\'analyse...');

        try {
            const response = await fetch(`/api/analysis/${taskId}`);
            const results = await response.json();

            this.currentResults = results;

            document.getElementById('uploadSection').style.display = 'none';
            document.getElementById('resultsSection').style.display = 'block';

            this.displayResults(results);
            this.triggerTabDataLoad(this.currentTabId);
            document.getElementById('resultsSection').scrollIntoView({block:'start',behavior:'auto'});

            // Double frame to let layout settle before chart resize
            this.requestChartsResize(2);

        } catch (error) {
            console.error('Load history item error:', error);
            this.showToast('error', 'Erreur', 'Impossible de charger l\'analyse');
        }
    }

    async deleteHistoryItem(taskId) {
        if (!confirm('Supprimer cette analyse ?')) return;

        try {
            await fetch(`/api/delete/${taskId}`, { method: 'DELETE' });
            this.showToast('success', 'Supprimé', 'Analyse supprimée');
            this.loadHistory();
        } catch (error) {
            console.error('Delete error:', error);
            this.showToast('error', 'Erreur', 'Impossible de supprimer');
        }
    }

    // ==================== EXPORT ====================

    async exportReport(format) {
        if (!this.currentTaskId) {
            this.showToast('warning', 'Pas d\'analyse', 'Aucune analyse à exporter');
            return;
        }

        this.showToast('info', 'Export', `Génération du rapport ${format.toUpperCase()}...`);

        try {
            const response = await fetch(`/api/export/${this.currentTaskId}/${format}`);
            const blob = await response.blob();

            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `pcap_analysis_${this.currentTaskId}.${format}`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);

            this.showToast('success', 'Export réussi', `Rapport ${format.toUpperCase()} téléchargé`);
        } catch (error) {
            console.error('Export error:', error);
            this.showToast('error', 'Erreur Export', error.message);
        }
    }

    // ==================== MODAL ====================

    openModal(title, content) {
        const modal = document.getElementById('detailModal');
        const modalTitle = document.getElementById('modalTitle');
        const modalBody = document.getElementById('modalBody');

        if (modalTitle) modalTitle.textContent = title;
        if (modalBody) modalBody.innerHTML = content;
        if (modal) modal.classList.add('open');
        if (modalBody) {
            requestAnimationFrame(() => {
                this.enrichModalMacVendors(modalBody);
            });
        }
    }

    closeModal() {
        const modal = document.getElementById('detailModal');
        if (modal) modal.classList.remove('open');
        if (typeof echarts !== 'undefined') {
            ['ipModalProtoChart', 'ipModalDstChart'].forEach(id => {
                const dom = document.getElementById(id);
                if (dom) {
                    const inst = echarts.getInstanceByDom(dom);
                    if (inst) inst.dispose();
                }
            });
        }
    }

    normalizeMacAddressForUi(mac) {
        const raw = String(mac || '').toUpperCase().replace(/[^0-9A-F]/g, '');
        if (raw.length !== 12) return '';
        return raw.match(/.{1,2}/g).join(':');
    }

    async resolveMacVendorForUi(mac) {
        const normalized = this.normalizeMacAddressForUi(mac);
        if (!normalized) return { mac: mac, vendor: 'Inconnu' };

        if (this.macVendorCache[normalized]) return this.macVendorCache[normalized];
        if (this.macVendorInflight[normalized]) return this.macVendorInflight[normalized];

        const promise = fetch(`/api/maclookup/resolve?mac=${encodeURIComponent(normalized)}`)
            .then(r => {
                if (!r.ok) throw new Error(`HTTP ${r.status}`);
                return r.json();
            })
            .then(data => ({
                mac: data.mac || normalized,
                vendor: data.vendor || 'Inconnu',
                mac_type: data.mac_type || 'unknown'
            }))
            .catch(() => ({ mac: normalized, vendor: 'Inconnu', mac_type: 'unknown' }))
            .finally(() => {
                delete this.macVendorInflight[normalized];
            });

        this.macVendorInflight[normalized] = promise;
        const resolved = await promise;
        this.macVendorCache[normalized] = resolved;
        return resolved;
    }

    async enrichModalMacVendors(container) {
        if (!container) return;
        const macRegex = /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g;
        const textNodes = [];
        const macs = new Set();

        const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT);
        let node = walker.nextNode();
        while (node) {
            if (!node.parentElement || node.parentElement.closest('[data-mac-enriched="1"]')) {
                node = walker.nextNode();
                continue;
            }
            const text = node.nodeValue || '';
            const matches = text.match(macRegex);
            if (matches && matches.length > 0) {
                textNodes.push(node);
                matches.forEach(m => {
                    const normalized = this.normalizeMacAddressForUi(m);
                    if (normalized) macs.add(normalized);
                });
            }
            node = walker.nextNode();
        }

        if (!macs.size) return;
        const vendorMap = {};
        await Promise.all(Array.from(macs).map(async mac => {
            const info = await this.resolveMacVendorForUi(mac);
            vendorMap[mac] = info.vendor || 'Inconnu';
        }));

        textNodes.forEach(textNode => {
            const parent = textNode.parentElement;
            if (!parent) return;
            const original = textNode.nodeValue || '';
            const updated = original.replace(macRegex, match => {
                const normalized = this.normalizeMacAddressForUi(match);
                const vendor = vendorMap[normalized] || 'Inconnu';
                return `${match} (${vendor})`;
            });
            textNode.nodeValue = updated;
            parent.setAttribute('data-mac-enriched', '1');
        });
    }

    showPacketDetails(packetNum) {
        const OSI_LAYERS = [
            { key: 'l1_physical', num: 1, label: 'Physical', color: '#64748b', icon: '📡' },
            { key: 'l2_datalink', num: 2, label: 'Data Link', color: '#3b82f6', icon: '🔗' },
            { key: 'l3_network', num: 3, label: 'Network', color: '#10b981', icon: '🌐' },
            { key: 'l4_transport', num: 4, label: 'Transport', color: '#f59e0b', icon: '🚀' },
            { key: 'l5_session', num: 5, label: 'Session', color: '#eab308', icon: '🔄' },
            { key: 'l6_presentation', num: 6, label: 'Presentation', color: '#f97316', icon: '🎨' },
            { key: 'l7_application', num: 7, label: 'Application', color: '#06b6d4', icon: '📦' },
        ];

        this.openModal(`Paquet #${packetNum} — Inspection OSI`, '<div class="loading-spinner"><div class="spinner"></div></div>');

        fetch(`/api/analysis/${this.currentTaskId}/packet/${packetNum}`)
            .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
            .then(data => {
                const basic = data.basic_info || {};
                const proto = basic.protocol || data.l4_transport?.protocol || '?';
                const src = basic.src_ip ? `${basic.src_ip}${basic.src_port ? ':' + basic.src_port : ''}` : '?';
                const dst = basic.dst_ip ? `${basic.dst_ip}${basic.dst_port ? ':' + basic.dst_port : ''}` : '?';
                const ts = basic.timestamp ? new Date(basic.timestamp * 1000).toLocaleTimeString() : '';

                let html = `
                <div class="osi-modal-header">
                    <span class="protocol-badge ${this.sanitizeClassToken(proto)}">${this.escapeHtml(proto)}</span>
                    <div class="pkt-badges">
                        <code style="font-size:0.85rem">${this.escapeHtml(src)}</code>
                        <span style="color:var(--text-muted)">→</span>
                        <code style="font-size:0.85rem">${this.escapeHtml(dst)}</code>
                        ${ts ? `<span style="color:var(--text-muted);font-size:0.8rem">${this.escapeHtml(ts)}</span>` : ''}
                        <span style="color:var(--text-muted);font-size:0.8rem">${basic.length || 0} B</span>
                    </div>
                </div>`;

                OSI_LAYERS.forEach(layer => {
                    const layerData = data[layer.key];
                    const hasData = layerData && Object.values(layerData).some(v =>
                        v !== null && v !== undefined && v !== '' &&
                        !(Array.isArray(v) && v.length === 0) &&
                        !(typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === 0)
                    );

                    const fields = layerData ? Object.entries(layerData)
                        .filter(([, v]) => v !== null && v !== undefined && v !== '' &&
                            !(Array.isArray(v) && v.length === 0) &&
                            !(typeof v === 'object' && !Array.isArray(v) && v !== null && Object.keys(v).length === 0))
                        .map(([k, v]) => {
                            const label = k.replace(/_/g, ' ');
                            const val = Array.isArray(v) ? v.join(', ') :
                                (typeof v === 'object' ? JSON.stringify(v) : v);
                            return `<div class="osi-field">
                                <span class="osi-field-label">${label}</span>
                                <span class="osi-field-value">${this.escapeHtml(String(val))}</span>
                            </div>`;
                        }).join('') : '';

                    let summary = '';
                    if (layer.key === 'l2_datalink' && layerData?.src_mac) {
                        const srcVendor = layerData.src_vendor || 'Inconnu';
                        const dstVendor = layerData.dst_vendor || 'Inconnu';
                        summary = `${layerData.src_mac} (${srcVendor}) → ${layerData.dst_mac} (${dstVendor})`;
                    }
                    if (layer.key === 'l3_network' && layerData?.src_ip)
                        summary = `TTL ${layerData.ttl} · ${layerData.src_ip} → ${layerData.dst_ip}`;
                    if (layer.key === 'l4_transport' && layerData?.protocol)
                        summary = `${layerData.protocol} ${layerData.src_port}→${layerData.dst_port} [${(layerData.flags || []).join(',')}]`
                            + `${layerData.window !== null && layerData.window !== undefined ? ` · win=${layerData.window}` : ''}`
                            + `${layerData.window_scale !== null && layerData.window_scale !== undefined ? ` · wscale=${layerData.window_scale}` : ''}`;
                    if (layer.key === 'l7_application' && layerData?.protocol)
                        summary = layerData.protocol;

                    const openClass = hasData ? 'open' : 'empty';

                    html += `
                    <div class="osi-layer ${openClass}" data-layer="${layer.key}">
                        <div class="osi-layer-header" onclick="this.closest('.osi-layer').classList.toggle('open')">
                            <span class="osi-layer-badge" style="background:${layer.color}">${layer.icon} L${layer.num}</span>
                            <span class="osi-layer-title">${layer.label}</span>
                            <span class="osi-layer-summary">${summary}</span>
                            <span class="osi-chevron">▶</span>
                        </div>
                        <div class="osi-layer-body">
                            ${hasData
                            ? `<div class="osi-fields">${fields}</div>`
                            : '<p style="color:var(--text-muted);font-size:0.82rem;margin:0">Aucune donnée disponible pour cette couche.</p>'}
                        </div>
                    </div>`;
                });

                if (data.raw_hex) {
                    const groups = data.raw_hex.match(/.{1,23}/g) || [];
                    const hexHtml = groups.map(g => `<span class="hex-group">${g}</span>`).join('');
                    html += `
                    <div style="padding: 0 1.25rem 1.25rem">
                        <button class="hex-toggle" onclick="
                            const d = this.nextElementSibling;
                            d.style.display = d.style.display === 'none' ? 'block' : 'none';
                            this.textContent = d.style.display === 'none' ? '▼ Voir raw hex dump' : '▲ Masquer hex dump';
                        ">▼ Voir raw hex dump</button>
                        <div class="hex-dump" style="display:none">${hexHtml}</div>
                    </div>`;
                }

                const modalBody = document.getElementById('modalBody');
                if (modalBody) {
                    modalBody.innerHTML = html;
                    this.enrichModalMacVendors(modalBody);
                }
            })
            .catch(() => {
                const modalBody = document.getElementById('modalBody');
                if (modalBody) {
                    modalBody.innerHTML = '<p style="color:var(--danger);padding:1rem">Erreur de chargement du paquet.</p>';
                    this.enrichModalMacVendors(modalBody);
                }
            });
    }

    showIpSessionModal(pivotIp, _sessionIdx) {
        if (!pivotIp || !this.currentResults) return;

        const allSessions = this.currentResults.tcp_analysis?.sessions || [];
        const packetsIndex = this.currentResults.packets_index || [];

        // Filter sessions involving this IP
        const related = allSessions.filter(s => {
            const srcIp = (s.src || '').split(':')[0];
            const dstIp = (s.dst || '').split(':')[0];
            return srcIp === pivotIp || dstIp === pivotIp;
        });

        // Count packets for this IP
        const ipPackets = packetsIndex.filter(p => p.src_ip === pivotIp || p.dst_ip === pivotIp);

        // Protocol breakdown from related sessions (infer from ports)
        const protoCounts = {};
        related.forEach(s => {
            const dstPort = parseInt((s.dst || '').split(':')[1]) || 0;
            let proto = 'TCP';
            if (dstPort === 443 || dstPort === 8443) proto = 'HTTPS';
            else if (dstPort === 80 || dstPort === 8080) proto = 'HTTP';
            else if (dstPort === 53) proto = 'DNS';
            else if (dstPort === 22) proto = 'SSH';
            else if (dstPort === 21) proto = 'FTP';
            protoCounts[proto] = (protoCounts[proto] || 0) + 1;
        });

        // Top 5 destination IPs
        const dstCounts = {};
        related.forEach(s => {
            const srcIp = (s.src || '').split(':')[0];
            const dstIp = (s.dst || '').split(':')[0];
            const remote = srcIp === pivotIp ? dstIp : srcIp;
            if (remote) dstCounts[remote] = (dstCounts[remote] || 0) + 1;
        });
        const topDsts = Object.entries(dstCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);

        const html = `
    <div class="osi-modal-header">
        <span style="font-size:1.1rem">🔍</span>
        <div>
            <div style="font-weight:700;font-size:1rem"><code>${this.escapeHtml(pivotIp)}</code></div>
            <div style="font-size:0.75rem;color:var(--text-muted)">Analyse de l'adresse IP</div>
        </div>
    </div>
    <div style="padding:1.25rem">
        <div class="ip-modal-stats">
            <div class="ip-stat-card">
                <div class="ip-stat-value">${related.length}</div>
                <div class="ip-stat-label">Sessions</div>
            </div>
            <div class="ip-stat-card">
                <div class="ip-stat-value">${ipPackets.length.toLocaleString()}</div>
                <div class="ip-stat-label">Paquets</div>
            </div>
            <div class="ip-stat-card">
                <div class="ip-stat-value">${Object.keys(protoCounts).length || 1}</div>
                <div class="ip-stat-label">Protocoles</div>
            </div>
            <div class="ip-stat-card">
                <div class="ip-stat-value">${topDsts.length}</div>
                <div class="ip-stat-label">IPs distantes</div>
            </div>
        </div>

        <div class="ip-mini-charts">
            <div>
                <div style="font-size:0.75rem;color:var(--text-muted);margin-bottom:0.4rem;text-transform:uppercase">Protocoles</div>
                <div id="ipModalProtoChart" style="height:160px"></div>
            </div>
            <div>
                <div style="font-size:0.75rem;color:var(--text-muted);margin-bottom:0.4rem;text-transform:uppercase">Top IPs distantes</div>
                <div id="ipModalDstChart" style="height:160px"></div>
            </div>
        </div>

        <div style="font-size:0.8rem;color:var(--text-muted);margin-bottom:0.5rem">
            ${related.length} session(s) impliquant <strong>${this.escapeHtml(pivotIp)}</strong>
        </div>
        <div style="overflow-x:auto">
        <table class="ip-sessions-table">
            <thead>
                <tr>
                    <th>Dir</th><th>IP distante</th><th>Port</th>
                    <th>État</th><th>Paquets</th><th>Retrans.</th><th>Action</th>
                </tr>
            </thead>
            <tbody>
            ${related.length === 0
                ? `<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:1rem">Aucune session trouvée pour cette IP.</td></tr>`
                : related.map(s => {
                    const srcIp = (s.src || '').split(':')[0];
                    const dstIp = (s.dst || '').split(':')[0];
                    const isOut = srcIp === pivotIp;
                    const remoteIp = isOut ? dstIp : srcIp;
                    const remotePort = isOut ? (s.dst || '').split(':')[1] : (s.src || '').split(':')[1];
                    return `<tr>
                        <td><span class="direction-badge ${isOut ? 'direction-out' : 'direction-in'}">${isOut ? '↗' : '↙'}</span></td>
                        <td><code>${this.escapeHtml(remoteIp || '-')}</code></td>
                        <td><code>${this.escapeHtml(remotePort || '-')}</code></td>
                        <td><span class="state-badge ${this.sanitizeClassToken(s.state || '')}">${this.escapeHtml(s.state || '-')}</span></td>
                        <td>${s.packets || 0}</td>
                        <td>${s.retransmissions || 0}</td>
                        <td>
                            <button class="action-btn" style="font-size:0.72rem;padding:0.25rem 0.5rem"
                                onclick="analyzer.filterByIpFromModal(${JSON.stringify(pivotIp)})">
                                Voir paquets
                            </button>
                        </td>
                    </tr>`;
                }).join('')}
            </tbody>
        </table>
        </div>
    </div>`;

        this.openModal(`Sessions — ${pivotIp}`, html);

        // Render mini charts after modal DOM is ready
        requestAnimationFrame(() => {
            const protoChart = this.initChart('ipModalProtoChart');
            if (protoChart && Object.keys(protoCounts).length) {
                protoChart.setOption({
                    backgroundColor: 'transparent',
                    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
                    series: [{
                        type: 'pie', radius: ['40%', '70%'],
                        data: Object.entries(protoCounts).map(([name, value]) => ({ name, value })),
                        label: { fontSize: 10 },
                    }]
                });
            }
            const dstChart = this.initChart('ipModalDstChart');
            if (dstChart && topDsts.length) {
                dstChart.setOption({
                    backgroundColor: 'transparent',
                    tooltip: { trigger: 'axis' },
                    grid: { left: '5%', right: '5%', top: '5%', bottom: '5%', containLabel: true },
                    xAxis: { type: 'value', axisLabel: { fontSize: 9 } },
                    yAxis: { type: 'category', data: topDsts.map(([ip]) => ip), axisLabel: { fontSize: 9 } },
                    series: [{
                        type: 'bar', data: topDsts.map(([, c]) => c),
                        itemStyle: {
                            color: new echarts.graphic.LinearGradient(1, 0, 0, 0, [
                                { offset: 0, color: '#06b6d4' }, { offset: 1, color: '#f97316' }
                            ])
                        }
                    }]
                });
            }
        });
    }

    filterByIpFromModal(ip) {
        this.closeModal();
        this.switchTab('packets');
        const input = document.getElementById('packetFilterInput');
        if (input) {
            input.value = ip;
            this.onPacketFilterInput(ip);
        }
    }

    // ==================== UTILITIES ====================

    escapeHtml(str) {
        return String(str ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    sanitizeClassToken(value) {
        return String(value ?? '')
            .trim()
            .toLowerCase()
            .replace(/[^a-z0-9_-]/g, '');
    }

    formatNumber(num) {
        if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
        if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
        return num.toString();
    }

    truncate(str, len) {
        if (!str) return '-';
        return str.length > len ? str.substring(0, len) + '...' : str;
    }

    showError(message) {
        const progressStatus = document.getElementById('progressStatus');
        if (progressStatus) {
            progressStatus.textContent = `❌ ${message}`;
            progressStatus.style.color = 'var(--danger)';
        }
    }

    resetUploadArea() {
        setTimeout(() => {
            document.getElementById('uploadArea').style.display = 'block';
            document.getElementById('progressContainer').style.display = 'none';
        }, 2000);
    }

    resetAnalysis() {
        // Arrêter le polling de statut avant de perdre le task_id
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
        this.currentTaskId = null;
        this.currentResults = null;
        this.renderSignatures = { dns: '', http: '' };
        this.streamsLoadedKey = '';
        this.packetsLoadedTaskId = '';
        this.streamsData = [];
        this.allPackets = [];
        this.filteredPackets = [];
        this.packetIndex = { byProto: {}, byIp: {} };
        this.chatHistory = [];
        this.guidedProblems = [];
        this.guidedQuestions = [];
        this.autoQuestionnaireInProgress = false;
        this.autoQuestionnaireDoneForTask = '';
        if (this.autoQuestionnaireTimer) {
            clearTimeout(this.autoQuestionnaireTimer);
            this.autoQuestionnaireTimer = null;
        }
        this.multiPcapResults = null;
        this.multiRenderedDetailSessionId = null;
        this.multiPcapTaskId = null;
        this.multiSelectedSessionId = null;
        this.multiSegmentFilter = '';
        this.multiRiskMinFilter = 0;
        this.multiHopFocusedIndex = null;
        this.destroyMultiHopVisuals();
        this.destroyChart('multiEquipmentChainGraph');
        this.networkVisualState = {
            ...this.networkVisualState,
            mode: 'idle',
            riskLevel: 'NONE',
            anomalyCount: 0,
            intensity: 0.18,
            burst: 0.12,
            updatedAt: Date.now(),
        };

        document.getElementById('resultsSection').style.display = 'none';
        document.getElementById('uploadSection').style.display = 'block';
        document.getElementById('uploadArea').style.display = 'block';
        document.getElementById('progressContainer').style.display = 'none';

        // Reset chatbot
        const chatMessages = document.getElementById('chatbotMessages');
        if (chatMessages) {
            chatMessages.innerHTML = `
                <div class="chat-message ai">
                    <div class="chat-avatar">🤖</div>
                    <div class="chat-bubble">Bonjour ! Analysez un fichier PCAP pour commencer. 📊</div>
                </div>
            `;
        }
        this.renderChatSuggestions();
        this.renderProblemSpotlight(null);

        this.applyFocusInvestigation();
        this.showToast('info', 'Réinitialisé', 'Prêt pour une nouvelle analyse');
    }

    // View shortcuts
    showPacketsView() { this.switchTab('packets'); }
    showTcpSessionsView() { this.switchTab('streams'); }
    showAnomaliesView() { this.switchTab('overview'); }
    showDnsView() { this.switchTab('dns'); }
    showHttpView() { this.switchTab('http'); }
    showIpDetailsFromChart() { /* TODO */ }

    // ==================== TEAM IA ANALYSIS ====================

    async launchTeamAnalysis() {
        if (!this.currentTaskId) {
            this.showToast('warning', 'Pas d\'analyse', 'Veuillez d\'abord analyser un fichier PCAP');
            return;
        }

        const launchBtn = document.getElementById('launchTeamBtn');
        if (launchBtn) launchBtn.disabled = true;

        const agents = ['brainstormer', 'chef_projet', 'programmeur', 'validateur', 'red_team'];
        const agentNames = {
            'brainstormer': '🎯 Threat Hunter',
            'chef_projet': '🛡️ Incident Commander',
            'programmeur': '🔬 Forensic Engineer',
            'validateur': '🔍 SOC Analyst',
            'red_team': '💀 Red Team / APT'
        };
        const agentActions = {
            'brainstormer': 'Le Threat Hunter analyse les menaces...',
            'chef_projet': 'Le Commandant d\'Incident coordonne...',
            'programmeur': 'L\'Ingénieur Forensic approfondit...',
            'validateur': 'Le SOC Analyst valide l\'investigation...',
            'red_team': 'La Red Team simule des attaques adverses...'
        };

        // Show progress
        const progressEl = document.getElementById('teamProgress');
        const progressFill = document.getElementById('teamProgressFill');
        const progressText = document.getElementById('teamProgressText');
        const resultsEl = document.getElementById('teamResults');

        if (progressEl) progressEl.style.display = 'block';
        if (resultsEl) {
            resultsEl.style.display = 'block';
            resultsEl.innerHTML = '';
        }

        // Reset all agent cards
        agents.forEach(agent => {
            const card = document.getElementById(`agent-${agent}`);
            const state = document.getElementById(`state-${agent}`);
            if (card) card.className = 'agent-card';
            if (state) state.textContent = 'En attente';
        });

        this.showToast('info', 'Team IA', 'Lancement de l\'équipe d\'analyse...');

        // Animate: mark first agent as thinking
        const setAgentState = (agentId, state, text) => {
            const card = document.getElementById(`agent-${agentId}`);
            const stateEl = document.getElementById(`state-${agentId}`);
            const stepEl = document.getElementById(`step-${agentId}`);
            if (card) card.className = `agent-card ${state}`;
            if (stateEl) stateEl.textContent = text;
            if (stepEl) {
                stepEl.className = `progress-step ${state === 'thinking' ? 'active' : state}`;
            }
        };

        // Show all agents as pending, then launch
        agents.forEach(a => setAgentState(a, '', 'En attente'));
        setAgentState(agents[0], 'thinking', 'Réflexion...');
        if (progressText) progressText.textContent = agentActions[agents[0]];
        if (progressFill) progressFill.style.width = '5%';

        try {
            const response = await fetch(`/api/analysis/${this.currentTaskId}/team-analysis`);
            const data = await response.json();

            if (!data.success) {
                this.showToast('error', 'Erreur Team IA', data.error || 'Erreur inconnue');
                agents.forEach(a => setAgentState(a, 'error', 'Erreur'));
                if (launchBtn) launchBtn.disabled = false;
                return;
            }

            // Display results progressively with animation
            const agentResults = data.agents || [];

            for (let i = 0; i < agentResults.length; i++) {
                const result = agentResults[i];
                const agentId = result.id;

                // Update progress
                const progress = ((i + 1) / agents.length) * 100;
                if (progressFill) progressFill.style.width = `${progress}%`;

                // Mark current agent as completed
                setAgentState(agentId, result.status === 'error' ? 'error' : 'completed',
                    result.status === 'error' ? 'Erreur' : `${result.duration}s`);

                // Mark next agent as thinking
                if (i + 1 < agents.length) {
                    setAgentState(agents[i + 1], 'thinking', 'Réflexion...');
                    if (progressText) progressText.textContent = agentActions[agents[i + 1]];
                }

                // Add result card with delay for animation
                await this._addTeamResultCard(resultsEl, result, i * 100);
            }

            if (progressText) progressText.textContent = `✅ Analyse terminée en ${data.total_duration}s`;

            this.showToast('success', 'Team IA', `Analyse complète terminée en ${data.total_duration}s !`);

        } catch (error) {
            console.error('Team analysis error:', error);
            this.showToast('error', 'Erreur', 'Erreur lors de l\'analyse d\'équipe');
            agents.forEach(a => setAgentState(a, 'error', 'Erreur'));
        } finally {
            if (launchBtn) launchBtn.disabled = false;
        }
    }

    async launchSingleAgent(agentName) {
        if (!this.currentTaskId) {
            this.showToast('warning', 'Pas d\'analyse', 'Veuillez d\'abord analyser un fichier PCAP');
            return;
        }

        const card = document.getElementById(`agent-${agentName}`);
        const state = document.getElementById(`state-${agentName}`);
        const resultsEl = document.getElementById('teamResults');

        if (card) card.className = 'agent-card thinking';
        if (state) state.textContent = 'Réflexion...';
        if (resultsEl) resultsEl.style.display = 'block';

        this.showToast('info', 'Agent IA', `Lancement de l'agent ${agentName}...`);

        try {
            const response = await fetch(`/api/analysis/${this.currentTaskId}/agent/${agentName}`);
            const data = await response.json();

            if (data.success) {
                if (card) card.className = 'agent-card completed';
                if (state) state.textContent = `${data.duration}s`;
                this._addTeamResultCard(resultsEl, data, 0);
                this.showToast('success', 'Agent IA', `Agent ${agentName} terminé en ${data.duration}s`);
            } else {
                if (card) card.className = 'agent-card error';
                if (state) state.textContent = 'Erreur';
                this.showToast('error', 'Erreur', data.error || 'Erreur inconnue');
            }
        } catch (error) {
            if (card) card.className = 'agent-card error';
            if (state) state.textContent = 'Erreur';
            this.showToast('error', 'Erreur', error.message);
        }
    }

    async _addTeamResultCard(container, result, delay = 0) {
        if (!container) return;

        const agent = result.agent || result;
        const card = document.createElement('div');
        card.className = 'team-result-card';
        card.style.animationDelay = `${delay}ms`;

        card.innerHTML = `
            <div class="team-result-header" onclick="this.nextElementSibling.style.display = this.nextElementSibling.style.display === 'none' ? 'block' : 'none'">
                <span class="agent-emoji">${agent.emoji || '🤖'}</span>
                <span class="agent-name">${agent.name || 'Agent'}</span>
                <span class="agent-role">${agent.role || ''}</span>
                <span class="agent-duration">${result.duration ? result.duration + 's' : ''}</span>
            </div>
            <div class="team-result-body">
                ${this.formatAIContent(result.analysis || result.error || 'Pas de résultat')}
                ${this.renderAIStructuredTable(result.structured || null, result.analysis || result.error || '')}
            </div>
        `;

        container.appendChild(card);

        // Scroll to new card
        card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    async openOllamaConfigMenu() {
        this.openModal('Configuration Ollama', '<div class="loading-spinner"><div class="spinner"></div></div>');
        try {
            const response = await fetch('/api/ai/config');
            const data = await response.json();

            const endpoint = String(data.endpoint || '');
            const model = String(data.model || '');
            const timeout = Number(data.timeout || 300);
            const models = Array.isArray(data.models) ? data.models : [];
            const statusCls = data.available ? 'connected' : 'disconnected';
            const statusText = data.available
                ? `Connecté (${models.length} modèle${models.length > 1 ? 's' : ''})`
                : `Déconnecté${data.error ? `: ${data.error}` : ''}`;

            const modelOptions = (models.length ? models : (model ? [model] : []))
                .map(m => `<option value="${this.escapeHtml(m)}" ${m === model ? 'selected' : ''}>${this.escapeHtml(m)}</option>`)
                .join('') || '<option value="">Aucun modèle détecté</option>';

            const html = `
                <div class="ollama-config-panel">
                    <div class="ollama-config-status ${statusCls}" id="ollamaConfigStatus">
                        <span class="dot"></span>
                        <span id="ollamaConfigStatusText">${this.escapeHtml(statusText)}</span>
                    </div>
                    <div class="ollama-config-grid">
                        <div class="ollama-config-field">
                            <label for="ollamaEndpointInput">Endpoint Ollama</label>
                            <input id="ollamaEndpointInput" type="text" value="${this.escapeHtml(endpoint)}" placeholder="http://127.0.0.1:11434" />
                        </div>
                        <div class="ollama-config-field">
                            <label for="ollamaTimeoutInput">Timeout (s)</label>
                            <input id="ollamaTimeoutInput" type="number" min="60" step="10" value="${Number.isFinite(timeout) ? timeout : 300}" />
                        </div>
                    </div>
                    <div class="ollama-config-field">
                        <label for="ollamaModelSelect">Modèle</label>
                        <select id="ollamaModelSelect">${modelOptions}</select>
                    </div>
                    <div class="ollama-config-actions">
                        <div class="ollama-config-help" id="ollamaConfigHelp">
                            Renseigne l'IP/URL Ollama, teste la connexion, puis applique la config.
                        </div>
                        <div style="display:flex;gap:0.5rem;">
                            <button class="btn btn-small" onclick="analyzer.refreshOllamaModels()">🔄 Tester</button>
                            <button class="btn btn-primary" onclick="analyzer.saveOllamaConfig()">💾 Appliquer</button>
                        </div>
                    </div>
                </div>
            `;

            const modalBody = document.getElementById('modalBody');
            if (modalBody) modalBody.innerHTML = html;
        } catch (error) {
            const modalBody = document.getElementById('modalBody');
            if (modalBody) {
                modalBody.innerHTML = `<div class="adv-error">❌ Impossible de charger la configuration Ollama: ${this.escapeHtml(error.message || String(error))}</div>`;
            }
        }
    }

    async refreshOllamaModels() {
        const endpointInput = document.getElementById('ollamaEndpointInput');
        const modelSelect = document.getElementById('ollamaModelSelect');
        const statusEl = document.getElementById('ollamaConfigStatus');
        const statusTextEl = document.getElementById('ollamaConfigStatusText');
        const helpEl = document.getElementById('ollamaConfigHelp');

        const endpoint = endpointInput?.value?.trim();
        if (!endpoint) {
            this.showToast('warning', 'Ollama', 'Veuillez renseigner un endpoint Ollama');
            return;
        }

        if (statusEl) statusEl.className = 'ollama-config-status';
        if (statusTextEl) statusTextEl.textContent = 'Test de connexion en cours...';

        try {
            const response = await fetch(`/api/ai/models?endpoint=${encodeURIComponent(endpoint)}`);
            const data = await response.json();
            const models = Array.isArray(data.models) ? data.models : [];

            if (modelSelect) {
                const current = modelSelect.value;
                modelSelect.innerHTML = models.length
                    ? models.map(m => `<option value="${this.escapeHtml(m)}" ${m === current ? 'selected' : ''}>${this.escapeHtml(m)}</option>`).join('')
                    : '<option value="">Aucun modèle détecté</option>';
            }

            if (statusEl) statusEl.className = `ollama-config-status ${data.available ? 'connected' : 'disconnected'}`;
            if (statusTextEl) {
                statusTextEl.textContent = data.available
                    ? `Connecté (${models.length} modèle${models.length > 1 ? 's' : ''})`
                    : `Déconnecté${data.error ? `: ${data.error}` : ''}`;
            }
            if (helpEl && data.available && models.length) {
                helpEl.textContent = `Modèles détectés: ${models.slice(0, 4).join(', ')}${models.length > 4 ? '…' : ''}`;
            }
        } catch (error) {
            if (statusEl) statusEl.className = 'ollama-config-status disconnected';
            if (statusTextEl) statusTextEl.textContent = 'Déconnecté';
            if (helpEl) helpEl.textContent = `Erreur: ${error.message || String(error)}`;
        }
    }

    async saveOllamaConfig() {
        const endpointInput = document.getElementById('ollamaEndpointInput');
        const modelSelect = document.getElementById('ollamaModelSelect');
        const timeoutInput = document.getElementById('ollamaTimeoutInput');

        const endpoint = endpointInput?.value?.trim();
        const model = modelSelect?.value?.trim();
        const timeout = Number(timeoutInput?.value);

        if (!endpoint) {
            this.showToast('warning', 'Ollama', 'Endpoint Ollama requis');
            return;
        }

        try {
            const response = await fetch('/api/ai/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    endpoint,
                    model: model || null,
                    timeout: Number.isFinite(timeout) ? timeout : null
                })
            });
            const data = await response.json();

            if (data.available) {
                this.showToast('success', 'Ollama', `Configuration appliquée (${data.model || 'modèle non défini'})`);
            } else {
                this.showToast('warning', 'Ollama', `Configuration enregistrée, mais connexion KO (${data.error || 'inconnue'})`);
            }
            if (Array.isArray(data.warnings) && data.warnings.length) {
                this.showToast('info', 'Ollama', data.warnings[0]);
            }

            await this.checkOllamaStatus();
            await this.openOllamaConfigMenu();
        } catch (error) {
            this.showToast('error', 'Ollama', `Erreur de sauvegarde: ${error.message || String(error)}`);
        }
    }

    async openMacLookupConfigMenu() {
        this.openModal('Configuration MacLookup', '<div class="loading-spinner"><div class="spinner"></div></div>');
        try {
            const response = await fetch('/api/maclookup/config');
            const data = await response.json();

            const endpoint = String(data.endpoint || 'https://api.maclookup.app/v2/macs');
            const timeout = Number(data.timeout || 2.0);
            const enabled = Boolean(data.enabled);
            const statusCls = data.available ? 'connected' : 'disconnected';
            const statusText = data.available
                ? `Connecté${data.sample_vendor ? ` (${data.sample_vendor})` : ''}`
                : `Déconnecté${data.error ? `: ${data.error}` : ''}`;

            const html = `
                <div class="ollama-config-panel">
                    <div class="ollama-config-status ${statusCls}" id="maclookupConfigStatus">
                        <span class="dot"></span>
                        <span id="maclookupConfigStatusText">${this.escapeHtml(statusText)}</span>
                    </div>
                    <div class="ollama-config-grid">
                        <div class="ollama-config-field">
                            <label for="maclookupEndpointInput">Endpoint API</label>
                            <input id="maclookupEndpointInput" type="text" value="${this.escapeHtml(endpoint)}" placeholder="https://api.maclookup.app/v2/macs" />
                        </div>
                        <div class="ollama-config-field">
                            <label for="maclookupTimeoutInput">Timeout (s)</label>
                            <input id="maclookupTimeoutInput" type="number" min="0.5" max="10" step="0.1" value="${Number.isFinite(timeout) ? timeout : 2.0}" />
                        </div>
                    </div>
                    <div class="ollama-config-grid">
                        <div class="ollama-config-field">
                            <label for="maclookupApiKeyInput">API Key MacLookup</label>
                            <input id="maclookupApiKeyInput" type="password" value="" placeholder="Laisser vide pour conserver la clé actuelle" autocomplete="off" />
                        </div>
                        <div class="ollama-config-field">
                            <label for="maclookupEnabledSelect">Fallback online</label>
                            <select id="maclookupEnabledSelect">
                                <option value="1" ${enabled ? 'selected' : ''}>Activé</option>
                                <option value="0" ${enabled ? '' : 'selected'}>Désactivé</option>
                            </select>
                        </div>
                    </div>
                    <div class="ollama-config-field">
                        <label for="maclookupTestMacInput">MAC de test</label>
                        <input id="maclookupTestMacInput" type="text" value="${this.escapeHtml(data.test_mac || '00:50:56:AA:BB:CC')}" placeholder="00:50:56:AA:BB:CC" />
                    </div>
                    <div class="ollama-config-actions">
                        <div class="ollama-config-help" id="maclookupConfigHelp">
                            Configure la clé API MacLookup puis teste la résolution avant d'appliquer.
                        </div>
                        <div style="display:flex;gap:0.5rem;">
                            <button class="btn btn-small" onclick="analyzer.testMacLookupConfig()">🔄 Tester</button>
                            <button class="btn btn-primary" onclick="analyzer.saveMacLookupConfig()">💾 Appliquer</button>
                        </div>
                    </div>
                </div>
            `;

            const modalBody = document.getElementById('modalBody');
            if (modalBody) modalBody.innerHTML = html;
        } catch (error) {
            const modalBody = document.getElementById('modalBody');
            if (modalBody) {
                modalBody.innerHTML = `<div class="adv-error">❌ Impossible de charger la configuration MacLookup: ${this.escapeHtml(error.message || String(error))}</div>`;
            }
        }
    }

    async testMacLookupConfig() {
        const endpointInput = document.getElementById('maclookupEndpointInput');
        const timeoutInput = document.getElementById('maclookupTimeoutInput');
        const apiKeyInput = document.getElementById('maclookupApiKeyInput');
        const enabledSelect = document.getElementById('maclookupEnabledSelect');
        const macInput = document.getElementById('maclookupTestMacInput');
        const statusEl = document.getElementById('maclookupConfigStatus');
        const statusTextEl = document.getElementById('maclookupConfigStatusText');
        const helpEl = document.getElementById('maclookupConfigHelp');

        const endpoint = endpointInput?.value?.trim();
        const mac = macInput?.value?.trim() || '00:50:56:AA:BB:CC';
        const timeout = Number(timeoutInput?.value);
        const enabled = String(enabledSelect?.value || '1') === '1';
        const apiKey = apiKeyInput?.value ?? '';

        if (!endpoint) {
            this.showToast('warning', 'MacLookup', 'Endpoint API requis');
            return;
        }

        if (statusEl) statusEl.className = 'ollama-config-status';
        if (statusTextEl) statusTextEl.textContent = 'Test de connexion en cours...';

        try {
            const response = await fetch('/api/maclookup/test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    mac,
                    enabled,
                    endpoint,
                    api_key: apiKey || null,
                    timeout: Number.isFinite(timeout) ? timeout : null
                })
            });
            const data = await response.json();
            const ok = Boolean(data.available);

            if (statusEl) statusEl.className = `ollama-config-status ${ok ? 'connected' : 'disconnected'}`;
            if (statusTextEl) {
                statusTextEl.textContent = ok
                    ? `Connecté (${data.vendor || 'Vendor trouvé'})`
                    : `Déconnecté${data.error ? `: ${data.error}` : ''}`;
            }
            if (helpEl) {
                helpEl.textContent = ok
                    ? `MAC ${data.mac || mac} → ${data.vendor || 'Inconnu'}`
                    : `Test KO: ${data.error || 'inconnu'}`;
            }
        } catch (error) {
            if (statusEl) statusEl.className = 'ollama-config-status disconnected';
            if (statusTextEl) statusTextEl.textContent = 'Déconnecté';
            if (helpEl) helpEl.textContent = `Erreur: ${error.message || String(error)}`;
        }
    }

    async saveMacLookupConfig() {
        const endpointInput = document.getElementById('maclookupEndpointInput');
        const timeoutInput = document.getElementById('maclookupTimeoutInput');
        const apiKeyInput = document.getElementById('maclookupApiKeyInput');
        const enabledSelect = document.getElementById('maclookupEnabledSelect');
        const macInput = document.getElementById('maclookupTestMacInput');

        const endpoint = endpointInput?.value?.trim();
        const mac = macInput?.value?.trim() || '00:50:56:AA:BB:CC';
        const timeout = Number(timeoutInput?.value);
        const enabled = String(enabledSelect?.value || '1') === '1';
        const apiKey = apiKeyInput?.value ?? '';

        if (!endpoint) {
            this.showToast('warning', 'MacLookup', 'Endpoint API requis');
            return;
        }

        try {
            const response = await fetch('/api/maclookup/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    enabled,
                    endpoint,
                    api_key: apiKey || null,
                    timeout: Number.isFinite(timeout) ? timeout : null,
                    test_mac: mac
                })
            });
            const data = await response.json();
            if (data.available) {
                this.showToast('success', 'MacLookup', `Configuration appliquée (${data.sample_vendor || 'OK'})`);
            } else {
                this.showToast('warning', 'MacLookup', `Configuration enregistrée, test KO (${data.error || 'inconnu'})`);
            }
            await this.checkMacLookupStatus();
            await this.openMacLookupConfigMenu();
        } catch (error) {
            this.showToast('error', 'MacLookup', `Erreur de sauvegarde: ${error.message || String(error)}`);
        }
    }

    // ==================== OLLAMA STATUS CHECK ====================

    async checkOllamaStatus() {
        try {
            const response = await fetch('/api/ai/status');
            const data = await response.json();

            const statusEl = document.getElementById('ollamaStatus');
            const dotEl = document.getElementById('ollamaDot');
            const labelEl = document.getElementById('ollamaLabel');

            if (statusEl) {
                if (data.available) {
                    statusEl.className = 'ollama-status connected';
                    if (labelEl) labelEl.textContent = this.truncate(data.model || 'Ollama ✓', 18);
                    statusEl.title = `Connecté: ${data.endpoint || 'endpoint inconnu'}`;
                } else {
                    statusEl.className = 'ollama-status disconnected';
                    if (labelEl) labelEl.textContent = 'Ollama ✗';
                    statusEl.title = `Déconnecté: ${data.error || 'serveur injoignable'}`;
                }
            }
        } catch (e) {
            const statusEl = document.getElementById('ollamaStatus');
            if (statusEl) {
                statusEl.className = 'ollama-status disconnected';
                statusEl.title = 'Déconnecté: erreur de requête';
            }
            const labelEl = document.getElementById('ollamaLabel');
            if (labelEl) labelEl.textContent = 'Ollama ✗';
        }
    }

    async checkMacLookupStatus(probe = true) {
        try {
            // probe=false pour les rafraîchissements périodiques: pas d'appel
            // à l'API externe maclookup, juste l'état connu du backend
            const response = await fetch(`/api/maclookup/status${probe ? '?probe=true' : ''}`);
            const data = await response.json();

            const statusEl = document.getElementById('maclookupStatus');
            const labelEl = document.getElementById('maclookupLabel');
            if (!statusEl) return;

            if (data.available) {
                statusEl.className = 'ollama-status connected';
                if (labelEl) labelEl.textContent = this.truncate(data.sample_vendor || 'MAC ✓', 18);
                statusEl.title = `MacLookup OK: ${data.endpoint || 'endpoint inconnu'}`;
            } else {
                statusEl.className = 'ollama-status disconnected';
                if (labelEl) labelEl.textContent = 'MAC ✗';
                statusEl.title = `MacLookup KO: ${data.error || 'API injoignable'}`;
            }
        } catch (e) {
            const statusEl = document.getElementById('maclookupStatus');
            if (statusEl) {
                statusEl.className = 'ollama-status disconnected';
                statusEl.title = 'MacLookup KO: erreur de requête';
            }
            const labelEl = document.getElementById('maclookupLabel');
            if (labelEl) labelEl.textContent = 'MAC ✗';
        }
    }

    // ==================== ANIMATED COUNTERS ====================

    animateCounter(elementId, targetValue, duration = 1200) {
        const el = document.getElementById(elementId);
        if (!el) return;

        const numTarget = parseInt(String(targetValue).replace(/[^0-9]/g, ''));
        if (isNaN(numTarget) || numTarget === 0) {
            el.textContent = targetValue;
            return;
        }

        let start = 0;
        const startTime = performance.now();

        const animate = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);

            // Easing: easeOutExpo
            const eased = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress);

            const current = Math.floor(eased * numTarget);
            el.textContent = this.formatNumber(current);

            if (progress < 1) {
                requestAnimationFrame(animate);
            } else {
                el.textContent = this.formatNumber(numTarget);
                el.classList.add('counting');
                setTimeout(() => el.classList.remove('counting'), 300);
            }
        };

        requestAnimationFrame(animate);
    }

    // ==================== PARTICLE BACKGROUND ====================

    initParticles() {
        const canvas = document.getElementById('particleCanvas');
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        let particles = [];

        const resize = () => {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
            createParticles();
        };
        const clamp = (value, min, max) => Math.max(min, Math.min(max, value));
        const isDark = () => document.documentElement.getAttribute('data-theme') === 'dark';

        const colorForRisk = (riskLevel, alpha = 0.3) => {
            const risk = String(riskLevel || 'NONE').toUpperCase();
            const darkPalette = {
                NONE: [34, 211, 238],
                LOW: [16, 185, 129],
                MEDIUM: [249, 115, 22],
                HIGH: [244, 63, 94],
                CRITICAL: [239, 68, 68],
            };
            const lightPalette = {
                NONE: [14, 165, 233],
                LOW: [5, 150, 105],
                MEDIUM: [234, 88, 12],
                HIGH: [225, 29, 72],
                CRITICAL: [220, 38, 38],
            };
            const palette = isDark() ? darkPalette : lightPalette;
            const rgb = palette[risk] || palette.NONE;
            return `rgba(${rgb[0]}, ${rgb[1]}, ${rgb[2]}, ${clamp(alpha, 0, 1).toFixed(3)})`;
        };

        const createParticles = () => {
            particles = [];
            const particleCount = Math.min(80, Math.floor((canvas.width * canvas.height) / 21000));
            for (let i = 0; i < particleCount; i++) {
                particles.push({
                    x: Math.random() * canvas.width,
                    y: Math.random() * canvas.height,
                    vx: (Math.random() - 0.5) * 0.55,
                    vy: (Math.random() - 0.5) * 0.55,
                    radius: Math.random() * 2 + 0.4,
                });
            }
        };

        const drawShaderGlow = (timeSec, state) => {
            const intensity = clamp(Number(state.intensity || 0.18), 0.08, 1);
            const pulse = 0.5 + 0.5 * Math.sin(timeSec * (1.2 + intensity * 1.9));
            const burst = clamp(Number(state.burst || 0.12), 0.08, 0.95);
            const centerX = canvas.width * (0.45 + Math.sin(timeSec * 0.11) * 0.08);
            const centerY = canvas.height * (0.4 + Math.cos(timeSec * 0.14) * 0.06);
            const secondX = canvas.width * (0.7 + Math.cos(timeSec * 0.09) * 0.06);
            const secondY = canvas.height * (0.68 + Math.sin(timeSec * 0.12) * 0.05);

            const radiusPrimary = Math.max(canvas.width, canvas.height) * (0.42 + 0.18 * burst);
            const radiusSecondary = Math.max(canvas.width, canvas.height) * (0.28 + 0.12 * burst);
            const alphaPrimary = 0.05 + intensity * 0.18 + pulse * 0.08 * burst;
            const alphaSecondary = 0.03 + intensity * 0.14;

            const grad1 = ctx.createRadialGradient(centerX, centerY, 24, centerX, centerY, radiusPrimary);
            grad1.addColorStop(0, colorForRisk(state.riskLevel, alphaPrimary));
            grad1.addColorStop(1, 'rgba(0, 0, 0, 0)');
            ctx.fillStyle = grad1;
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            const grad2 = ctx.createRadialGradient(secondX, secondY, 16, secondX, secondY, radiusSecondary);
            grad2.addColorStop(0, colorForRisk(state.riskLevel, alphaSecondary));
            grad2.addColorStop(1, 'rgba(0, 0, 0, 0)');
            ctx.fillStyle = grad2;
            ctx.fillRect(0, 0, canvas.width, canvas.height);
        };

        resize();
        window.addEventListener('resize', resize);

        let lastFrameTime = 0;
        const FRAME_INTERVAL = 1000 / 30; // 30 fps suffisent pour un fond décoratif

        const animate = (timestamp = 0) => {
            // Pause complète quand l'onglet est caché (0% CPU en arrière-plan)
            if (document.hidden) {
                requestAnimationFrame(animate);
                return;
            }
            // Limiter à 30 fps: divise par 2 le coût du fond animé
            if (timestamp - lastFrameTime < FRAME_INTERVAL) {
                requestAnimationFrame(animate);
                return;
            }
            lastFrameTime = timestamp;

            const timeSec = timestamp * 0.001;
            const state = this.networkVisualState || {};
            const intensity = clamp(Number(state.intensity || 0.18), 0.08, 1);
            const riskLevel = String(state.riskLevel || 'NONE').toUpperCase();
            const burst = clamp(Number(state.burst || 0.12), 0.08, 0.95);

            ctx.clearRect(0, 0, canvas.width, canvas.height);
            drawShaderGlow(timeSec, { intensity, burst, riskLevel });

            const speedFactor = 0.5 + intensity * 1.5;
            const connectDistance = 110 + intensity * 90;
            const pointAlpha = 0.24 + intensity * 0.48;

            particles.forEach((particle, i) => {
                const drift = Math.sin(timeSec * 0.75 + i * 0.83) * 0.015 * (0.4 + intensity);
                particle.x += particle.vx * speedFactor + drift;
                particle.y += particle.vy * speedFactor - drift * 0.8;

                if (particle.x < 0 || particle.x > canvas.width) particle.vx *= -1;
                if (particle.y < 0 || particle.y > canvas.height) particle.vy *= -1;

                particle.x = clamp(particle.x, 0, canvas.width);
                particle.y = clamp(particle.y, 0, canvas.height);

                ctx.beginPath();
                ctx.arc(particle.x, particle.y, particle.radius + intensity * 0.65, 0, Math.PI * 2);
                ctx.fillStyle = colorForRisk(riskLevel, pointAlpha);
                ctx.fill();

                for (let j = i + 1; j < particles.length; j++) {
                    const other = particles[j];
                    const dx = other.x - particle.x;
                    const dy = other.y - particle.y;
                    const distance = Math.sqrt(dx * dx + dy * dy);

                    if (distance < connectDistance) {
                        const lineAlpha = (0.05 + intensity * 0.2) * (1 - distance / connectDistance);
                        ctx.beginPath();
                        ctx.moveTo(particle.x, particle.y);
                        ctx.lineTo(other.x, other.y);
                        ctx.strokeStyle = colorForRisk(riskLevel, lineAlpha);
                        ctx.lineWidth = 0.45 + burst * 0.5;
                        ctx.stroke();
                    }
                }
            });

            requestAnimationFrame(animate);
        };

        requestAnimationFrame(animate);
    }
}

// Initialize
const analyzer = new PCAPAnalyzer();

// Post-init: particles + Ollama status
analyzer.initParticles();
analyzer.checkOllamaStatus();
analyzer.checkMacLookupStatus();
// Rafraîchissement périodique: uniquement quand l'onglet est visible,
// et sans sonde externe maclookup (probe=false)
analyzer.statusRefreshInterval = setInterval(() => {
    if (document.hidden) return;
    analyzer.checkOllamaStatus();
    analyzer.checkMacLookupStatus(false);
}, 30000);
