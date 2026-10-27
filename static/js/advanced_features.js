/**
 * PCAP Analyzer Pro v2 — Advanced Features Module
 * Handles all data fetching and rendering for advanced analysis tabs:
 *   1. TLS Security Audit
 *   2. Threat Intelligence
 *   3. Flow Behavior (C2 / Exfiltration)
 *   4. Lateral Movement
 *   5. QoS & Performance
 *   6. TCP Health Diagnostics
 *   7. IR Playbook + DFIR Export
 */

// ─────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────

function advFetch(url) {
    return fetch(url).then(async r => {
        const ct = (r.headers.get('content-type') || '').toLowerCase();
        const isJson = ct.includes('application/json');
        const payload = isJson ? await r.json().catch(() => ({})) : await r.text().catch(() => '');
        if (!r.ok) {
            const detail = isJson
                ? (payload.detail || payload.message || JSON.stringify(payload))
                : String(payload || r.statusText);
            throw new Error(`HTTP ${r.status}: ${detail}`);
        }
        return payload;
    });
}

function advEscape(v) {
    return String(v ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function advNum(v, d = 0) {
    const n = Number(v);
    return Number.isFinite(n) ? n : d;
}

function advSourceList(sources) {
    if (Array.isArray(sources)) {
        return sources.map(v => String(v)).filter(Boolean);
    }
    if (sources && typeof sources === 'object') {
        return Object.keys(sources);
    }
    if (typeof sources === 'string') {
        return sources.split(',').map(s => s.trim()).filter(Boolean);
    }
    return [];
}

function advFormatTimestamp(ts) {
    const n = Number(ts);
    if (!Number.isFinite(n) || n <= 0) return 'N/A';
    const d = new Date(n * 1000);
    if (Number.isNaN(d.getTime())) return String(ts ?? '');
    return `${d.toLocaleDateString('fr-FR')} ${d.toLocaleTimeString('fr-FR')}`;
}

function advHealthPill(level) {
    const value = String(level || '').toUpperCase();
    if (value === 'CRITIQUE' || value === 'CRITICAL' || value === 'HIGH') {
        return '<span class="adv-health-pill adv-health-pill-danger">Élevé</span>';
    }
    if (value === 'MODÉRÉ' || value === 'MEDIUM') {
        return '<span class="adv-health-pill adv-health-pill-warning">Modéré</span>';
    }
    return '<span class="adv-health-pill adv-health-pill-ok">Faible</span>';
}

function advShow(id) {
    const el = document.getElementById(id);
    if (el) el.style.display = '';
}
function advHide(id, display = 'none') {
    const el = document.getElementById(id);
    if (el) el.style.display = display;
}

function advSetHTML(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
}

function advEmptyState(msg = 'Aucune donnée disponible') {
    return `<div class="adv-empty"><span>🔍</span><p>${advEscape(msg)}</p></div>`;
}

function severityBadge(sev) {
    const map = {
        CRITICAL: 'adv-badge-critical',
        HIGH: 'adv-badge-high',
        MEDIUM: 'adv-badge-medium',
        LOW: 'adv-badge-low',
    };
    const cls = map[(sev || '').toUpperCase()] || 'adv-badge-low';
    return `<span class="adv-badge ${cls}">${advEscape(sev || 'N/A')}</span>`;
}

function advTable(headers, rows, emptyMsg) {
    if (!rows || rows.length === 0) return advEmptyState(emptyMsg);
    return `<div class="adv-scroll-table"><table class="adv-data-table">
        <thead><tr>${headers.map(h => `<th>${advEscape(h)}</th>`).join('')}</tr></thead>
        <tbody>${rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join('')}</tr>`).join('')}</tbody>
    </table></div>`;
}

function metricCard(label, value, icon = '', cls = '', attrs = '') {
    return `<div class="adv-metric-card ${cls}" ${attrs}>
        <div class="adv-metric-icon">${icon}</div>
        <div class="adv-metric-value">${value}</div>
        <div class="adv-metric-label">${label}</div>
    </div>`;
}

function advMarkLoadFailed(tabName, taskId) {
    try {
        _advLoaded.delete(`${tabName}:${taskId}`);
    } catch (_) {
        // noop
    }
}

const _advTcpHealthCache = new Map();
const _advTcpHealthFocusByTask = new Map();
const _advTcpHealthAiPending = new Set();
const _advTlsAuditCache = new Map();
const _advThreatIntelCache = new Map();
const _advQosCache = new Map();
const _advTlsSelectedSessionByTask = new Map();
const _advTlsSearchByTask = new Map();
const _advGlobalFilter = { query: '', protocol: '', riskMin: 0 };

function advGetGlobalFilter() {
    return {
        query: String(_advGlobalFilter.query || '').trim().toLowerCase(),
        protocol: String(_advGlobalFilter.protocol || '').trim().toUpperCase(),
        riskMin: Math.max(0, advNum(_advGlobalFilter.riskMin, 0)),
    };
}

function advSetTcpHealthAiStatus(message, type = 'info') {
    const el = document.getElementById('tcpHealthAiStatus');
    if (!el) return;
    el.className = `adv-ai-status ${type}`;
    el.textContent = String(message || '');
}

function advRenderTcpHealthAiResult(text, structured = null) {
    const el = document.getElementById('tcpHealthAiResult');
    if (!el) return;
    const raw = String(text || '').trim();
    if (!raw) {
        el.innerHTML = advEmptyState('Aucune réponse IA');
        return;
    }

    const escaped = advEscape(raw);
    const html = escaped
        .replace(/^### (.*)$/gm, '<h4>$1</h4>')
        .replace(/^## (.*)$/gm, '<h4>$1</h4>')
        .replace(/^# (.*)$/gm, '<h4>$1</h4>')
        .replace(/^\- (.*)$/gm, '<li>$1</li>')
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\n\n+/g, '</p><p>')
        .replace(/\n/g, '<br>');

    const structuredHtml = (
        window.analyzer
        && typeof window.analyzer.renderAIStructuredTable === 'function'
    ) ? window.analyzer.renderAIStructuredTable(structured, raw, false) : '';

    el.innerHTML = `<div class="adv-ai-prose"><p>${html}</p></div>${structuredHtml}`;
}

function advBuildTcpHealthAiPrompt(taskId, data, focusKey = 'sessions') {
    const sum = data?.summary || {};
    const win = data?.window_metrics || {};
    const rtt = data?.rtt_metrics || {};
    const adv = data?.advanced_metrics || {};
    const issues = Array.isArray(data?.probable_issues) ? data.probable_issues.slice(0, 10) : [];
    const recs = Array.isArray(data?.recommendations) ? data.recommendations.slice(0, 10) : [];
    const ips = Array.isArray(data?.problematic_ips) ? data.problematic_ips.slice(0, 10) : [];
    const vendors = Array.isArray(data?.problematic_vendors) ? data.problematic_vendors.slice(0, 6) : [];
    const culpritMatrix = Array.isArray(data?.root_cause_matrix) ? data.root_cause_matrix.slice(0, 10) : [];
    const retransSessions = Array.isArray(data?.top_retransmitting_sessions) ? data.top_retransmitting_sessions.slice(0, 8) : [];
    const bursts = Array.isArray(data?.bursts) ? data.bursts.slice(0, 8) : [];

    const compactIssues = issues.map(i => ({
        title: i?.title || '',
        severity: i?.severity || '',
        details: i?.details || '',
        impact: i?.impact || ''
    }));
    const compactIps = ips.map(i => ({
        ip: i?.ip || '',
        mac: i?.mac || '',
        vendor: i?.vendor || '',
        score: advNum(i?.score, 0),
        sessions: advNum(i?.session_count, 0),
        retrans: advNum(i?.retransmissions, 0),
        rst: advNum(i?.rst_count, 0),
        causes: Array.isArray(i?.possible_causes) ? i.possible_causes.slice(0, 3) : []
    }));
    const compactVendors = vendors.map(v => ({
        vendor: v?.vendor || '',
        score: advNum(v?.score, 0),
        ip_count: advNum(v?.ip_count, 0),
        sessions: advNum(v?.sessions, 0),
    }));
    const compactCulprits = culpritMatrix.map(c => ({
        culprit: c?.culprit || '',
        vendor: c?.vendor || '',
        top_cause: c?.top_cause || '',
        evidence: c?.evidence || '',
        confidence: advNum(c?.confidence, 0),
    }));

    return `Contexte TCP Health (task ${taskId}, focus=${focusKey}):
Résumé: ${JSON.stringify({
        total_sessions: advNum(sum.total_sessions, 0),
        total_retransmissions: advNum(sum.total_retransmissions, 0),
        retransmission_rate_pct: advNum(sum.retransmission_rate, 0),
        sessions_with_retransmission_pct: advNum(sum.sessions_with_retransmission_pct, 0),
        sessions_with_rst_pct: advNum(sum.sessions_with_rst_pct, 0),
        half_open_percentage: advNum(sum.half_open_percentage, 0),
        avg_rtt_ms: advNum(sum.avg_rtt_ms, 0),
        max_rtt_ms: advNum(sum.max_rtt_ms, 0),
        rtt_range_ms: advNum(sum.rtt_range_ms, advNum(rtt.range_ms, 0)),
        zero_window_count: advNum(sum.zero_window_count, advNum(win.zero_window_count, 0)),
        zero_window_percentage: advNum(sum.zero_window_percentage, advNum(win.zero_window_percentage, 0)),
        window_pressure_score: advNum(sum.window_pressure_score, advNum(win.window_pressure_score, 0)),
        bottleneck_score: advNum(sum.bottleneck_score, 0),
        bottleneck_level: sum.bottleneck_level || '',
        handshake_success_rate: advNum(sum.handshake_success_rate, advNum(adv.handshake_success_rate, 0)),
        bursts_count: advNum(sum.bursts_count, 0),
        bursts_per_minute: advNum(sum.bursts_per_minute, advNum(adv.bursts_per_minute, 0)),
        problematic_ips_count: advNum(sum.problematic_ips_count, 0),
        problematic_macs_count: advNum(sum.problematic_macs_count, 0),
        broadcast_percentage: advNum(sum.broadcast_percentage, 0),
        multicast_percentage: advNum(sum.multicast_percentage, 0)
    })}
Top issues: ${JSON.stringify(compactIssues)}
Top IPs/équipements: ${JSON.stringify(compactIps)}
Top vendors: ${JSON.stringify(compactVendors)}
Root-cause matrix: ${JSON.stringify(compactCulprits)}
Top sessions retransmises: ${JSON.stringify(retransSessions)}
Bursts: ${JSON.stringify(bursts)}
Recommandations déjà calculées: ${JSON.stringify(recs)}

Tu es un ingénieur réseau senior orienté root-cause.
Analyse ces données et réponds en français avec ce format strict:
1) "Synthèse" (5 à 8 lignes max)
2) "Signaux techniques observés" (ralentissement, congestion, pertes, reset, zero-window)
3) "Équipement(s) potentiellement coupable(s)" (TOP 3 max):
   - IP / MAC / Vendor
   - indice de confiance (0-100)
   - pourquoi techniquement (preuves métriques)
4) "Vérifications de confirmation" (commandes/contrôles concrets)
5) "Actions correctives" (immédiates puis durables)

Important:
- Si les preuves sont insuffisantes, indique-le explicitement.
- Ne pas inventer de données absentes.
- Priorise congestion, ralentissement, goulot d'étranglement et segments suspects.`;
}

async function advAnalyzeTcpHealthWithAI(taskId) {
    const realTaskId = String(taskId || (window.analyzer?.currentTaskId || '')).trim();
    if (!realTaskId) {
        advSetTcpHealthAiStatus('Aucune analyse en cours.', 'error');
        return;
    }
    if (_advTcpHealthAiPending.has(realTaskId)) return;

    const data = _advTcpHealthCache.get(realTaskId);
    if (!data) {
        advSetTcpHealthAiStatus('Chargez d’abord les données TCP Health.', 'warning');
        return;
    }

    _advTcpHealthAiPending.add(realTaskId);
    const btn = document.getElementById('tcpHealthAiAnalyzeBtn');
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Analyse IA...';
    }
    advSetTcpHealthAiStatus('Analyse IA en cours...', 'loading');
    advRenderTcpHealthAiResult('');

    try {
        const focusKey = _advTcpHealthFocusByTask.get(realTaskId) || 'sessions';
        const prompt = advBuildTcpHealthAiPrompt(realTaskId, data, focusKey);
        const response = await fetch(`/api/analysis/${encodeURIComponent(realTaskId)}/chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: prompt })
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) {
            throw new Error(payload?.detail || payload?.error || `HTTP ${response.status}`);
        }
        if (!payload?.success) {
            throw new Error(payload?.error || 'Service IA indisponible');
        }

        advRenderTcpHealthAiResult(payload.response || '', payload.structured || null);
        advSetTcpHealthAiStatus(`Analyse IA terminée (${payload.model || 'modèle inconnu'})`, 'success');
    } catch (e) {
        advSetTcpHealthAiStatus(`Erreur IA TCP Health: ${e.message}`, 'error');
        advRenderTcpHealthAiResult(`Erreur IA: ${e.message}`);
    } finally {
        _advTcpHealthAiPending.delete(realTaskId);
        if (btn) {
            btn.disabled = false;
            btn.textContent = 'Analyser TCP Health';
        }
    }
}

let advTlsHandshakeFlowInst = null;

function advFilterTlsCatalog(catalog, gf) {
    const rows = Array.isArray(catalog) ? catalog : [];
    return rows.filter((s) => {
        const risk = String(s?.overall_risk_level || s?.risk_level || '').toUpperCase();
        if (gf.riskMin >= 70 && risk !== 'HIGH') return false;
        if (gf.riskMin >= 40 && !['HIGH', 'MEDIUM'].includes(risk)) return false;
        // On n'applique pas de filtre protocole strict ici pour éviter de masquer
        // les sessions TLS quand le drilldown global est positionné sur un autre module.
        if (!gf.query) return true;
        const txt = `${s?.flow || ''} ${s?.sni || ''} ${s?.ja3 || ''} ${s?.tls_version || ''} ${s?.cipher || ''}`.toLowerCase();
        return txt.includes(gf.query);
    });
}

function advRenderTlsHandshakeSummary(summary) {
    const rs = summary?.risk_distribution || {};
    const trs = summary?.transport_risk_distribution || {};
    const srs = summary?.security_risk_distribution || {};
    advSetHTML('tlsHandshakeSummaryCards', `
        <div class="adv-ti-cards">
            ${metricCard('Handshake complets', advNum(summary?.complete_handshakes, 0), '🤝', '')}
            ${metricCard('Handshake incomplets', advNum(summary?.incomplete_handshakes, 0), '⚠️', advNum(summary?.incomplete_handshakes, 0) > 0 ? 'adv-metric-warning' : '')}
            ${metricCard('Success rate', `${advNum(summary?.handshake_success_rate, 0).toFixed(1)}%`, '✅', advNum(summary?.handshake_success_rate, 0) < 95 ? 'adv-metric-warning' : '')}
            ${metricCard('RTT handshake p95 (est)', `${advNum(summary?.handshake_rtt_ms_p95_est, 0).toFixed(1)} ms`, '⏱️', advNum(summary?.handshake_rtt_ms_p95_est, 0) >= 150 ? 'adv-metric-warning' : '')}
            ${metricCard('Sessions HIGH (global)', advNum(rs.high, 0), '🔴', advNum(rs.high, 0) > 0 ? 'adv-metric-danger' : '')}
            ${metricCard('HIGH transport', advNum(trs.high, 0), '📉', advNum(trs.high, 0) > 0 ? 'adv-metric-warning' : '')}
            ${metricCard('HIGH sécurité TLS', advNum(srs.high, 0), '🔐', advNum(srs.high, 0) > 0 ? 'adv-metric-danger' : '')}
            ${metricCard('RST paquets', advNum(summary?.total_rst_packets, 0), '⛔', advNum(summary?.total_rst_packets, 0) > 0 ? 'adv-metric-warning' : '')}
        </div>
    `);
}

function advRenderTlsSessionMetrics(session) {
    const transportRisk = String(session?.transport_risk_level || session?.risk_level || 'LOW').toUpperCase();
    const securityRisk = String(session?.security_risk_level || 'LOW').toUpperCase();
    const overallRisk = String(session?.overall_risk_level || transportRisk || 'LOW').toUpperCase();
    const renderRiskPill = (risk) => `<span class="adv-health-pill ${risk === 'HIGH' ? 'adv-health-pill-danger' : (risk === 'MEDIUM' ? 'adv-health-pill-warning' : 'adv-health-pill-ok')}">${advEscape(risk || 'LOW')}</span>`;
    const transportReasons = Array.isArray(session?.transport_risk_reasons) ? session.transport_risk_reasons : [];
    const securityReasons = Array.isArray(session?.security_risk_reasons) ? session.security_risk_reasons : [];

    const rows = session ? [
        ['Flow', `<code>${advEscape(session.flow || '-')}</code>`],
        ['SNI', advEscape(session.sni || '-')],
        ['Version TLS', advEscape(session.tls_version || '-')],
        ['Cipher', `<code>${advEscape(session.cipher || '-')}</code>`],
        ['JA3 / JA3S', `<code>${advEscape(session.ja3 || '-')}</code><br><code>${advEscape(session.ja3s || '-')}</code>`],
        ['État TCP', advEscape(session.tcp_state || '-')],
        ['Retransmissions / RST', `${advNum(session.tcp_retransmissions, 0)} / ${advNum(session.tcp_rst, 0)}`],
        ['Durée session', `${advNum(session.duration_s, 0).toFixed(3)} s`],
        ['Handshake SYN/SYN-ACK/ACK', `${advNum(session?.handshake_flags?.syn, 0)} / ${advNum(session?.handshake_flags?.syn_ack, 0)} / ${advNum(session?.handshake_flags?.ack, 0)}`],
        ['RTT handshake (est)', `${advNum(session.handshake_rtt_ms_est, 0).toFixed(2)} ms`],
        ['Risque transport', renderRiskPill(transportRisk)],
        ['Risque sécurité TLS', renderRiskPill(securityRisk)],
        ['Risque global', renderRiskPill(overallRisk)],
        ['Cause(s) transport', transportReasons.length ? advEscape(transportReasons.join(' • ')) : '-'],
        ['Cause(s) sécurité TLS', securityReasons.length ? advEscape(securityReasons.join(' • ')) : '-'],
    ] : [];
    advSetHTML('tlsSessionMetricsTable', advTable(['Métrique', 'Valeur'], rows, 'Aucune session TLS sélectionnée'));
}

function advRenderTlsHandshakeFlow(session) {
    const chartEl = document.getElementById('tlsHandshakeFlowChart');
    if (!chartEl || typeof echarts === 'undefined') return;
    if (advTlsHandshakeFlowInst) {
        advTlsHandshakeFlowInst.dispose();
        advTlsHandshakeFlowInst = null;
    }
    advTlsHandshakeFlowInst = echarts.init(chartEl);
    if (!session) {
        advTlsHandshakeFlowInst.setOption({
            backgroundColor: 'transparent',
            graphic: [{ type: 'text', left: 'center', top: 'middle', style: { text: 'Sélectionnez une session TLS', fill: '#94a3b8' } }]
        });
        return;
    }

    const hf = session.handshake_flags || {};
    const complete = Boolean(hf.complete);
    const hasSyn = advNum(hf.syn, 0) > 0;
    const hasSynAck = advNum(hf.syn_ack, 0) > 0;
    const hasAck = advNum(hf.ack, 0) > 0;
    const statusColor = complete ? '#10b981' : '#f97316';

    const nodes = [
        { name: 'Client', x: 90, y: 120, symbolSize: 62, itemStyle: { color: '#0ea5e9' } },
        { name: 'Server', x: 420, y: 120, symbolSize: 62, itemStyle: { color: '#6366f1' } },
    ];
    const edges = [];
    if (hasSyn) {
        edges.push({ source: 'Client', target: 'Server', value: `SYN`, lineStyle: { color: '#06b6d4', width: 2.5 }, label: { show: true, formatter: 'SYN' } });
    }
    if (hasSynAck) {
        edges.push({ source: 'Server', target: 'Client', value: `SYN-ACK`, lineStyle: { color: '#f59e0b', width: 2.5 }, label: { show: true, formatter: 'SYN-ACK' } });
    }
    if (hasAck) {
        edges.push({ source: 'Client', target: 'Server', value: `ACK`, lineStyle: { color: '#22c55e', width: 2.5 }, label: { show: true, formatter: 'ACK' } });
    }

    advTlsHandshakeFlowInst.setOption({
        backgroundColor: 'transparent',
        tooltip: { trigger: 'item' },
        graphic: [
            {
                type: 'text',
                left: 14,
                top: 8,
                style: {
                    text: `3-Way Handshake • ${complete ? 'COMPLET' : 'PARTIEL'} • RTT est ${advNum(session.handshake_rtt_ms_est, 0).toFixed(2)} ms`,
                    fill: statusColor,
                    font: '600 13px Space Grotesk',
                },
            }
        ],
        series: [{
            type: 'graph',
            layout: 'none',
            data: nodes,
            links: edges,
            edgeSymbol: ['none', 'arrow'],
            edgeSymbolSize: [4, 10],
            lineStyle: { curveness: 0.1, opacity: 0.95 },
            label: { color: '#e2e8f0', fontWeight: 700 },
            roam: false,
        }],
        grid: { left: 0, right: 0, top: 0, bottom: 0 },
    });
}

// ─────────────────────────────────────────────────────────
// 1. TLS Security Audit
// ─────────────────────────────────────────────────────────

async function loadTlsAudit(taskId, forceRefresh = false) {
    advShow('tls-audit-loading');
    try {
        // Cache lu en priorité: la recherche/le drilldown re-rendent sans refetch
        let data = forceRefresh ? null : _advTlsAuditCache.get(taskId);
        if (!data) {
            data = await advFetch(`/api/${taskId}/tls-audit`);
            _advTlsAuditCache.set(taskId, data);
        }
        const gf = advGetGlobalFilter();

        // Grade badge
        const grade = data.grade || 'N/A';
        const gradeColors = { 'A+': '#00c851', 'A': '#00c851', 'B': '#ffbb33', 'C': '#ff8800', 'D': '#ff4444', 'F': '#cc0000' };
        const gradeColor = gradeColors[grade] || '#888';
        const gBadge = document.getElementById('tlsGradeBadge');
        const gScore = document.getElementById('tlsScore');
        if (gBadge) { gBadge.textContent = grade; gBadge.style.background = gradeColor; }
        if (gScore) gScore.textContent = `${advNum(data.overall_score, 0)}/100`;

        const sum = data.summary || {};
        advSetHTML('tlsSummaryStats', `
            <span>${advNum(sum.total_sessions_audited, 0)} sessions auditées</span> ·
            <span>${advNum(sum.malware_ja3_matches, 0)} JA3 malware</span> ·
            <span>${advNum(sum.weak_cipher_sessions, 0)} ciphers faibles</span> ·
            <span>${advNum(sum.deprecated_tls_sessions, 0)} TLS dépréciés</span>
        `);
        document.getElementById('tlsGradeSection').style.display = '';

        // Critical findings
        const criticals = (Array.isArray(data.critical_findings) ? data.critical_findings : []).filter((f) => {
            if (!gf.query) return true;
            const txt = (typeof f === 'string' ? f : `${f?.type || ''} ${f?.detail || ''} ${f?.description || ''}`).toLowerCase();
            return txt.includes(gf.query);
        });
        advSetHTML('tlsCriticalFindings', criticals.length
            ? criticals.map(f => {
                const title = typeof f === 'string' ? 'Finding' : (f.type || 'Finding');
                const detail = typeof f === 'string' ? f : (f.detail || f.description || '');
                return `<div class="adv-finding adv-finding-critical">
                <span class="adv-finding-icon">🔴</span>
                <div><strong>${advEscape(title)}</strong><p>${advEscape(detail)}</p></div>
              </div>`;
            }).join('')
            : advEmptyState('Aucun finding critique'));

        // Warnings
        const warns = (Array.isArray(data.warnings) ? data.warnings : []).filter((f) => {
            if (!gf.query) return true;
            return String(f || '').toLowerCase().includes(gf.query);
        });
        advSetHTML('tlsWarnings', warns.length
            ? warns.map(f => {
                const title = typeof f === 'string' ? 'Avertissement' : (f.type || 'Avertissement');
                const detail = typeof f === 'string' ? f : (f.detail || f.description || '');
                return `<div class="adv-finding adv-finding-warning">
                <span class="adv-finding-icon">🟠</span>
                <div><strong>${advEscape(title)}</strong><p>${advEscape(detail)}</p></div>
              </div>`;
            }).join('')
            : advEmptyState('Aucun avertissement'));

        // Malware JA3
        const matches = (Array.isArray(data.malware_ja3_matches) ? data.malware_ja3_matches : []).filter((m) => {
            if (!gf.query) return true;
            return `${m?.ja3 || ''} ${m?.malware_family || ''} ${m?.malware_name || ''} ${(m?.src_ips || []).join(' ')}`.toLowerCase().includes(gf.query);
        });
        advSetHTML('tlsMalwareMatches', advTable(
            ['JA3 Hash', 'Famille Malware', 'Ports', 'Sessions'],
            matches.map(m => [
                `<code>${advEscape(m.ja3 || '')}</code>`,
                `<strong style="color:#ff4444">${advEscape(m.malware_family || m.malware_name || '')}</strong>`,
                advEscape(((m.dst_ports || m.snis || []).slice(0, 5).join(', '))),
                advNum(m.session_count || m.count, 0)
            ]),
            'Aucun JA3 malware détecté ✅'
        ));

        // Ciphers
        const ciphers = (Array.isArray(data.top_cipher_suites) ? data.top_cipher_suites : []).filter((c) => {
            if (gf.riskMin >= 70 && !(c?.weak || c?.is_weak)) return false;
            if (!gf.query) return true;
            return `${c?.name || c?.cipher_suite || c?.cipher || ''}`.toLowerCase().includes(gf.query);
        });
        advSetHTML('tlsCiphers', advTable(
            ['Cipher Suite', 'Sessions', 'Statut'],
            ciphers.slice(0, 15).map(c => [
                `<code>${advEscape(c.name || c.cipher_suite || c.cipher || '')}</code>`,
                advNum(c.count, 0),
                (c.weak || c.is_weak) ? '<span style="color:#ff8800">⚠️ Faible</span>' : '✅ OK'
            ]),
            'Aucune donnée cipher'
        ));

        const rawCatalog = Array.isArray(data.tls_session_catalog) ? data.tls_session_catalog : [];
        const tlsLocalQuery = String(_advTlsSearchByTask.get(taskId) || '').trim().toLowerCase();
        const catalog = rawCatalog.filter((s) => {
            if (!tlsLocalQuery) return true;
            const txt = `${s?.flow || ''} ${s?.sni || ''} ${s?.ja3 || ''} ${s?.tls_version || ''} ${s?.cipher || ''}`.toLowerCase();
            return txt.includes(tlsLocalQuery);
        });
        advRenderTlsHandshakeSummary(data.tcp_handshake_summary || {});
        const selectorEl = document.getElementById('tlsSessionSelect');
        const searchEl = document.getElementById('tlsSessionSearch');
        if (searchEl && searchEl !== document.activeElement) {
            searchEl.value = String(_advTlsSearchByTask.get(taskId) || '');
        }
        const renderSessionById = (sessionId) => {
            const session = (catalog || []).find((s) => String(s.session_id) === String(sessionId)) || null;
            advRenderTlsHandshakeFlow(session);
            advRenderTlsSessionMetrics(session);
        };
        if (selectorEl) {
            selectorEl.innerHTML = `<option value="">Sélectionner une session TLS</option>${catalog.slice(0, 120).map((s) => {
                const lvl = String(s.overall_risk_level || s.risk_level || 'LOW').toUpperCase();
                const riskBadge = lvl === 'HIGH' ? '🔴' : (lvl === 'MEDIUM' ? '🟠' : '🟢');
                const label = `${riskBadge} ${s.flow} ${s.sni ? `• ${s.sni}` : ''}`;
                return `<option value="${advEscape(s.session_id)}">${advEscape(label)}</option>`;
            }).join('')}`;
            if (!catalog.length) {
                selectorEl.innerHTML = '<option value="">Aucune session TLS détectée (ou filtrée)</option>';
                advRenderTlsHandshakeFlow(null);
                const warningHit = (Array.isArray(data.warnings) ? data.warnings : []).some((w) =>
                    String(w || '').toLowerCase().includes('fallback') || String(w || '').toLowerCase().includes('cipher suite not usable')
                );
                advSetHTML(
                    'tlsSessionMetricsTable',
                    advEmptyState(
                        warningHit
                            ? 'Parser TLS limité sur cette capture. Essayez sans filtre global, ou activez le fallback TCP (déjà appliqué côté API).'
                            : 'Aucune session TLS correspondante.'
                    )
                );
                return;
            }
            const selectedStored = _advTlsSelectedSessionByTask.get(taskId) || '';
            const selected = catalog.some((s) => String(s.session_id) === String(selectedStored))
                ? selectedStored
                : (catalog[0]?.session_id || '');
            selectorEl.value = String(selected || '');
            selectorEl.onchange = () => {
                const next = String(selectorEl.value || '');
                _advTlsSelectedSessionByTask.set(taskId, next);
                renderSessionById(next);
            };
            if (selected) {
                _advTlsSelectedSessionByTask.set(taskId, String(selected));
                renderSessionById(selected);
            } else {
                advRenderTlsHandshakeFlow(null);
                advRenderTlsSessionMetrics(null);
            }
        }
        if (searchEl && !searchEl.dataset.bound) {
            searchEl.dataset.bound = '1';
            let searchDebounce = null;
            searchEl.addEventListener('input', () => {
                clearTimeout(searchDebounce);
                searchDebounce = setTimeout(() => {
                    _advTlsSearchByTask.set(taskId, String(searchEl.value || '').trim());
                    loadTlsAudit(taskId); // re-render depuis le cache, pas de refetch
                }, 250);
            });
        }

        const versionChartEl = document.getElementById('tlsVersionDistChart');
        if (versionChartEl && typeof echarts !== 'undefined') {
            const versions = {};
            (Array.isArray(catalog) ? catalog : []).forEach((s) => {
                const key = String(s?.tls_version || 'Unknown');
                versions[key] = (versions[key] || 0) + 1;
            });
            const prev = echarts.getInstanceByDom(versionChartEl);
            if (prev) prev.dispose();
            const chart = echarts.init(versionChartEl);
            const entries = Object.entries(versions);
            chart.setOption({
                backgroundColor: 'transparent',
                tooltip: { trigger: 'item' },
                series: [{
                    type: 'pie',
                    radius: ['40%', '70%'],
                    center: ['48%', '50%'],
                    label: { color: '#cbd5e1' },
                    data: entries.length ? entries.map(([k, v]) => ({ name: k, value: advNum(v, 0) })) : [{ name: 'No data', value: 1 }],
                }]
            });
        }

        // Recommendations
        const recs = data.recommendations || [];
        advSetHTML('tlsRecommendations', recs.length
            ? recs.map((r, i) => `<div class="adv-rec"><span class="adv-rec-num">${i + 1}</span><p>${r}</p></div>`).join('')
            : advEmptyState('Aucune recommandation'));

    } catch (e) {
        advMarkLoadFailed('tls-audit', taskId);
        advSetHTML('tls-audit-content', `<div class="adv-error">❌ Erreur: ${e.message}</div>`);
    } finally {
        advHide('tls-audit-loading');
    }
}

// ─────────────────────────────────────────────────────────
// 2. Threat Intelligence
// ─────────────────────────────────────────────────────────

async function loadThreatIntel(taskId, forceRefresh = false) {
    advShow('threat-intel-loading');
    try {
        let data = forceRefresh ? null : _advThreatIntelCache.get(taskId);
        if (!data) {
            data = await advFetch(`/api/${taskId}/threat-intel`);
            _advThreatIntelCache.set(taskId, data);
        }
        const gf = advGetGlobalFilter();
        const sum = data.summary || {};
        const analytics = data.analytics || {};

        // Summary cards
        advSetHTML('tiSummaryCards', `
            <div class="adv-ti-cards">
                ${metricCard('IPs Malveillantes', sum.malicious_ips || 0, '🔴', sum.malicious_ips > 0 ? 'adv-metric-danger' : '')}
                ${metricCard('IPs Suspectes', sum.suspicious_ips || 0, '🟠', sum.suspicious_ips > 0 ? 'adv-metric-warning' : '')}
                ${metricCard('IPs Analysées', sum.total_ips_checked || 0, '🌍', '')}
                ${metricCard('IoCs Critiques', (data.critical_iocs || []).length, '🎯', (data.critical_iocs || []).length > 0 ? 'adv-metric-danger' : '')}
            </div>
        `);

        const scoreDist = analytics.score_distribution || {};
        const scoreChartEl = document.getElementById('tiScoreDistChart');
        if (scoreChartEl && typeof echarts !== 'undefined') {
            const prev = echarts.getInstanceByDom(scoreChartEl);
            if (prev) prev.dispose();
            const chart = echarts.init(scoreChartEl);
            chart.setOption({
                backgroundColor: 'transparent',
                tooltip: { trigger: 'item' },
                xAxis: { type: 'category', data: ['Malicious', 'Suspicious', 'Clean'], axisLabel: { color: '#94a3b8' } },
                yAxis: { type: 'value', axisLabel: { color: '#94a3b8' } },
                series: [{
                    type: 'bar',
                    data: [
                        { value: advNum(scoreDist.malicious, 0), itemStyle: { color: '#ef4444' } },
                        { value: advNum(scoreDist.suspicious, 0), itemStyle: { color: '#f97316' } },
                        { value: advNum(scoreDist.clean, 0), itemStyle: { color: '#10b981' } },
                    ],
                    barMaxWidth: 36
                }],
                grid: { top: 20, right: 18, bottom: 28, left: 42 }
            });
        }

        const srcCovEl = document.getElementById('tiSourceCoverageChart');
        if (srcCovEl && typeof echarts !== 'undefined') {
            const srcMap = analytics.source_hit || {};
            const entries = Object.entries(srcMap);
            const prev = echarts.getInstanceByDom(srcCovEl);
            if (prev) prev.dispose();
            const chart = echarts.init(srcCovEl);
            chart.setOption({
                backgroundColor: 'transparent',
                tooltip: { trigger: 'item' },
                series: [{
                    type: 'pie',
                    radius: ['42%', '70%'],
                    center: ['48%', '50%'],
                    label: { color: '#cbd5e1' },
                    data: entries.length
                        ? entries.map(([k, v]) => ({ name: k, value: advNum(v, 0) }))
                        : [{ name: 'No data', value: 1 }],
                }]
            });
        }

        const countryRows = (Array.isArray(analytics.top_country_risk) ? analytics.top_country_risk : []).map((row) => [
            advEscape(row.country || 'N/A'),
            advNum(row.score, 0).toFixed(1),
        ]);
        advSetHTML('tiCountryRiskTable', advTable(['Pays', 'Score risque agrégé'], countryRows, 'Aucune agrégation pays'));

        // Critical IoCs
        const iocs = (Array.isArray(data.critical_iocs) ? data.critical_iocs : []).filter((i) => {
            if (!gf.query) return true;
            return `${i?.value || ''} ${i?.type || ''}`.toLowerCase().includes(gf.query);
        });
        advSetHTML('tiCriticalIocs', advTable(
            ['Indicateur', 'Type', 'Score', 'Source', 'Verdict'],
            iocs.slice(0, 20).map(i => [
                `<code>${advEscape(i.value || '')}</code>`,
                advEscape(i.type || ''),
                `<span class="adv-score-bar"><span style="width:${advNum(i.score, 0)}%;background:${advNum(i.score, 0) > 70 ? '#ff4444' : advNum(i.score, 0) > 40 ? '#ff8800' : '#ffbb33'}">${advNum(i.score, 0)}%</span></span>`,
                advEscape(i.source || ''),
                advEscape(i.verdict || '')
            ]),
            'Aucun IoC critique détecté ✅'
        ));

        // IP Intel
        const ipIntel = data.ip_intel || {};
        const ipRows = Object.entries(ipIntel)
            .filter(([ip, info]) => {
                const infoObj = (info && typeof info === 'object') ? info : {};
                const score = advNum(infoObj.reputation_score, 0);
                if (gf.riskMin >= 70 && score < 70) return false;
                if (gf.riskMin >= 40 && score < 30) return false;
                if (gf.query && !(`${ip} ${infoObj.verdict || ''}`.toLowerCase().includes(gf.query))) return false;
                return true;
            })
            .slice(0, 20)
            .map(([ip, info]) => {
            const infoObj = (info && typeof info === 'object') ? info : {};
            const score = advNum(infoObj.reputation_score, 0);
            const sources = advSourceList(infoObj.sources);
            const country = infoObj.country || infoObj.geoip?.country_code || infoObj.geoip?.country || 'N/A';
            return [
                `<code>${advEscape(ip)}</code>`,
                `<span style="color:${score > 70 ? '#ff4444' : score > 40 ? '#ff8800' : '#27ae60'}">${score}%</span>`,
                advEscape(sources.join(', ') || 'N/A'),
                advEscape(country),
                advEscape(infoObj.verdict || '')
            ];
        });
        advSetHTML('tiIpIntel', advTable(['IP', 'Score', 'Sources', 'Pays', 'Verdict'], ipRows, 'Aucune IP analysée'));

        // Domain Intel
        const domIntel = data.domain_intel || {};
        const domRows = Object.entries(domIntel)
            .filter(([dom, info]) => {
                const infoObj = (info && typeof info === 'object') ? info : {};
                const score = advNum(infoObj.reputation_score, 0);
                if (gf.riskMin >= 70 && score < 70) return false;
                if (gf.riskMin >= 40 && score < 30) return false;
                if (gf.query && !(`${dom} ${infoObj.verdict || ''}`.toLowerCase().includes(gf.query))) return false;
                return true;
            })
            .slice(0, 20)
            .map(([dom, info]) => {
            const infoObj = (info && typeof info === 'object') ? info : {};
            const score = advNum(infoObj.reputation_score, 0);
            const status = score >= 70
                ? '<span style="color:#ff4444">⚠️ Malveillant</span>'
                : (score >= 30 ? '<span style="color:#ff8800">🟠 Suspect</span>' : '✅ Clean');
            const source = infoObj.source || advSourceList(infoObj.sources).join(', ') || 'N/A';
            const threat = infoObj.threat_type || (
                infoObj.sources &&
                typeof infoObj.sources === 'object' &&
                infoObj.sources.urlhaus &&
                typeof infoObj.sources.urlhaus === 'object'
                    ? infoObj.sources.urlhaus.query_status
                    : ''
            ) || '';
            return [
                `<code>${advEscape(dom)}</code>`,
                status,
                advEscape(source),
                advEscape(threat)
            ];
        });
        advSetHTML('tiDomainIntel', advTable(['Domaine', 'Statut', 'Source', 'Type'], domRows, 'Aucun domaine analysé'));

    } catch (e) {
        advMarkLoadFailed('threat-intel', taskId);
        advSetHTML('threat-intel-content', `<div class="adv-error">❌ Erreur: ${e.message}</div>`);
    } finally {
        advHide('threat-intel-loading');
    }
}

// ─────────────────────────────────────────────────────────
// 3. Flow Behavior (C2 Beaconing / Exfiltration)
// ─────────────────────────────────────────────────────────

async function loadFlowBehavior(taskId) {
    advShow('flow-behavior-loading');
    try {
        const data = await advFetch(`/api/${taskId}/flow-behavior`);
        const sum = data.summary || {};

        advSetHTML('flowSummaryCards', `<div class="adv-summary-strip">
            ${metricCard('Alertes Beaconing', sum.beaconing_alerts || 0, '🎯', sum.beaconing_alerts > 0 ? 'adv-metric-danger' : '')}
            ${metricCard('Alertes Exfiltration', sum.exfiltration_alerts || 0, '📤', sum.exfiltration_alerts > 0 ? 'adv-metric-danger' : '')}
            ${metricCard('Flux Analysés', sum.total_flows_analyzed || 0, '📡', '')}
            ${metricCard('Flow Fingerprints', sum.unique_fingerprints || 0, '🔑', '')}
        </div>`);

        // Beaconing table
        const beacons = data.beaconing_alerts || [];
        advSetHTML('flowBeaconing', advTable(
            ['IP Source', 'IP C2', 'Port', 'Score', 'Intervalle (s)', 'Jitter', 'MITRE', 'Verdict'],
            beacons.map(b => [
                `<code>${advEscape(b.src_ip || '')}</code>`,
                `<code style="color:#ff4444">${advEscape(b.dst_ip || '')}</code>`,
                advEscape(b.dst_port || ''),
                `<strong style="color:${advNum(b.beacon_score, 0) >= 90 ? '#ff4444' : '#ff8800'}">${advNum(b.beacon_score, 0)}</strong>`,
                advNum(b.avg_interval || b.avg_interval_sec, 0).toFixed(1),
                advNum(b.jitter || b.jitter_ratio, 0).toFixed(3),
                `<code>${advEscape(b.mitre || '')}</code>`,
                advEscape(b.verdict || '')
            ]),
            'Aucun beaconing C2 détecté ✅'
        ));

        // Exfiltration table
        const exfil = data.exfiltration_alerts || [];
        advSetHTML('flowExfiltration', advTable(
            ['IP Source', 'IP Dest', 'Port', 'Volume exfiltré', 'Ratio Up/Down', 'MITRE', 'Verdict'],
            exfil.map(e => [
                `<code>${advEscape(e.src_ip || '')}</code>`,
                `<code style="color:#ff8800">${advEscape(e.dst_ip || '')}</code>`,
                advEscape(e.dst_port || ''),
                `<strong>${advNum(e.estimated_exfil_mb, 0).toFixed(2)} MB</strong>`,
                advNum(e.upload_ratio || e.upload_download_ratio, 0).toFixed(2),
                `<code>${advEscape(e.mitre || '')}</code>`,
                advEscape(e.verdict || '')
            ]),
            'Aucune exfiltration détectée ✅'
        ));

        // Fingerprints
        const fps = data.flow_fingerprints || [];
        advSetHTML('flowFingerprints', advTable(
            ['Empreinte', 'Occurrences', 'Protocole', 'Taille moy.', 'Intervalle moy.'],
            fps.slice(0, 20).map(fp => [
                `<code>${advEscape(fp.fingerprint || '')}</code>`,
                advNum(fp.count || fp.total_packets, 0),
                advEscape(fp.protocol || fp.fingerprint_details?.proto || ''),
                `${advNum(fp.avg_size || fp.fingerprint_details?.median_pkt_size_bytes, 0).toFixed(0)} B`,
                `${advNum(fp.avg_interval || fp.fingerprint_details?.avg_interval_ms / 1000, 0).toFixed(2)} s`
            ]),
            'Aucun fingerprint disponible'
        ));

    } catch (e) {
        advMarkLoadFailed('flow-behavior', taskId);
        advSetHTML('flow-behavior-content', `<div class="adv-error">❌ Erreur: ${e.message}</div>`);
    } finally {
        advHide('flow-behavior-loading');
    }
}

// ─────────────────────────────────────────────────────────
// 4. Lateral Movement
// ─────────────────────────────────────────────────────────

async function loadLateralMovement(taskId) {
    advShow('lateral-movement-loading');
    try {
        const data = await advFetch(`/api/${taskId}/lateral-movement`);
        const sum = data.summary || {};

        advSetHTML('lmSummaryCards', `<div class="adv-summary-strip">
            ${metricCard('Pivots', sum.pivot_hosts || 0, '🔀', sum.pivot_hosts > 0 ? 'adv-metric-danger' : '')}
            ${metricCard('Pass-the-Hash', sum.pass_the_hash || 0, '🔑', sum.pass_the_hash > 0 ? 'adv-metric-danger' : '')}
            ${metricCard('Kerberoasting', sum.kerberoasting || 0, '🎫', sum.kerberoasting > 0 ? 'adv-metric-warning' : '')}
            ${metricCard('LDAP Enum', sum.ldap_enumeration || 0, '📖', sum.ldap_enumeration > 0 ? 'adv-metric-warning' : '')}
        </div>`);

        // Pivot hosts
        const pivots = data.pivot_hosts || [];
        advSetHTML('lmPivots', advTable(
            ['Host Pivot', 'Peers Internes', 'Ports', 'Direction', 'Score'],
            pivots.map(p => [
                `<code style="color:#ff8800">${advEscape(p.src_ip || '')}</code>`,
                advNum(p.internal_peer_count || p.target_count, 0),
                advEscape((p.dst_ports || p.targets || []).slice(0, 5).join(', ')),
                advEscape(p.direction || p.protocol || ''),
                advEscape(p.pivot_score || p.risk || '')
            ]),
            'Aucun pivot détecté ✅'
        ));

        // Pass-the-Hash
        const pth = data.pass_the_hash || [];
        advSetHTML('lmPth', advTable(
            ['IP Source', 'IP Cible', 'Échecs NTLM', 'Succès', 'MITRE'],
            pth.map(p => [
                `<code style="color:#ff4444">${advEscape(p.src_ip || '')}</code>`,
                `<code>${advEscape(p.dst_ip || (p.targets || [])[0] || '')}</code>`,
                advNum(p.ntlm_failures || p.failures, 0),
                advNum(p.ntlm_success || p.ntlm_successes || p.successes, 0),
                `<code>${advEscape(p.mitre || 'T1550.002')}</code>`
            ]),
            'Aucun Pass-the-Hash détecté ✅'
        ));

        // Kerberoasting
        const kerb = data.kerberoasting || [];
        advSetHTML('lmKerb', advTable(
            ['IP Source', 'KDC', 'TGS-REQ burst', 'AS-REQ sans preauth', 'MITRE'],
            kerb.map(k => [
                `<code style="color:#ff8800">${advEscape(k.src_ip || '')}</code>`,
                advEscape(k.kdc_ip || ''),
                advNum(k.tgs_req_count, 0),
                advNum(k.as_req_no_preauth || k.total_asreq_no_preauth, 0),
                `<code>${advEscape(k.mitre || 'T1558.003')}</code>`
            ]),
            'Aucun Kerberoasting détecté ✅'
        ));

        // LDAP enumeration
        const ldap = data.ldap_enumeration || [];
        advSetHTML('lmLdap', advTable(
            ['IP Source', 'Requêtes LDAP', 'Filtres Suspects', 'MITRE'],
            ldap.map(l => [
                `<code style="color:#ff8800">${advEscape(l.src_ip || '')}</code>`,
                advNum(l.ldap_query_count || l.query_count, 0),
                advEscape((l.suspicious_filters || []).slice(0, 3).join(', ') || 'N/A'),
                `<code>${advEscape(l.mitre || 'T1069.002')}</code>`
            ]),
            'Aucune énumération LDAP détectée ✅'
        ));

    } catch (e) {
        advMarkLoadFailed('lateral-movement', taskId);
        advSetHTML('lateral-movement-content', `<div class="adv-error">❌ Erreur: ${e.message}</div>`);
    } finally {
        advHide('lateral-movement-loading');
    }
}

// ─────────────────────────────────────────────────────────
// 5. QoS & Performance
// ─────────────────────────────────────────────────────────

let qosRttChartInst = null;
let tcpHealthFocusChartInst = null;

async function loadQos(taskId, forceRefresh = false) {
    advShow('qos-loading');
    try {
        let data = forceRefresh ? null : _advQosCache.get(taskId);
        if (!data) {
            data = await advFetch(`/api/${taskId}/qos-metrics`);
            _advQosCache.set(taskId, data);
        }
        const gf = advGetGlobalFilter();
        const rtt = data.rtt_ms || data.rtt_metrics || {};
        const tcp = data.tcp_summary || {};
        const volumetry = data.volumetry || {};
        const series = Array.isArray(data.timeseries) ? data.timeseries : [];
        const jitter = advNum(rtt.jitter || rtt.jitter_ms || tcp.jitter_ms, 0);
        const healthScore = advNum(tcp.health_score, 0);
        const throughputAvg = advNum(volumetry.throughput_avg_mbps || tcp.throughput_avg_mbps, 0);
        const throughputPeak = advNum(volumetry.throughput_peak_mbps || tcp.throughput_peak_mbps, 0);

        // Metric cards
        advSetHTML('qosMetricsCards', `<div class="adv-qos-strip">
            ${metricCard('RTT Médian (p50)', `${advNum(rtt.p50 || rtt.p50_ms, 0).toFixed(1)} ms`, '⏱️', '')}
            ${metricCard('RTT p95', `${advNum(rtt.p95 || rtt.p95_ms, 0).toFixed(1)} ms`, '📈', advNum(rtt.p95 || rtt.p95_ms, 0) > 100 ? 'adv-metric-warning' : '')}
            ${metricCard('RTT p99', `${advNum(rtt.p99 || rtt.p99_ms, 0).toFixed(1)} ms`, '🔝', advNum(rtt.p99 || rtt.p99_ms, 0) > 200 ? 'adv-metric-danger' : '')}
            ${metricCard('RTT Max', `${advNum(rtt.max || rtt.max_ms, 0).toFixed(1)} ms`, '⚠️', advNum(rtt.max || rtt.max_ms, 0) > 500 ? 'adv-metric-danger' : '')}
            ${metricCard('Jitter RTT', `${jitter.toFixed(2)} ms`, '🌡️', jitter >= 18 ? 'adv-metric-warning' : '')}
            ${metricCard('Débit moyen', `${throughputAvg.toFixed(3)} Mbps`, '📦', throughputAvg >= 40 ? 'adv-metric-warning' : '')}
            ${metricCard('Débit pic', `${throughputPeak.toFixed(3)} Mbps`, '🚀', throughputPeak >= 80 ? 'adv-metric-warning' : '')}
            ${metricCard('Retransmissions', advNum(tcp.total_retransmissions, 0), '🔄', advNum(tcp.total_retransmissions, 0) > 50 ? 'adv-metric-warning' : '')}
            ${metricCard('Zero Windows', advNum(tcp.total_zero_windows, 0), '🪟', advNum(tcp.total_zero_windows, 0) > 10 ? 'adv-metric-warning' : '')}
            ${metricCard('Health Score', `${healthScore.toFixed(1)}/100`, '🧭', healthScore < 45 ? 'adv-metric-danger' : (healthScore < 70 ? 'adv-metric-warning' : ''), '')}
        </div>`);

        // RTT chart using ECharts
        const chartEl = document.getElementById('qosRttChart');
        if (chartEl && typeof echarts !== 'undefined') {
            if (qosRttChartInst) qosRttChartInst.dispose();
            qosRttChartInst = echarts.init(chartEl);
            if (series.length >= 3) {
                const labels = series.map((row) => advFormatTimestamp(row.timestamp));
                qosRttChartInst.setOption({
                    backgroundColor: 'transparent',
                    tooltip: { trigger: 'axis' },
                    legend: { top: 0, textStyle: { color: '#94a3b8' } },
                    xAxis: { type: 'category', data: labels, axisLabel: { color: '#94a3b8', fontSize: 10 } },
                    yAxis: [
                        { type: 'value', name: 'pps', axisLabel: { color: '#94a3b8' } },
                        { type: 'value', name: 'Mbps', axisLabel: { color: '#94a3b8' } }
                    ],
                    series: [
                        {
                            name: 'Paquets/s',
                            type: 'bar',
                            yAxisIndex: 0,
                            data: series.map((row) => advNum(row.packets_per_sec, 0)),
                            itemStyle: { color: 'rgba(14,165,233,0.5)' },
                            barMaxWidth: 14
                        },
                        {
                            name: 'Débit (Mbps)',
                            type: 'line',
                            smooth: true,
                            yAxisIndex: 1,
                            data: series.map((row) => advNum(row.throughput_mbps, 0)),
                            lineStyle: { width: 2, color: '#34d399' },
                            itemStyle: { color: '#34d399' },
                            areaStyle: { color: 'rgba(52,211,153,0.16)' }
                        },
                        {
                            name: 'Retrans évts/s',
                            type: 'line',
                            smooth: true,
                            yAxisIndex: 0,
                            data: series.map((row) => advNum(row.retrans_events, 0)),
                            lineStyle: { width: 1.6, color: '#f97316' },
                            itemStyle: { color: '#f97316' }
                        }
                    ],
                    dataZoom: [
                        { type: 'inside', start: 0, end: 100 },
                        { type: 'slider', height: 16, bottom: 4, start: 0, end: 100 }
                    ],
                    grid: { top: 30, right: 42, bottom: 38, left: 52 }
                });
            } else {
                qosRttChartInst.setOption({
                    backgroundColor: 'transparent',
                    tooltip: { trigger: 'axis' },
                    xAxis: { type: 'category', data: ['Min', 'p50', 'p95', 'p99', 'Max'], axisLabel: { color: '#aaa' } },
                    yAxis: { type: 'value', name: 'ms', axisLabel: { color: '#aaa' } },
                    series: [{
                        name: 'RTT (ms)',
                        type: 'bar',
                        data: [
                            advNum(rtt.min || rtt.min_ms, 0),
                            advNum(rtt.p50 || rtt.p50_ms, 0),
                            advNum(rtt.p95 || rtt.p95_ms, 0),
                            advNum(rtt.p99 || rtt.p99_ms, 0),
                            advNum(rtt.max || rtt.max_ms, 0),
                        ],
                        itemStyle: {
                            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                                { offset: 0, color: '#06b6d4' },
                                { offset: 1, color: '#0e7490' }
                            ])
                        },
                        label: { show: true, color: '#fff', formatter: '{c} ms' }
                    }],
                    grid: { top: 20, right: 20, bottom: 30, left: 55 }
                });
            }
        }

        // TCP stats table
        const sessionsRaw = data.slow_sessions || data.tcp_sessions || data.sessions || [];
        const sessions = (Array.isArray(sessionsRaw) ? sessionsRaw : []).filter((s) => {
            const queryHit = !gf.query || `${s?.src_ip || s?.src || ''} ${s?.dst_ip || s?.dst || ''} ${s?.state || ''}`.toLowerCase().includes(gf.query);
            if (!queryHit) return false;
            if (gf.riskMin >= 70) return advNum(s?.retransmissions, 0) >= 3 || advNum(s?.zero_windows, 0) >= 1 || advNum(s?.avg_rtt_ms || s?.rtt_ms, 0) >= 120;
            if (gf.riskMin >= 40) return advNum(s?.retransmissions, 0) >= 1 || advNum(s?.zero_windows, 0) >= 1 || advNum(s?.avg_rtt_ms || s?.rtt_ms, 0) >= 80;
            return true;
        });
        advSetHTML('qosTcpStats', advTable(
            ['Source', 'Destination', 'Retrans.', 'Zero-Win', 'RTT avg', 'État', 'Cause probable'],
            sessions.slice(0, 20).map(s => [
                `<code>${advEscape((s.src_ip || s.src || ''))}:${advEscape(s.src_port || '')}</code>`,
                `<code>${advEscape((s.dst_ip || s.dst || ''))}:${advEscape(s.dst_port || '')}</code>`,
                advNum(s.retransmissions, 0),
                advNum(s.zero_windows, 0),
                `${advNum(s.avg_rtt_ms || s.rtt_ms, 0).toFixed(1)} ms`,
                advEscape(s.state || ''),
                advEscape(
                    advNum(s.retransmissions, 0) > 0
                        ? 'Pertes/congestion'
                        : (advNum(s.zero_windows, 0) > 0
                            ? 'Fenêtre saturée'
                            : (advNum(s.avg_rtt_ms || s.rtt_ms, 0) > 120 ? 'Latence élevée' : 'Stable'))
                )
            ]),
            'Aucune session TCP disponible'
        ));

    } catch (e) {
        advMarkLoadFailed('qos', taskId);
        advSetHTML('qos-content', `<div class="adv-error">❌ Erreur: ${e.message}</div>`);
    } finally {
        advHide('qos-loading');
    }
}

// ─────────────────────────────────────────────────────────
// 6. TCP Health Diagnostics
// ─────────────────────────────────────────────────────────

function advBuildTcpHealthFocusCatalog(data) {
    const sum = data.summary || {};
    const win = data.window_metrics || {};
    const rtt = data.rtt_metrics || {};
    const adv = data.advanced_metrics || {};
    const sessionDuration = adv.session_duration || {};
    const stability = adv.stability || {};

    const totalSessions = advNum(sum.total_sessions, 0);
    const halfOpen = advNum(sum.half_open_connections, 0);
    const rstSessions = advNum(sum.sessions_with_rst, 0);
    const retransSessions = advNum(sum.sessions_with_retransmissions, 0);
    const retransRate = advNum(sum.retransmission_rate, 0);
    const zeroWinPct = advNum(sum.zero_window_percentage, 0);
    const windowScaleAvg = advNum(win.window_scale_avg, 0);
    const windowScaleP95 = advNum(win.window_scale_p95, 0);
    const windowScaleCoverage = advNum(win.window_scale_coverage_pct, 0);
    const effectiveWindowAvg = advNum(win.effective_avg_window, 0);
    const effectiveWindowMax = advNum(win.effective_max_window, 0);
    const handshakeOk = advNum(sum.handshake_success_rate, 0);
    const bottleneck = advNum(sum.bottleneck_score, 0);
    const windowPressure = advNum(sum.window_pressure_score, 0);
    const rttMin = advNum(rtt.min_rtt_ms, 0);
    const rttAvg = advNum(rtt.avg_rtt_ms, 0);
    const rttMax = advNum(rtt.max_rtt_ms, 0);
    const rttSpread = advNum(sum.rtt_range_ms ?? stability.rtt_range_ms ?? rtt.range_ms, 0);
    const bursts = advNum(sum.bursts_count, 0);
    const burstsMin = advNum(sum.bursts_per_minute, 0);
    const durationAvg = advNum(sum.session_duration_avg_s ?? sessionDuration.avg_seconds, 0);
    const durationP95 = advNum(sum.session_duration_p95_s ?? sessionDuration.p95_seconds, 0);
    const durationMax = advNum(sum.session_duration_max_s ?? sessionDuration.max_seconds, 0);
    const impacted = advNum(sum.problematic_macs_count, 0);
    const broadcastPct = advNum(sum.broadcast_percentage, 0);
    const jitter = advNum(sum.rtt_jitter_ms ?? rtt.jitter_ms ?? stability.rtt_jitter_ms, 0);
    const p95 = advNum(sum.rtt_p95_ms ?? rtt.p95_rtt_ms, 0);
    const throughputAvg = advNum(sum.avg_throughput_mbps ?? adv.avg_throughput_mbps, 0);
    const throughputPeak = advNum(sum.peak_throughput_mbps ?? adv.peak_throughput_mbps, 0);
    const ppsAvg = advNum(sum.avg_pps ?? adv.avg_pps, 0);
    const ppsPeak = advNum(sum.peak_pps ?? adv.peak_pps, 0);
    const healthScore = advNum(sum.health_score ?? adv.health_score, 0);
    const culpritsCount = Array.isArray(data.root_cause_matrix) ? data.root_cause_matrix.length : 0;
    const volumetrySeries = Array.isArray(data.volumetry_timeseries) ? data.volumetry_timeseries : [];

    const issueCount = Array.isArray(data.probable_issues) ? data.probable_issues.length : 0;

    const bar = (name, labels, values) => ({ kind: 'bar', name, labels, values });
    const gauge = (name, value, max = 100) => ({ kind: 'gauge', name, value, max });

    return {
        sessions: {
            title: '🔌 Focus Sessions TCP',
            description: 'Répartition des sessions et signaux de stabilité de connexion.',
            kpis: [
                { label: 'Sessions totales', value: `${totalSessions}` },
                { label: 'Half-open', value: `${halfOpen}` },
                { label: 'Sessions avec RST', value: `${rstSessions}` },
                { label: 'Sessions retransmises', value: `${retransSessions}` }
            ],
            analysis: [
                halfOpen > 0 ? `${halfOpen} sessions half-open: vérifier SYN/SYN-ACK sur le chemin.` : 'Aucune session half-open significative.',
                rstSessions > 0 ? `${rstSessions} sessions avec reset: corréler avec firewall/serveur.` : 'Peu de resets TCP observés.',
                issueCount > 0 ? `${issueCount} causes probables détectées dans le diagnostic global.` : 'Aucune alerte majeure remontée.'
            ],
            chart: bar('Sessions', ['Total', 'Half-open', 'Avec RST', 'Retrans'], [totalSessions, halfOpen, rstSessions, retransSessions])
        },
        rtt: {
            title: '⏱️ Focus RTT',
            description: 'Distribution de latence observée sur les échanges TCP.',
            kpis: [
                { label: 'RTT min', value: `${rttMin.toFixed(2)} ms` },
                { label: 'RTT moyen', value: `${rttAvg.toFixed(2)} ms` },
                { label: 'RTT max', value: `${rttMax.toFixed(2)} ms` },
                { label: 'Spread', value: `${rttSpread.toFixed(2)} ms` }
            ],
            analysis: [
                rttAvg >= 80 ? 'RTT moyen élevé: suspicion congestion ou distance WAN importante.' : 'RTT moyen nominal.',
                rttSpread >= 100 ? 'Variation RTT forte: possible gigue/queueing intermittent.' : 'Spread RTT maîtrisé.',
                rttMax >= 200 ? 'Pics RTT hauts: investiguer micro-bursts ou buffer saturation.' : 'Pas de pic RTT critique.'
            ],
            chart: bar('RTT (ms)', ['Min', 'Moyen', 'Max', 'Spread'], [rttMin, rttAvg, rttMax, rttSpread])
        },
        retrans: {
            title: '🔄 Focus Retransmissions',
            description: 'Volume et exposition des sessions aux retransmissions.',
            kpis: [
                { label: 'Retrans total', value: `${advNum(sum.total_retransmissions, 0)}` },
                { label: 'Taux retrans', value: `${retransRate.toFixed(2)}%` },
                { label: 'Sessions impactées', value: `${retransSessions}` },
                { label: '% sessions impactées', value: `${advNum(sum.sessions_with_retransmission_pct, 0).toFixed(2)}%` }
            ],
            analysis: [
                retransRate >= 5 ? 'Taux retrans élevé: pertes réseau probables.' : (retransRate >= 2 ? 'Taux retrans modéré: à surveiller.' : 'Taux retrans faible.'),
                retransSessions > 0 ? 'Identifier les segments/ports les plus touchés via sessions top retrans.' : 'Pas de session dominante en retransmission.',
                'Croiser avec RTT et bursts pour distinguer perte vs congestion.'
            ],
            chart: bar('Retransmissions', ['Total', 'Taux %', 'Sessions'], [advNum(sum.total_retransmissions, 0), retransRate, retransSessions])
        },
        zero_window: {
            title: '🪟 Focus Zero Window',
            description: 'Pression de réception et saturation potentielle des buffers TCP.',
            kpis: [
                { label: 'Zero Window count', value: `${advNum(sum.zero_window_count, 0)}` },
                { label: 'Zero Window %', value: `${zeroWinPct.toFixed(2)}%` },
                { label: 'Window scale avg', value: `${windowScaleAvg.toFixed(2)}` },
                { label: 'Scale coverage', value: `${windowScaleCoverage.toFixed(1)}%` }
            ],
            analysis: [
                zeroWinPct >= 1 ? 'Zero Window significatif: endpoint récepteur potentiellement saturé.' : 'Peu de signaux Zero Window.',
                windowPressure >= 70 ? 'Pression Window critique: risque blocage applicatif.' : (windowPressure >= 45 ? 'Pression Window modérée/élevée.' : 'Pression Window faible.'),
                windowScaleCoverage < 30
                    ? 'Peu de négociations Window Scale visibles (captures partielles ou flux déjà établis).'
                    : 'Window Scale majoritairement observé, métriques de fenêtre effective exploitables.'
            ],
            chart: bar(
                'Window',
                ['ZeroWin %', 'Pressure', 'WScale avg', 'Scale cov %', 'Eff win avg', 'Eff win max'],
                [zeroWinPct, windowPressure, windowScaleAvg, windowScaleCoverage, effectiveWindowAvg, effectiveWindowMax]
            )
        },
        handshake: {
            title: '🤝 Focus Handshake TCP',
            description: 'Qualité d’établissement des sessions (3-way handshake).',
            kpis: [
                { label: 'Success rate', value: `${handshakeOk.toFixed(2)}%` },
                { label: 'Complets', value: `${advNum(sum.complete_handshakes, 0)}` },
                { label: 'Incomplets', value: `${advNum(sum.incomplete_handshakes, 0)}` },
                { label: 'Half-open', value: `${halfOpen}` }
            ],
            analysis: [
                handshakeOk > 0 && handshakeOk < 95 ? 'Taux handshake dégradé: possible filtre, drop ou backlog saturé.' : 'Taux handshake correct.',
                halfOpen > 0 ? 'Présence de half-open: vérifier retours SYN-ACK et état firewall.' : 'Pas de half-open notable.',
                'Corréler avec logs applicatifs et état des listeners.'
            ],
            chart: gauge('Handshake success %', handshakeOk, 100)
        },
        bursts: {
            title: '⚡ Focus Bursts',
            description: 'Pics de trafic et densité temporelle des bursts.',
            kpis: [
                { label: 'Bursts', value: `${bursts}` },
                { label: 'Bursts/min', value: `${burstsMin.toFixed(2)}` },
                { label: 'Capture (s)', value: `${advNum(sum.capture_duration_seconds, 0).toFixed(2)}` },
                { label: 'Bottleneck score', value: `${bottleneck}/100` }
            ],
            analysis: [
                bursts >= 3 ? 'Bursts récurrents: probables micro-congestions.' : 'Peu de bursts, trafic plutôt lissé.',
                burstsMin >= 3 ? 'Densité bursts/min élevée: surveiller files QoS/egress queue.' : 'Densité bursts modérée.',
                'Comparer avec RTT spread pour confirmer un comportement bufferbloat.'
            ],
            chart: bar('Bursts', ['Count', 'Bursts/min', 'Bottleneck'], [bursts, burstsMin, bottleneck])
        },
        duration: {
            title: '🕰️ Focus Durée des Sessions',
            description: 'Profil de durée des sessions TCP pour repérer les flux longs/problématiques.',
            kpis: [
                { label: 'Durée moyenne', value: `${durationAvg.toFixed(3)} s` },
                { label: 'Durée p95', value: `${durationP95.toFixed(3)} s` },
                { label: 'Durée max', value: `${durationMax.toFixed(3)} s` },
                { label: 'Sessions', value: `${totalSessions}` }
            ],
            analysis: [
                durationP95 >= 30 ? 'Long tail de sessions élevées: investiguer lenteurs applicatives.' : 'P95 de durée raisonnable.',
                durationMax >= 120 ? 'Présence de sessions très longues: vérifier keepalive/latence.' : 'Pas de session extrême dominante.',
                'Corréler avec retransmissions et reset pour identifier les flux pénalisés.'
            ],
            chart: bar('Durées sessions (s)', ['Moyenne', 'p95', 'Max'], [durationAvg, durationP95, durationMax])
        },
        bottleneck: {
            title: '🧠 Focus Risque de Goulot',
            description: 'Score agrégé de congestion/performance basé sur RTT, retrans, windows et bursts.',
            kpis: [
                { label: 'Bottleneck score', value: `${bottleneck}/100` },
                { label: 'Window pressure', value: `${windowPressure}/100` },
                { label: 'Retrans rate', value: `${retransRate.toFixed(2)}%` },
                { label: 'RTT spread', value: `${rttSpread.toFixed(2)} ms` }
            ],
            analysis: [
                bottleneck >= 70 ? 'Risque élevé: segment réseau probablement contraint.' : (bottleneck >= 45 ? 'Risque modéré: symptômes à confirmer.' : 'Risque faible.'),
                windowPressure >= 45 ? 'Composante window pressure significative dans le score global.' : 'Pression window non dominante.',
                'Prioriser les IPs/macs les plus scorées pour isoler le maillon dégradant.'
            ],
            chart: gauge('Bottleneck score', bottleneck, 100)
        },
        infra: {
            title: '🧩 Focus Infrastructure Impactée',
            description: 'Vision équipements impactés et bruit L2 (broadcast).',
            kpis: [
                { label: 'Équipements touchés', value: `${impacted}` },
                { label: 'Broadcast %', value: `${broadcastPct.toFixed(2)}%` },
                { label: 'Multicast %', value: `${advNum(sum.multicast_percentage, 0).toFixed(2)}%` },
                { label: 'Constructeurs impactés', value: `${(data.problematic_vendors || []).length}` }
            ],
            analysis: [
                impacted > 0 ? 'Des équipements/macs sont corrélés aux symptômes TCP.' : 'Aucun équipement clairement dominant.',
                broadcastPct >= 2 ? 'Bruit L2 à surveiller: possible contention locale.' : 'Niveau broadcast faible.',
                'Croiser avec top vendors et IPs problématiques pour cibler l’investigation.'
            ],
            chart: bar('Infra', ['Équipements', 'Broadcast %', 'Multicast %'], [impacted, broadcastPct, advNum(sum.multicast_percentage, 0)])
        },
        volumetry: {
            title: '📈 Focus Volumétrie & Débit',
            description: 'Débit/pps et variabilité temporelle pour détection de saturation ou bursts.',
            kpis: [
                { label: 'PPS moyen', value: `${ppsAvg.toFixed(1)}` },
                { label: 'PPS pic', value: `${ppsPeak.toFixed(0)}` },
                { label: 'Débit moyen', value: `${throughputAvg.toFixed(3)} Mbps` },
                { label: 'Débit pic', value: `${throughputPeak.toFixed(3)} Mbps` }
            ],
            analysis: [
                throughputPeak >= (throughputAvg * 2.5) && throughputPeak > 0
                    ? 'Pics de débit marqués: suspicion de micro-bursts ou trafic applicatif spiky.'
                    : 'Débit relativement stable sur la fenêtre observée.',
                ppsPeak >= (ppsAvg * 3) && ppsPeak > 0
                    ? 'PPS pic nettement supérieur à la moyenne: vérifier files d’attente et drops.'
                    : 'Pas de flambée PPS majeure détectée.',
                'Croiser avec retransmissions et RTT pour confirmer congestion vs charge applicative normale.'
            ],
            chart: {
                kind: 'line',
                name: 'Volumétrie',
                labels: volumetrySeries.slice(0, 180).map((p) => advFormatTimestamp(p.timestamp)),
                series: [
                    { name: 'Paquets/s', data: volumetrySeries.slice(0, 180).map((p) => advNum(p.packets_per_sec, 0)) },
                    { name: 'Mbps', data: volumetrySeries.slice(0, 180).map((p) => advNum(p.throughput_mbps, 0)) },
                    { name: 'Retrans évts/s', data: volumetrySeries.slice(0, 180).map((p) => advNum(p.retrans_events, 0)) },
                ]
            }
        },
        culprits: {
            title: '🕵️ Focus Coupables Probables',
            description: 'Classement des équipements/IP les plus corrélés aux symptômes.',
            kpis: [
                { label: 'Coupables candidats', value: `${culpritsCount}` },
                { label: 'Health score', value: `${healthScore.toFixed(1)}/100` },
                { label: 'RTT p95', value: `${p95.toFixed(2)} ms` },
                { label: 'Jitter', value: `${jitter.toFixed(2)} ms` }
            ],
            analysis: [
                culpritsCount > 0
                    ? 'Des entités ressortent avec des preuves métriques consolidées.'
                    : 'Pas de coupable dominant: analyse à confirmer avec captures complémentaires.',
                healthScore < 45
                    ? 'Santé TCP dégradée: prioriser les équipements top scorés.'
                    : (healthScore < 70 ? 'Santé TCP intermédiaire: surveiller les top suspects.' : 'Santé TCP correcte.'),
                'Vérifier en priorité les causes avec confiance la plus élevée.'
            ],
            chart: bar(
                'Santé/Coupables',
                ['Coupables', 'Health', 'RTT p95', 'Jitter'],
                [culpritsCount, healthScore, p95, jitter]
            )
        }
    };
}

function advRenderTcpHealthFocusChart(chartEl, cfg) {
    if (!chartEl || typeof echarts === 'undefined') return;
    if (tcpHealthFocusChartInst) {
        tcpHealthFocusChartInst.dispose();
        tcpHealthFocusChartInst = null;
    }

    tcpHealthFocusChartInst = echarts.init(chartEl);
    const kind = cfg?.kind || 'bar';

    if (kind === 'gauge') {
        const max = advNum(cfg.max, 100);
        const value = Math.max(0, Math.min(max, advNum(cfg.value, 0)));
        tcpHealthFocusChartInst.setOption({
            backgroundColor: 'transparent',
            tooltip: { formatter: `{a}<br/>{b}: {c}/${max}` },
            series: [{
                name: cfg.name || 'Score',
                type: 'gauge',
                min: 0,
                max,
                progress: { show: true, width: 16 },
                axisLine: { lineStyle: { width: 16 } },
                detail: { valueAnimation: true, formatter: `{value}/${max}`, color: '#e2e8f0', fontSize: 18, offsetCenter: [0, '70%'] },
                data: [{ value, name: cfg.name || 'Score' }],
            }]
        });
        return;
    }

    if (kind === 'line') {
        const labels = Array.isArray(cfg.labels) ? cfg.labels : [];
        const lines = Array.isArray(cfg.series) ? cfg.series : [];
        const lineSeries = lines.map((s, idx) => ({
            name: advEscape(s?.name || `Série ${idx + 1}`),
            type: 'line',
            smooth: true,
            data: Array.isArray(s?.data) ? s.data.map(v => advNum(v, 0)) : [],
            showSymbol: false,
            lineStyle: { width: 2 },
            areaStyle: idx === 1 ? { opacity: 0.12 } : undefined
        }));

        tcpHealthFocusChartInst.setOption({
            backgroundColor: 'transparent',
            tooltip: { trigger: 'axis' },
            legend: { top: 0, textStyle: { color: '#94a3b8' } },
            xAxis: { type: 'category', data: labels, axisLabel: { color: '#94a3b8', fontSize: 10 } },
            yAxis: { type: 'value', axisLabel: { color: '#94a3b8' } },
            series: lineSeries,
            dataZoom: [
                { type: 'inside', start: 0, end: 100 },
                { type: 'slider', bottom: 4, height: 14, start: 0, end: 100 }
            ],
            grid: { top: 30, right: 18, bottom: 30, left: 52 }
        });
        return;
    }

    const labels = Array.isArray(cfg.labels) ? cfg.labels : [];
    const values = Array.isArray(cfg.values) ? cfg.values.map(v => advNum(v, 0)) : [];
    tcpHealthFocusChartInst.setOption({
        backgroundColor: 'transparent',
        tooltip: { trigger: 'axis' },
        xAxis: { type: 'category', data: labels, axisLabel: { color: '#94a3b8' } },
        yAxis: { type: 'value', axisLabel: { color: '#94a3b8' } },
        series: [{
            name: cfg.name || 'Valeurs',
            type: 'bar',
            data: values,
            barMaxWidth: 42,
            itemStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                    { offset: 0, color: '#22d3ee' },
                    { offset: 0.5, color: '#3b82f6' },
                    { offset: 1, color: '#8b5cf6' }
                ]),
                borderRadius: [8, 8, 0, 0]
            },
            label: { show: true, color: '#e2e8f0', formatter: '{c}' }
        }],
        grid: { top: 28, right: 18, bottom: 28, left: 52 }
    });
}

function advRenderTcpHealthFocus(focusKey, catalog) {
    const keys = Object.keys(catalog || {});
    if (!keys.length) return;
    const key = keys.includes(focusKey) ? focusKey : keys[0];
    const item = catalog[key];

    const titleEl = document.getElementById('tcpHealthFocusTitle');
    const bodyEl = document.getElementById('tcpHealthFocusBody');
    const chartEl = document.getElementById('tcpHealthFocusChart');
    if (titleEl) titleEl.textContent = item.title;

    if (bodyEl) {
        const kpis = (item.kpis || []).map(k => `
            <div class="adv-focus-kpi">
                <span>${advEscape(k.label || '')}</span>
                <strong>${advEscape(k.value || '')}</strong>
            </div>
        `).join('');
        const analysis = (item.analysis || []).map((line, idx) => `
            <div class="adv-rec">
                <span class="adv-rec-num">${idx + 1}</span>
                <p>${advEscape(line)}</p>
            </div>
        `).join('');
        bodyEl.innerHTML = `
            <p class="adv-focus-desc">${advEscape(item.description || '')}</p>
            <div class="adv-focus-kpis">${kpis}</div>
            <div class="adv-focus-analysis">${analysis}</div>
        `;
    }

    advRenderTcpHealthFocusChart(chartEl, item.chart || {});
}

function advBindTcpHealthMetricCards(catalog, onSelect = null) {
    const cards = Array.from(document.querySelectorAll('#tcpHealthSummaryCards .adv-metric-card[data-tcp-focus]'));
    if (!cards.length) return;

    cards.forEach((card) => {
        card.classList.add('clickable');
        card.addEventListener('click', () => {
            cards.forEach(c => c.classList.remove('active'));
            card.classList.add('active');
            const focusKey = card.dataset.tcpFocus || '';
            advRenderTcpHealthFocus(focusKey, catalog);
            if (typeof onSelect === 'function') onSelect(focusKey);
        });
    });

    cards[0].classList.add('active');
    const defaultFocusKey = cards[0].dataset.tcpFocus || '';
    advRenderTcpHealthFocus(defaultFocusKey, catalog);
    if (typeof onSelect === 'function') onSelect(defaultFocusKey);
}

function advTcpHealthFilterNote(title, shown, total) {
    return `<div class="adv-filter-note">${advEscape(title)}: ${advNum(shown, 0)} / ${advNum(total, 0)} lignes</div>`;
}

function advTcpHealthFilter(data, focusKey) {
    const issuesAll = Array.isArray(data.probable_issues) ? data.probable_issues : [];
    const recsAll = Array.isArray(data.recommendations) ? data.recommendations : [];
    const vendorsAll = Array.isArray(data.problematic_vendors) ? data.problematic_vendors : [];
    const ipsAll = Array.isArray(data.problematic_ips) ? data.problematic_ips : [];
    const burstsAll = Array.isArray(data.bursts) ? data.bursts : [];
    const retransAll = Array.isArray(data.top_retransmitting_sessions) ? data.top_retransmitting_sessions : [];

    const rx = {
        sessions: /(session|connexion|rst|half-open|syn)/i,
        rtt: /(rtt|latence|queue|qos|traceroute|burst)/i,
        retrans: /(retrans|perte|congestion)/i,
        zero_window: /(window|fenêtre|buffer|récepteur|satur)/i,
        handshake: /(handshake|syn|half-open|connexion)/i,
        bursts: /(burst|micro-congestion|pic)/i,
        duration: /(durée|timeout|latence|session)/i,
        bottleneck: /(goulot|congestion|latence|retrans|window)/i,
        infra: /(broadcast|multicast|vlan|équipement|mac|l2)/i,
        volumetry: /(débit|throughput|pps|burst|volum|saturation|queue)/i,
        culprits: /(coupable|cause|suspect|preuve|équipement|vendor|ip)/i,
    };

    const matchIssue = (issue, key) => {
        const rgx = rx[key];
        if (!rgx) return true;
        const text = `${issue?.title || ''} ${issue?.details || ''} ${issue?.impact || ''}`;
        return rgx.test(text);
    };

    const matchRecommendation = (rec, key) => {
        const rgx = rx[key];
        if (!rgx) return true;
        return rgx.test(String(rec || ''));
    };

    const matchIp = (ip, key) => {
        const causes = Array.isArray(ip?.possible_causes) ? ip.possible_causes.join(' ').toLowerCase() : '';
        if (key === 'sessions') return advNum(ip?.rst_count, 0) > 0 || advNum(ip?.half_open, 0) > 0 || advNum(ip?.session_count, 0) > 1;
        if (key === 'retrans') return advNum(ip?.retransmissions, 0) > 0;
        if (key === 'zero_window') return /window|satur|buffer/.test(causes) || advNum(ip?.score, 0) >= 20;
        if (key === 'handshake') return advNum(ip?.half_open, 0) > 0 || /connexion incomplète|syn/.test(causes);
        if (key === 'bursts') return /burst|traffic_burst|anomalie/.test(causes) || advNum(ip?.packets, 0) >= 200;
        if (key === 'duration') return advNum(ip?.session_count, 0) >= 2 || advNum(ip?.packets, 0) >= 200;
        if (key === 'infra') return String(ip?.vendor || '').toLowerCase() !== 'inconnu' || String(ip?.mac || '').toUpperCase() !== 'N/A';
        if (key === 'culprits') return advNum(ip?.score, 0) >= 10;
        if (key === 'volumetry') return advNum(ip?.packets, 0) >= 120;
        if (key === 'rtt') return advNum(ip?.score, 0) >= 18 || /latence|congestion/.test(causes);
        if (key === 'bottleneck') return advNum(ip?.score, 0) >= 15;
        return true;
    };

    const matchBurst = (b, key) => {
        if (key === 'bursts') return true;
        if (key === 'rtt') return advNum(b?.packets_per_second, 0) >= 300;
        if (key === 'bottleneck') return advNum(b?.packets_per_second, 0) >= 200;
        return false;
    };

    const matchRetrans = (s, key) => {
        if (key === 'retrans' || key === 'bottleneck') return advNum(s?.retransmissions, 0) > 0;
        if (key === 'sessions') return advNum(s?.packets, 0) >= 10;
        return false;
    };

    const issues = issuesAll.filter(i => matchIssue(i, focusKey));
    const recommendations = recsAll.filter(r => matchRecommendation(r, focusKey));
    const vendors = focusKey === 'infra' ? vendorsAll : vendorsAll.slice(0, 5);
    const problematicIps = ipsAll.filter(ip => matchIp(ip, focusKey));
    const bursts = burstsAll.filter(b => matchBurst(b, focusKey));
    const retransSessions = retransAll.filter(s => matchRetrans(s, focusKey));

    return {
        issues: issues.length ? issues : issuesAll,
        recommendations: recommendations.length ? recommendations : recsAll,
        vendors,
        problematicIps: problematicIps.length ? problematicIps : (focusKey === 'retrans' || focusKey === 'sessions' || focusKey === 'infra' || focusKey === 'bursts' || focusKey === 'handshake' ? problematicIps : ipsAll),
        bursts: bursts.length ? bursts : (focusKey === 'bursts' || focusKey === 'rtt' || focusKey === 'bottleneck' ? bursts : burstsAll),
        retransSessions: retransSessions.length ? retransSessions : (focusKey === 'retrans' || focusKey === 'sessions' || focusKey === 'bottleneck' ? retransSessions : retransAll),
        totals: {
            issues: issuesAll.length,
            recs: recsAll.length,
            ips: ipsAll.length,
            bursts: burstsAll.length,
            retrans: retransAll.length
        }
    };
}

function advRenderTcpHealthTables(data, focusKey = 'sessions') {
    const sum = data.summary || {};
    const win = data.window_metrics || {};
    const rtt = data.rtt_metrics || {};
    const adv = data.advanced_metrics || {};
    const sessionDuration = adv.session_duration || {};
    const stability = adv.stability || {};

    const handshakeSuccess = advNum(sum.handshake_success_rate ?? adv.handshake_success_rate, 0);
    const halfOpenPct = advNum(sum.half_open_percentage ?? adv.half_open_percentage, 0);
    const rstPct = advNum(sum.sessions_with_rst_pct ?? adv.sessions_with_rst_pct, 0);
    const retransSessPct = advNum(sum.sessions_with_retransmission_pct ?? adv.sessions_with_retransmission_pct, 0);
    const burstsPerMinute = advNum(sum.bursts_per_minute ?? adv.bursts_per_minute, 0);
    const durationP95 = advNum(sum.session_duration_p95_s ?? sessionDuration.p95_seconds, 0);
    const rttRange = advNum(sum.rtt_range_ms ?? stability.rtt_range_ms ?? rtt.range_ms, 0);
    const windowPressure = advNum(sum.window_pressure_score ?? stability.window_pressure_score ?? win.window_pressure_score, 0);
    const windowPressureLevel = String(sum.window_pressure_level || stability.window_pressure_level || win.window_pressure_level || 'FAIBLE');
    const windowScaleAvg = advNum(win.window_scale_avg, 0);
    const windowScaleCoverage = advNum(win.window_scale_coverage_pct, 0);

    const filtered = advTcpHealthFilter(data, focusKey);
    const focusLabel = focusKey || 'global';

    const issueHtml = filtered.issues.length
        ? filtered.issues.map(i => {
            const sev = String(i.severity || 'LOW').toUpperCase();
            const sevClass = sev === 'HIGH' || sev === 'CRITICAL'
                ? 'adv-health-pill-danger'
                : (sev === 'MEDIUM' ? 'adv-health-pill-warning' : 'adv-health-pill-ok');
            return `<div class="adv-health-issue">
                <div class="adv-health-issue-header">
                    <strong>${advEscape(i.title || 'Signal')}</strong>
                    <span class="adv-health-pill ${sevClass}">${advEscape(sev)}</span>
                </div>
                <p>${advEscape(i.details || '')}</p>
                <small>${advEscape(i.impact || '')}</small>
            </div>`;
        }).join('')
        : advEmptyState('Aucun signal correspondant au filtre');
    const recHtml = filtered.recommendations.length
        ? filtered.recommendations.map((r, idx) => `<div class="adv-rec"><span class="adv-rec-num">${idx + 1}</span><p>${advEscape(r)}</p></div>`).join('')
        : advEmptyState('Aucune recommandation pour ce filtre');
    const vendors = (filtered.vendors || []).slice(0, 5).map(v => `
        <div class="adv-rec">
            <span class="adv-rec-num">🏷️</span>
            <p><strong>${advEscape(v.vendor || 'Inconnu')}</strong> — score agrégé ${advNum(v.score, 0)} sur ${advNum(v.ip_count, 0)} IP(s)</p>
        </div>
    `).join('');
    const culpritRows = (Array.isArray(data.root_cause_matrix) ? data.root_cause_matrix : [])
        .slice(0, 5)
        .map((row, idx) => `
        <div class="adv-rec">
            <span class="adv-rec-num">${idx + 1}</span>
            <p>
                <strong>${advEscape(row.culprit || '-')}</strong>
                (${advEscape(row.vendor || 'Inconnu')}) • confiance ${advNum(row.confidence, 0)}%<br>
                <span style="color:var(--text-muted)">${advEscape(row.top_cause || 'Cause non déterminée')} — ${advEscape(row.evidence || '')}</span>
            </p>
        </div>
    `).join('');
    const vendorsHtml = vendors
        ? `<div class="adv-health-rec-list"><h4 style="margin-bottom:8px;">Constructeurs les plus impactés</h4>${vendors}</div>`
        : '';
    const culpritsHtml = culpritRows
        ? `<div class="adv-health-rec-list"><h4 style="margin-bottom:8px;">Coupables probables (root-cause matrix)</h4>${culpritRows}</div>`
        : '';
    advSetHTML(
        'tcpHealthDiagnosis',
        `${advTcpHealthFilterNote(`Filtre actif (${focusLabel})`, filtered.issues.length, filtered.totals.issues)}
        <div class="adv-health-diagnosis">${issueHtml}<div class="adv-health-rec-list">${recHtml}</div>${culpritsHtml}${vendorsHtml}</div>`
    );

    const ipRows = (filtered.problematicIps || []).map(ip => [
        `<code>${advEscape(ip.ip || '')}</code>`,
        `<code>${advEscape(ip.mac || 'N/A')}</code>`,
        advEscape(ip.vendor || 'Inconnu'),
        advNum(ip.score, 0),
        advNum(ip.session_count, 0),
        advNum(ip.retransmissions, 0),
        advNum(ip.rst_count, 0),
        advNum(ip.packets, 0),
        advEscape((ip.possible_causes || []).join(' | ') || 'N/A')
    ]);
    advSetHTML(
        'tcpHealthProblemIps',
        `${advTcpHealthFilterNote(`Filtre actif (${focusLabel})`, ipRows.length, filtered.totals.ips)}
        ${advTable(
            ['IP', 'MAC', 'Constructeur', 'Score', 'Sessions', 'Retrans.', 'RST', 'Paquets', 'Causes'],
            ipRows,
            'Aucune IP correspondant au filtre'
        )}`
    );

    const burstRows = (filtered.bursts || []).map(b => [
        advEscape(advFormatTimestamp(b.timestamp)),
        advNum(b.packets_per_second, 0),
        advEscape(String(b.severity || 'LOW')),
        advEscape(b.description || '')
    ]);
    advSetHTML(
        'tcpHealthBursts',
        `${advTcpHealthFilterNote(`Filtre actif (${focusLabel})`, burstRows.length, filtered.totals.bursts)}
        ${advTable(
            ['Timestamp', 'Paquets/s', 'Sévérité', 'Description'],
            burstRows,
            'Aucun burst correspondant au filtre'
        )}`
    );

    const retrRows = (filtered.retransSessions || []).map(s => [
        `<code>${advEscape(s.session || '')}</code>`,
        advNum(s.retransmissions, 0),
        advNum(s.packets, 0)
    ]);
    advSetHTML(
        'tcpHealthRetransSessions',
        `${advTcpHealthFilterNote(`Filtre actif (${focusLabel})`, retrRows.length, filtered.totals.retrans)}
        ${advTable(
            ['Session', 'Retrans.', 'Paquets'],
            retrRows,
            'Aucune session correspondant au filtre'
        )}`
    );

    advSetHTML('tcpHealthWindowStats', advTable(
        ['Métrique', 'Valeur'],
        [
            ['Window min', advNum(win.min_window, 0)],
            ['Window max', advNum(win.max_window, 0)],
            ['Window moyenne', advNum(win.avg_window, 0)],
            ['Window effective moyenne', advNum(win.effective_avg_window, 0)],
            ['Window effective min', advNum(win.effective_min_window, 0)],
            ['Window effective max', advNum(win.effective_max_window, 0)],
            ['Window scale min', advNum(win.window_scale_min, 0)],
            ['Window scale max', advNum(win.window_scale_max, 0)],
            ['Window scale moyen', windowScaleAvg.toFixed(3)],
            ['Window scale p95', advNum(win.window_scale_p95, 0).toFixed(3)],
            ['Sessions avec scale', advNum(win.window_scale_observed_sessions, 0)],
            ['Directions avec scale', advNum(win.window_scale_observed_directions, 0)],
            ['Window scale coverage', `${windowScaleCoverage.toFixed(2)}%`],
            ['Window range', advNum(win.window_range, advNum(sum.window_range, 0))],
            ['Pression window', `${windowPressure}/100 (${advEscape(windowPressureLevel)})`],
            ['Zero window count', advNum(win.zero_window_count, 0)],
            ['Zero window %', `${advNum(win.zero_window_percentage, 0).toFixed(2)}%`],
            ['RTT min', `${advNum(rtt.min_rtt_ms, 0).toFixed(2)} ms`],
            ['RTT max', `${advNum(rtt.max_rtt_ms, 0).toFixed(2)} ms`],
            ['RTT moyen', `${advNum(rtt.avg_rtt_ms, 0).toFixed(2)} ms`],
            ['RTT spread', `${rttRange.toFixed(2)} ms`],
            ['Échantillons RTT', advNum(rtt.samples_count, 0)],
            ['Handshake success', `${handshakeSuccess.toFixed(2)}%`],
            ['Half-open', `${advNum(sum.half_open_connections, 0)} (${halfOpenPct.toFixed(2)}%)`],
            ['Sessions avec retrans.', `${advNum(sum.sessions_with_retransmissions, 0)} (${retransSessPct.toFixed(2)}%)`],
            ['Sessions avec RST', `${advNum(sum.sessions_with_rst, 0)} (${rstPct.toFixed(2)}%)`],
            ['Burst density', `${burstsPerMinute.toFixed(2)} / min`],
            ['Durée session p95', `${durationP95.toFixed(3)} s`],
            ['Durée session max', `${advNum(sum.session_duration_max_s ?? sessionDuration.max_seconds, 0).toFixed(3)} s`]
        ],
        'Aucune statistique TCP disponible'
    ));
}

async function loadTcpHealth(taskId, forceRefresh = false) {
    advShow('tcp-health-loading');
    try {
        let data = forceRefresh ? null : _advTcpHealthCache.get(taskId);
        if (!data) {
            data = await advFetch(`/api/${taskId}/tcp-health`);
            _advTcpHealthCache.set(taskId, data);
        }
        const sum = data.summary || {};
        const win = data.window_metrics || {};
        const rtt = data.rtt_metrics || {};
        const adv = data.advanced_metrics || {};
        const sessionDuration = adv.session_duration || {};
        const stability = adv.stability || {};

        const bottleneckScore = advNum(sum.bottleneck_score, 0);
        const bottleneckClass = bottleneckScore >= 70
            ? 'adv-metric-danger'
            : (bottleneckScore >= 45 ? 'adv-metric-warning' : '');
        const handshakeSuccess = advNum(sum.handshake_success_rate ?? adv.handshake_success_rate, 0);
        const halfOpenPct = advNum(sum.half_open_percentage ?? adv.half_open_percentage, 0);
        const rstPct = advNum(sum.sessions_with_rst_pct ?? adv.sessions_with_rst_pct, 0);
        const retransSessPct = advNum(sum.sessions_with_retransmission_pct ?? adv.sessions_with_retransmission_pct, 0);
        const burstsPerMinute = advNum(sum.bursts_per_minute ?? adv.bursts_per_minute, 0);
        const durationP95 = advNum(sum.session_duration_p95_s ?? sessionDuration.p95_seconds, 0);
        const durationAvg = advNum(sum.session_duration_avg_s ?? sessionDuration.avg_seconds, 0);
        const rttRange = advNum(sum.rtt_range_ms ?? stability.rtt_range_ms ?? rtt.range_ms, 0);
        const windowPressure = advNum(sum.window_pressure_score ?? stability.window_pressure_score ?? win.window_pressure_score, 0);
        const windowPressureLevel = String(sum.window_pressure_level || stability.window_pressure_level || win.window_pressure_level || 'FAIBLE');
        const jitter = advNum(sum.rtt_jitter_ms ?? rtt.jitter_ms ?? stability.rtt_jitter_ms, 0);
        const p95 = advNum(sum.rtt_p95_ms ?? rtt.p95_rtt_ms, 0);
        const avgThroughput = advNum(sum.avg_throughput_mbps ?? adv.avg_throughput_mbps, 0);
        const peakPps = advNum(sum.peak_pps ?? adv.peak_pps, 0);
        const healthScore = advNum(sum.health_score ?? adv.health_score, 0);
        const culpritCount = Array.isArray(data.root_cause_matrix) ? data.root_cause_matrix.length : 0;
        const windowScaleAvg = advNum(win.window_scale_avg, 0);
        const windowScaleCoverage = advNum(win.window_scale_coverage_pct, 0);

        advSetHTML('tcpHealthSummaryCards', `<div class="adv-qos-strip">
            ${metricCard('Sessions TCP', advNum(sum.total_sessions, 0), '🔌', '', 'data-tcp-focus="sessions"')}
            ${metricCard('RTT Moyen', `${advNum(sum.avg_rtt_ms, 0).toFixed(1)} ms`, '⏱️', advNum(sum.avg_rtt_ms, 0) >= 80 ? 'adv-metric-warning' : '', 'data-tcp-focus="rtt"')}
            ${metricCard('RTT p95', `${p95.toFixed(1)} ms`, '📈', p95 >= 120 ? 'adv-metric-warning' : '', 'data-tcp-focus="rtt"')}
            ${metricCard('Retransmissions', advNum(sum.total_retransmissions, 0), '🔄', advNum(sum.retransmission_rate, 0) >= 2 ? 'adv-metric-warning' : '', 'data-tcp-focus="retrans"')}
            ${metricCard('Zero Window', `${advNum(sum.zero_window_count, 0)} (${advNum(sum.zero_window_percentage, 0).toFixed(2)}%)`, '🪟', advNum(sum.zero_window_count, 0) > 0 ? 'adv-metric-warning' : '', 'data-tcp-focus="zero_window"')}
            ${metricCard('Sessions Retrans.', `${advNum(sum.sessions_with_retransmissions, 0)} (${retransSessPct.toFixed(1)}%)`, '📉', retransSessPct >= 15 ? 'adv-metric-warning' : '', 'data-tcp-focus="retrans"')}
            ${metricCard('Sessions avec RST', `${advNum(sum.sessions_with_rst, 0)} (${rstPct.toFixed(1)}%)`, '⛔', rstPct >= 10 ? 'adv-metric-danger' : (rstPct >= 4 ? 'adv-metric-warning' : ''), 'data-tcp-focus="sessions"')}
            ${metricCard('Half-open', `${advNum(sum.half_open_connections, 0)} (${halfOpenPct.toFixed(1)}%)`, '🧷', halfOpenPct >= 5 ? 'adv-metric-danger' : (halfOpenPct >= 2 ? 'adv-metric-warning' : ''), 'data-tcp-focus="handshake"')}
            ${metricCard('Handshake OK', `${handshakeSuccess.toFixed(1)}%`, '🤝', handshakeSuccess > 0 && handshakeSuccess < 95 ? 'adv-metric-warning' : '', 'data-tcp-focus="handshake"')}
            ${metricCard('Jitter RTT', `${jitter.toFixed(2)} ms`, '🌡️', jitter >= 18 ? 'adv-metric-warning' : '', 'data-tcp-focus="rtt"')}
            ${metricCard('Bursts', advNum(sum.bursts_count, 0), '⚡', advNum(sum.bursts_count, 0) > 0 ? 'adv-metric-warning' : '', 'data-tcp-focus="bursts"')}
            ${metricCard('Bursts/min', burstsPerMinute.toFixed(2), '📊', burstsPerMinute >= 3 ? 'adv-metric-warning' : '', 'data-tcp-focus="bursts"')}
            ${metricCard('Débit moyen', `${avgThroughput.toFixed(3)} Mbps`, '📦', avgThroughput >= 40 ? 'adv-metric-warning' : '', 'data-tcp-focus="volumetry"')}
            ${metricCard('PPS pic', `${peakPps.toFixed(0)}`, '🚀', peakPps >= 1200 ? 'adv-metric-warning' : '', 'data-tcp-focus="volumetry"')}
            ${metricCard('Durée session p95', `${durationP95.toFixed(2)} s`, '🕰️', durationP95 >= 30 ? 'adv-metric-warning' : '', 'data-tcp-focus="duration"')}
            ${metricCard('Durée session moy.', `${durationAvg.toFixed(2)} s`, '⌛', '', 'data-tcp-focus="duration"')}
            ${metricCard('Window Scale avg', `${windowScaleAvg.toFixed(2)}`, '🧮', windowScaleCoverage < 25 ? 'adv-metric-warning' : '', 'data-tcp-focus="zero_window"')}
            ${metricCard('Scale coverage', `${windowScaleCoverage.toFixed(1)}%`, '📐', windowScaleCoverage < 25 ? 'adv-metric-warning' : '', 'data-tcp-focus="zero_window"')}
            ${metricCard(`Pression Window ${advHealthPill(windowPressureLevel)}`, `${windowPressure}/100`, '🪟', windowPressure >= 70 ? 'adv-metric-danger' : (windowPressure >= 45 ? 'adv-metric-warning' : ''), 'data-tcp-focus="zero_window"')}
            ${metricCard('RTT Spread', `${rttRange.toFixed(1)} ms`, '🌡️', rttRange >= 100 ? 'adv-metric-warning' : '', 'data-tcp-focus="rtt"')}
            ${metricCard(`Risque Goulot ${advHealthPill(sum.bottleneck_level)}`, `${bottleneckScore}/100`, '🧠', bottleneckClass, 'data-tcp-focus="bottleneck"')}
            ${metricCard('Health Score', `${healthScore.toFixed(1)}/100`, '🧭', healthScore < 45 ? 'adv-metric-danger' : (healthScore < 70 ? 'adv-metric-warning' : ''), 'data-tcp-focus="culprits"')}
            ${metricCard('Coupables probables', culpritCount, '🕵️', culpritCount > 0 ? 'adv-metric-warning' : '', 'data-tcp-focus="culprits"')}
            ${metricCard('Équipements touchés', advNum(sum.problematic_macs_count, 0), '🧩', advNum(sum.problematic_macs_count, 0) > 0 ? 'adv-metric-warning' : '', 'data-tcp-focus="infra"')}
            ${metricCard('Broadcast', `${advNum(sum.broadcast_percentage, 0).toFixed(2)}%`, '📣', advNum(sum.broadcast_percentage, 0) >= 2 ? 'adv-metric-warning' : '', 'data-tcp-focus="infra"')}
        </div>`);
        const focusCatalog = advBuildTcpHealthFocusCatalog(data);
        advBindTcpHealthMetricCards(focusCatalog, (focusKey) => {
            _advTcpHealthFocusByTask.set(taskId, focusKey || 'sessions');
            advRenderTcpHealthTables(data, focusKey);
        });

        const aiBtn = document.getElementById('tcpHealthAiAnalyzeBtn');
        if (aiBtn) aiBtn.onclick = () => advAnalyzeTcpHealthWithAI(taskId);
        const activeFocus = _advTcpHealthFocusByTask.get(taskId) || 'sessions';
        advSetTcpHealthAiStatus(`Prêt. Focus courant: ${activeFocus}.`, 'info');
        advSetHTML('tcpHealthAiResult', `<div class="adv-empty"><span>🤖</span><p>Lancez l'analyse IA TCP Health pour obtenir un diagnostic root-cause détaillé.</p></div>`);

    } catch (e) {
        advMarkLoadFailed('tcp-health', taskId);
        advSetHTML('tcp-health-content', `<div class="adv-error">❌ Erreur: ${e.message}</div>`);
    } finally {
        advHide('tcp-health-loading');
    }
}

// ─────────────────────────────────────────────────────────
// 7. IR Playbook
// ─────────────────────────────────────────────────────────

async function generatePlaybook(taskId) {
    if (!taskId) return;
    const btn = document.getElementById('generatePlaybookBtn');
    const loadingEl = document.getElementById('playbook-loading');
    if (btn) btn.disabled = true;
    if (loadingEl) loadingEl.style.display = '';

    try {
        const resp = await fetch(`/api/${taskId}/generate-playbook`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        const data = await resp.json();

        const playbooks = data.playbooks || [];
        if (!playbooks.length) {
            advSetHTML('playbook-content', advEmptyState('Aucun playbook généré. Lancez une analyse d\'abord.'));
            return;
        }

        const priorityColors = { CRITICAL: '#ff4444', HIGH: '#ff8800', MEDIUM: '#ffbb33', LOW: '#27ae60' };

        const html = playbooks.map((pb, idx) => {
            const pColor = priorityColors[pb.priority] || '#888';
            const phases = pb.phases || [];
            const phasesHTML = phases.map(phase => {
                const tasks = phase.tasks || [];
                return `<div class="pb-phase">
                    <h4 class="pb-phase-title"><span class="pb-phase-icon">${phase.icon || '📌'}</span> ${phase.name}</h4>
                    <div class="pb-tasks">
                        ${tasks.map((t, ti) => `
                            <label class="pb-task" id="pbtask-${idx}-${phase.name}-${ti}">
                                <input type="checkbox" class="pb-checkbox" onchange="advUpdateProgress(this)" data-playbook="${idx}">
                                <span class="pb-task-text">${t}</span>
                            </label>
                        `).join('')}
                    </div>
                </div>`;
            }).join('');

            return `<div class="pb-card" id="pb-card-${idx}">
                <div class="pb-header" style="border-left: 4px solid ${pColor}">
                    <div class="pb-type-badge" style="background:${pColor}">${pb.incident_type || ''}</div>
                    <h3 class="pb-title">${pb.title || ''}</h3>
                    <div class="pb-meta">
                        <span>⏱️ ${pb.estimated_time || ''}</span>
                        <span>👥 ${(pb.required_roles || []).join(', ')}</span>
                        <div class="pb-progress-wrap">
                            <div class="pb-progress-bar"><div class="pb-progress-fill" id="pb-prog-${idx}" style="width:0%"></div></div>
                            <span class="pb-progress-text" id="pb-prog-text-${idx}">0%</span>
                        </div>
                    </div>
                </div>
                ${pb.context ? `<div class="pb-context"><strong>🎯 Contexte:</strong> ${pb.context}</div>` : ''}
                ${pb.iocs && pb.iocs.length ? `<div class="pb-iocs"><strong>🔴 IoCs:</strong> ${pb.iocs.slice(0, 5).map(i => `<code>${i}</code>`).join(' ')}</div>` : ''}
                <div class="pb-phases">${phasesHTML}</div>
                <div class="pb-footer">
                    <span>MITRE: ${(pb.mitre_techniques || []).slice(0, 5).map(m => `<code>${m}</code>`).join(' ')}</span>
                </div>
            </div>`;
        }).join('');

        advSetHTML('playbook-content', html);

        // Restore checkbox states from localStorage
        advRestorePlaybookProgress();

    } catch (e) {
        advSetHTML('playbook-content', `<div class="adv-error">❌ Erreur: ${e.message}</div>`);
    } finally {
        if (btn) btn.disabled = false;
        if (loadingEl) loadingEl.style.display = 'none';
    }
}

function advUpdateProgress(checkbox) {
    const card = checkbox.closest('.pb-card');
    if (!card) return;
    const idx = card.id.replace('pb-card-', '');
    const all = card.querySelectorAll('.pb-checkbox');
    const checked = card.querySelectorAll('.pb-checkbox:checked');
    const pct = all.length ? Math.round((checked.length / all.length) * 100) : 0;

    const fill = document.getElementById(`pb-prog-${idx}`);
    const text = document.getElementById(`pb-prog-text-${idx}`);
    if (fill) fill.style.width = pct + '%';
    if (text) text.textContent = pct + '%';

    // Persist to localStorage
    const key = `pbcheck_${idx}`;
    const states = Array.from(all).map(c => c.checked);
    localStorage.setItem(key, JSON.stringify(states));
}

function advRestorePlaybookProgress() {
    document.querySelectorAll('.pb-card').forEach(card => {
        const idx = card.id.replace('pb-card-', '');
        const key = `pbcheck_${idx}`;
        const saved = localStorage.getItem(key);
        if (!saved) return;
        const states = JSON.parse(saved);
        const checkboxes = card.querySelectorAll('.pb-checkbox');
        states.forEach((state, i) => {
            if (checkboxes[i]) checkboxes[i].checked = state;
        });
        // Trigger progress update
        const fakeEl = { closest: () => card };
        advUpdateProgress(fakeEl);
    });
}

// ─────────────────────────────────────────────────────────
// DFIR Export handlers
// ─────────────────────────────────────────────────────────

async function exportDfirPdf(taskId) {
    if (!taskId) { alert('Aucune analyse chargée'); return; }
    const btn = document.getElementById('exportDfirPdf');
    if (btn) { btn.disabled = true; btn.textContent = '⏳ Génération...'; }
    try {
        const resp = await fetch(`/api/${taskId}/export/dfir-report`);
        if (!resp.ok) throw new Error(await resp.text());
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `dfir-report-${taskId.slice(0, 8)}.pdf`;
        a.click();
        URL.revokeObjectURL(url);
    } catch (e) {
        alert(`Erreur export PDF: ${e.message}`);
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = '🔒 DFIR Report PDF'; }
    }
}

async function exportDfirJson(taskId) {
    if (!taskId) { alert('Aucune analyse chargée'); return; }
    try {
        const data = await advFetch(`/api/${taskId}/export/dfir-report-json`);
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `dfir-report-${taskId.slice(0, 8)}.json`;
        a.click();
        URL.revokeObjectURL(url);
    } catch (e) {
        alert(`Erreur export JSON: ${e.message}`);
    }
}

// ─────────────────────────────────────────────────────────
// Tab lazy-load dispatcher (called by main app.js tab switcher)
// ─────────────────────────────────────────────────────────

const _advLoaded = new Set();

function advOnTabActivated(tabName, taskId) {
    if (!taskId) return;
    const key = `${tabName}:${taskId}`;
    if (_advLoaded.has(key)) return;  // already loaded
    _advLoaded.add(key);

    switch (tabName) {
        case 'tls-audit': loadTlsAudit(taskId); break;
        case 'threat-intel': loadThreatIntel(taskId); break;
        case 'flow-behavior': loadFlowBehavior(taskId); break;
        case 'lateral-movement': loadLateralMovement(taskId); break;
        case 'qos': loadQos(taskId); break;
        case 'tcp-health': loadTcpHealth(taskId); break;
        // playbook is on-demand (button click), no auto-load
    }
}

function advApplyGlobalDrilldown(filter = {}) {
    _advGlobalFilter.query = String(filter.query || '').trim();
    _advGlobalFilter.protocol = String(filter.protocol || '').trim().toUpperCase();
    _advGlobalFilter.riskMin = Math.max(0, advNum(filter.riskMin, 0));

    const taskId = String(window.analyzer?.currentTaskId || '').trim();
    if (!taskId) return;

    if (_advQosCache.has(taskId)) loadQos(taskId);
    if (_advTlsAuditCache.has(taskId)) loadTlsAudit(taskId);
    if (_advThreatIntelCache.has(taskId)) loadThreatIntel(taskId);
}

window.advApplyGlobalDrilldown = advApplyGlobalDrilldown;
