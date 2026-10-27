# Premium UI Redesign — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Refonte complète de l'UI vers un style glassmorphism premium avec Apache ECharts, virtual scroll, et filtres avancés.

**Architecture:** Remplacement de Chart.js par Apache ECharts (CDN), refonte CSS glassmorphism (backdrop-filter, gradient borders, animations), virtual scroll custom pour le tableau des paquets, filtres multi-colonnes avec regex.

**Tech Stack:** Apache ECharts 5.x (CDN), Vanilla JS, CSS custom properties, backdrop-filter

**Fichiers impactés (uniquement frontend) :**
- `templates/index.html`
- `static/css/style.css`
- `static/js/app.js`

---

## Task 1 : Swap CDN — Chart.js → ECharts + nouveaux conteneurs HTML

**Files:**
- Modify: `templates/index.html`

**Step 1: Remplacer les scripts CDN**

Dans `<head>`, remplacer:
```html
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
```
Par:
```html
<script src="https://cdn.jsdelivr.net/npm/echarts@5/dist/echarts.min.js"></script>
```

**Step 2: Ajouter les conteneurs pour les nouveaux charts**

Après le bloc des charts existants dans `tab-overview`, ajouter:
```html
<!-- Heatmap temporelle -->
<div class="card chart-card">
    <div class="chart-header">
        <h3>Heatmap Temporelle</h3>
        <div class="chart-actions">
            <button class="chart-btn" onclick="analyzer.resetZoom('heatmap')" title="Reset zoom">⟲</button>
            <button class="chart-btn" onclick="analyzer.fullscreenChart('heatmapChart')" title="Plein écran">⛶</button>
        </div>
    </div>
    <div id="heatmapChart" style="height: 200px;"></div>
</div>

<!-- Treemap protocoles -->
<div class="card chart-card">
    <div class="chart-header">
        <h3>Treemap Protocoles</h3>
        <div class="chart-actions">
            <button class="chart-btn" onclick="analyzer.fullscreenChart('treemapChart')" title="Plein écran">⛶</button>
        </div>
    </div>
    <div id="treemapChart" style="height: 300px;"></div>
</div>

<!-- Sankey network flow -->
<div class="card chart-card chart-card-wide">
    <div class="chart-header">
        <h3>Network Flow (Sankey)</h3>
        <div class="chart-actions">
            <button class="chart-btn" onclick="analyzer.fullscreenChart('sankeyChart')" title="Plein écran">⛶</button>
        </div>
    </div>
    <div id="sankeyChart" style="height: 350px;"></div>
</div>
```

Faire pareil pour tous les `<canvas>` existants : remplacer `<canvas id="protocolChart">` etc. par `<div id="protocolChart" style="height: 300px;">`.

**Step 3: Vérifier**

Ouvrir le navigateur sur `http://localhost:8000`. La console ne doit plus montrer d'erreurs liées à Chart.js. ECharts doit être disponible en tapant `echarts` dans la console.

**Step 4: Commit**
```bash
git add templates/index.html
git commit -m "feat: swap Chart.js for ECharts CDN, add new chart containers"
```

---

## Task 2 : CSS Glassmorphism — base (cards, header, variables)

**Files:**
- Modify: `static/css/style.css`

**Step 1: Mettre à jour les variables CSS dark theme**

Dans `[data-theme="dark"]`, modifier/ajouter:
```css
[data-theme="dark"] {
    /* Glassmorphism surfaces */
    --bg-card: rgba(15, 23, 42, 0.5);
    --bg-glass: rgba(30, 41, 59, 0.35);
    --bg-glass-hover: rgba(30, 41, 59, 0.55);
    --border-glass: rgba(255, 255, 255, 0.07);
    --border-glass-hover: rgba(255, 255, 255, 0.14);
    --blur-md: blur(20px);
    --blur-lg: blur(32px);
    --glow-primary: 0 0 20px rgba(6, 182, 212, 0.15);
    --glow-accent: 0 0 20px rgba(139, 92, 246, 0.15);
    --glow-danger: 0 0 20px rgba(239, 68, 68, 0.25);
}
```

Dans `[data-theme="light"]`, ajouter:
```css
[data-theme="light"] {
    --bg-card: rgba(255, 255, 255, 0.65);
    --bg-glass: rgba(248, 250, 252, 0.7);
    --bg-glass-hover: rgba(248, 250, 252, 0.9);
    --border-glass: rgba(0, 0, 0, 0.08);
    --border-glass-hover: rgba(0, 0, 0, 0.15);
    --blur-md: blur(20px);
    --blur-lg: blur(32px);
    --glow-primary: 0 0 20px rgba(6, 182, 212, 0.1);
    --glow-accent: 0 0 20px rgba(139, 92, 246, 0.1);
    --glow-danger: 0 0 20px rgba(239, 68, 68, 0.15);
}
```

**Step 2: Refonte des cards**

Remplacer le bloc `.card` existant par:
```css
.card {
    background: var(--bg-card);
    backdrop-filter: var(--blur-md);
    -webkit-backdrop-filter: var(--blur-md);
    border: 1px solid var(--border-glass);
    border-radius: var(--radius-lg);
    padding: var(--spacing-lg);
    position: relative;
    overflow: hidden;
    transition: border-color var(--transition-normal), box-shadow var(--transition-normal), transform var(--transition-fast);
}

.card::before {
    content: '';
    position: absolute;
    inset: 0;
    border-radius: inherit;
    padding: 1px;
    background: linear-gradient(135deg, rgba(6, 182, 212, 0.2), rgba(139, 92, 246, 0.1), transparent 60%);
    -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
    -webkit-mask-composite: xor;
    mask-composite: exclude;
    pointer-events: none;
    opacity: 0;
    transition: opacity var(--transition-normal);
}

.card:hover {
    border-color: var(--border-glass-hover);
    box-shadow: var(--glow-primary);
    transform: translateY(-1px);
}

.card:hover::before {
    opacity: 1;
}
```

**Step 3: Refonte du header en glassmorphism**

Remplacer le bloc `.header` par:
```css
.header {
    position: sticky;
    top: 0;
    z-index: 100;
    background: rgba(15, 23, 42, 0.6);
    backdrop-filter: var(--blur-lg);
    -webkit-backdrop-filter: var(--blur-lg);
    border-bottom: 1px solid var(--border-glass);
    padding: var(--spacing-md) var(--spacing-xl);
}

[data-theme="light"] .header {
    background: rgba(248, 250, 252, 0.75);
}
```

**Step 4: Vérifier visuellement**

Recharger le navigateur. Les cards doivent avoir un effet de verre. Passer en mode light pour vérifier la cohérence.

**Step 5: Commit**
```bash
git add static/css/style.css
git commit -m "feat: glassmorphism base — cards and header backdrop-filter"
```

---

## Task 3 : CSS — Animations, skeletons, upload zone, risk card pulse

**Files:**
- Modify: `static/css/style.css`

**Step 1: Animations d'entrée des cards**

Ajouter:
```css
@keyframes fadeInUp {
    from {
        opacity: 0;
        transform: translateY(16px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.summary-cards .card {
    animation: fadeInUp 0.4s ease both;
}
.summary-cards .card:nth-child(1) { animation-delay: 0ms; }
.summary-cards .card:nth-child(2) { animation-delay: 60ms; }
.summary-cards .card:nth-child(3) { animation-delay: 120ms; }
.summary-cards .card:nth-child(4) { animation-delay: 180ms; }

.chart-card {
    animation: fadeInUp 0.5s ease both;
}
```

**Step 2: Loading skeletons**

Remplacer / compléter le style de progression avec des skeletons:
```css
@keyframes shimmer {
    0% { background-position: -400px 0; }
    100% { background-position: 400px 0; }
}

.skeleton {
    background: linear-gradient(
        90deg,
        var(--bg-secondary) 25%,
        var(--bg-tertiary) 50%,
        var(--bg-secondary) 75%
    );
    background-size: 800px 100%;
    animation: shimmer 1.5s infinite linear;
    border-radius: var(--radius-sm);
}

.skeleton-card {
    height: 80px;
    border-radius: var(--radius-lg);
}

.skeleton-chart {
    height: 250px;
    border-radius: var(--radius-md);
}
```

Ajouter dans `templates/index.html` dans `#progressContainer`:
```html
<div class="skeleton-grid" id="skeletonGrid" style="display: none;">
    <div class="skeleton skeleton-card"></div>
    <div class="skeleton skeleton-card"></div>
    <div class="skeleton skeleton-card"></div>
    <div class="skeleton skeleton-card"></div>
    <div class="skeleton skeleton-chart" style="grid-column: span 2;"></div>
    <div class="skeleton skeleton-chart"></div>
</div>
```

**Step 3: Risk card pulse**

```css
@keyframes pulseRisk {
    0%, 100% { box-shadow: 0 0 10px rgba(239, 68, 68, 0.2); }
    50% { box-shadow: 0 0 30px rgba(239, 68, 68, 0.5), 0 0 60px rgba(239, 68, 68, 0.15); }
}

.risk-card[data-risk="CRITICAL"],
.risk-card[data-risk="HIGH"] {
    animation: pulseRisk 2s ease-in-out infinite;
    border-color: rgba(239, 68, 68, 0.4) !important;
}
```

**Step 4: Upload zone améliorée**

```css
.upload-area {
    /* existant + ajouter: */
    background: var(--bg-glass);
    backdrop-filter: var(--blur-md);
    border: 2px dashed var(--border-glass-hover);
    transition: all var(--transition-normal);
}

.upload-area.dragover {
    border-color: var(--primary);
    background: rgba(6, 182, 212, 0.08);
    box-shadow: 0 0 40px rgba(6, 182, 212, 0.2), inset 0 0 40px rgba(6, 182, 212, 0.05);
    transform: scale(1.01);
}

.upload-area.upload-success {
    border-color: var(--success);
    box-shadow: 0 0 40px rgba(16, 185, 129, 0.3);
}
```

**Step 5: Vérifier**

Charger la page, vérifier que les animations fadeInUp sont visibles sur les cards après une analyse. Tester drag-over sur la zone upload.

**Step 6: Commit**
```bash
git add static/css/style.css templates/index.html
git commit -m "feat: animations fadeInUp, loading skeletons, risk card pulse, upload zone glow"
```

---

## Task 4 : CSS — Tableau paquets premium (badges, expand, colonnes)

**Files:**
- Modify: `static/css/style.css`

**Step 1: Badges protocoles colorés**

```css
.proto-badge {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;
    border-radius: var(--radius-full);
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: 0.05em;
}

.proto-badge.tcp    { background: rgba(6, 182, 212, 0.15); color: #06b6d4; border: 1px solid rgba(6, 182, 212, 0.3); }
.proto-badge.udp    { background: rgba(139, 92, 246, 0.15); color: #8b5cf6; border: 1px solid rgba(139, 92, 246, 0.3); }
.proto-badge.dns    { background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); }
.proto-badge.http   { background: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.3); }
.proto-badge.https  { background: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.3); }
.proto-badge.icmp   { background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); }
.proto-badge.arp    { background: rgba(236, 72, 153, 0.15); color: #ec4899; border: 1px solid rgba(236, 72, 153, 0.3); }
.proto-badge.other  { background: rgba(100, 116, 139, 0.15); color: #64748b; border: 1px solid rgba(100, 116, 139, 0.3); }
```

**Step 2: Badges flags TCP**

```css
.flag-badge {
    display: inline-flex;
    align-items: center;
    padding: 1px 5px;
    border-radius: 3px;
    font-size: 0.65rem;
    font-weight: 700;
    font-family: monospace;
    margin: 0 1px;
}

.flag-badge.syn  { background: rgba(6, 182, 212, 0.2); color: #06b6d4; }
.flag-badge.ack  { background: rgba(16, 185, 129, 0.2); color: #10b981; }
.flag-badge.fin  { background: rgba(100, 116, 139, 0.2); color: #64748b; }
.flag-badge.rst  { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
.flag-badge.psh  { background: rgba(245, 158, 11, 0.2); color: #f59e0b; }
.flag-badge.urg  { background: rgba(236, 72, 153, 0.2); color: #ec4899; }
```

**Step 3: Lignes expandables**

```css
.packet-row {
    cursor: pointer;
    transition: background var(--transition-fast);
}

.packet-row:hover {
    background: var(--bg-glass-hover);
}

.packet-row.expanded {
    background: rgba(6, 182, 212, 0.05);
    border-bottom: none;
}

.packet-detail-row {
    display: none;
    background: rgba(15, 23, 42, 0.6);
    border-bottom: 1px solid var(--border-glass);
}

.packet-detail-row.visible {
    display: table-row;
}

.packet-detail-content {
    padding: var(--spacing-md) var(--spacing-lg);
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: 0.8rem;
    color: var(--text-secondary);
}
```

**Step 4: Barre de filtres**

```css
.packet-filter-bar {
    display: flex;
    gap: var(--spacing-sm);
    padding: var(--spacing-md);
    background: var(--bg-glass);
    backdrop-filter: var(--blur-md);
    border-radius: var(--radius-md);
    border: 1px solid var(--border-glass);
    margin-bottom: var(--spacing-md);
    flex-wrap: wrap;
    align-items: center;
}

.filter-input-wrapper {
    position: relative;
    flex: 1;
    min-width: 200px;
}

.filter-input-wrapper input {
    width: 100%;
    padding: 8px 12px 8px 36px;
    background: var(--bg-secondary);
    border: 1px solid var(--border-glass);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font-size: 0.875rem;
    transition: border-color var(--transition-fast), box-shadow var(--transition-fast);
}

.filter-input-wrapper input:focus {
    outline: none;
    border-color: var(--primary);
    box-shadow: 0 0 0 3px rgba(6, 182, 212, 0.1);
}

.filter-input-wrapper .filter-icon {
    position: absolute;
    left: 10px;
    top: 50%;
    transform: translateY(-50%);
    color: var(--text-muted);
    pointer-events: none;
}

.filter-tag {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 4px 10px;
    background: rgba(6, 182, 212, 0.1);
    border: 1px solid rgba(6, 182, 212, 0.3);
    border-radius: var(--radius-full);
    font-size: 0.8rem;
    color: var(--primary);
    cursor: pointer;
}

.filter-tag .remove {
    cursor: pointer;
    opacity: 0.7;
}
.filter-tag .remove:hover { opacity: 1; }
```

**Step 5: Colonnes redimensionnables**

```css
.resizable-table th {
    position: relative;
    user-select: none;
}

.col-resizer {
    position: absolute;
    right: 0;
    top: 0;
    bottom: 0;
    width: 4px;
    cursor: col-resize;
    background: transparent;
    transition: background var(--transition-fast);
}

.col-resizer:hover,
.col-resizer.resizing {
    background: var(--primary);
}
```

**Step 6: Commit**
```bash
git add static/css/style.css
git commit -m "feat: premium packet table CSS — proto/flag badges, expand rows, filter bar, resizable columns"
```

---

## Task 5 : JS — Bootstrap ECharts, theme config, updateChartsTheme

**Files:**
- Modify: `static/js/app.js`

**Step 1: Remplacer `setupChartDefaults()`**

Trouver `setupChartDefaults()` (~ligne 324) et remplacer entièrement par:
```javascript
setupChartDefaults() {
    // ECharts doesn't need global defaults — theme applied per chart
    this.echartsInstances = {};
}
```

**Step 2: Remplacer `updateChartsTheme()`**

Trouver `updateChartsTheme()` (~ligne 333) et remplacer par:
```javascript
updateChartsTheme() {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    Object.values(this.echartsInstances).forEach(chart => {
        if (chart && !chart.isDisposed()) {
            const option = chart.getOption();
            if (option) chart.setOption(option);
        }
    });
}
```

**Step 3: Ajouter méthode helper `getEChartsTheme()`**

Juste avant `createProtocolChart`, ajouter:
```javascript
getEChartsTheme() {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    return {
        isDark,
        textColor: isDark ? '#94a3b8' : '#64748b',
        textPrimary: isDark ? '#f8fafc' : '#0f172a',
        grid: isDark ? 'rgba(148,163,184,0.08)' : 'rgba(100,116,139,0.1)',
        tooltip: {
            backgroundColor: isDark ? 'rgba(15,23,42,0.9)' : 'rgba(255,255,255,0.95)',
            borderColor: isDark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.08)',
            textStyle: { color: isDark ? '#f8fafc' : '#0f172a', fontFamily: 'Inter, sans-serif' }
        },
        colors: ['#06b6d4','#8b5cf6','#10b981','#f59e0b','#ef4444','#ec4899','#0ea5e9','#64748b']
    };
}

destroyChart(key) {
    if (this.echartsInstances[key]) {
        this.echartsInstances[key].dispose();
        delete this.echartsInstances[key];
    }
}

initChart(domId) {
    const dom = document.getElementById(domId);
    if (!dom) return null;
    const existing = echarts.getInstanceByDom(dom);
    if (existing) existing.dispose();
    return echarts.init(dom, null, { renderer: 'canvas' });
}

resetZoom(chartKey) {
    const chart = this.echartsInstances[chartKey];
    if (chart) chart.dispatchAction({ type: 'dataZoom', start: 0, end: 100 });
}

fullscreenChart(domId) {
    const dom = document.getElementById(domId);
    if (!dom) return;
    if (!document.fullscreenElement) {
        dom.requestFullscreen();
        const chart = echarts.getInstanceByDom(dom);
        if (chart) setTimeout(() => chart.resize(), 300);
    } else {
        document.exitFullscreen();
    }
}
```

**Step 4: Mettre à jour le constructeur**

Dans `constructor()`, ajouter `this.echartsInstances = {};` et supprimer `this.charts = {};`

**Step 5: Vérifier**

Ouvrir la console browser. `typeof echarts` doit retourner `"object"`. Pas d'erreurs.

**Step 6: Commit**
```bash
git add static/js/app.js
git commit -m "feat: ECharts bootstrap — theme helpers, destroyChart, initChart, fullscreen, resetZoom"
```

---

## Task 6 : JS — Protocol donut chart avec drill-down (ECharts)

**Files:**
- Modify: `static/js/app.js`

**Step 1: Remplacer `createProtocolChart()`**

Trouver et remplacer entièrement `createProtocolChart(protocols)` (~ligne 1031):
```javascript
createProtocolChart(protocols) {
    const chart = this.initChart('protocolChart');
    if (!chart) return;
    this.echartsInstances.protocol = chart;

    const t = this.getEChartsTheme();
    const data = Object.entries(protocols)
        .map(([name, value]) => ({ name, value }))
        .sort((a, b) => b.value - a.value);

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
            textStyle: { color: t.textColor, fontFamily: 'Inter, sans-serif', fontSize: 12 }
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
        this.filterPacketsByProtocol(params.name);
        this.showToast('info', 'Filtre appliqué', `Protocole: ${params.name}`);
    });
}
```

**Step 2: Vérifier**

Lancer une analyse, vérifier que le donut apparaît avec animation. Cliquer sur un segment doit afficher le toast de filtre.

**Step 3: Commit**
```bash
git add static/js/app.js
git commit -m "feat: protocol donut chart — ECharts with drill-down filter"
```

---

## Task 7 : JS — Flags chart + Top IPs chart (ECharts)

**Files:**
- Modify: `static/js/app.js`

**Step 1: Remplacer `createFlagsChart()`**

```javascript
createFlagsChart(flags) {
    const chart = this.initChart('flagsChart');
    if (!chart) return;
    this.echartsInstances.flags = chart;

    const t = this.getEChartsTheme();
    const entries = Object.entries(flags).sort((a, b) => b[1] - a[1]);

    chart.setOption({
        backgroundColor: 'transparent',
        tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, ...t.tooltip },
        grid: { left: '3%', right: '4%', top: '8%', bottom: '3%', containLabel: true },
        xAxis: {
            type: 'category',
            data: entries.map(e => e[0]),
            axisLabel: { color: t.textColor, fontFamily: 'Inter, sans-serif' },
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
```

**Step 2: Remplacer `createTopIpsChart()`**

```javascript
createTopIpsChart(ipStats) {
    const chart = this.initChart('topIpsChart');
    if (!chart) return;
    this.echartsInstances.topIps = chart;

    const t = this.getEChartsTheme();
    const topIps = (ipStats.top_sources || []).slice(0, 10).reverse();

    chart.setOption({
        backgroundColor: 'transparent',
        tooltip: {
            trigger: 'axis',
            axisPointer: { type: 'shadow' },
            formatter: (params) => {
                const p = params[0];
                return `<div style="font-family:Inter,sans-serif">
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
                    { offset: 1, color: '#8b5cf6' }
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
        this.filterPacketsByIp(params.name);
        this.showToast('info', 'Filtre appliqué', `IP: ${params.name}`);
    });
}
```

**Step 3: Vérifier**

Charger une analyse. Les deux charts doivent apparaître avec gradients.

**Step 4: Commit**
```bash
git add static/js/app.js
git commit -m "feat: flags bar chart + top IPs gradient bar — ECharts"
```

---

## Task 8 : JS — Anomalies chart + Traffic area chart (ECharts)

**Files:**
- Modify: `static/js/app.js`

**Step 1: Remplacer `createAnomaliesChart()`**

```javascript
createAnomaliesChart(byType) {
    const chart = this.initChart('anomaliesChart');
    if (!chart) return;
    this.echartsInstances.anomalies = chart;

    const t = this.getEChartsTheme();
    const data = Object.entries(byType).map(([name, value]) => ({ name, value }));

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
                itemStyle: { color: ['#ef4444','#f59e0b','#8b5cf6','#06b6d4','#10b981'][i % 5] }
            }))
        }]
    });
}
```

**Step 2: Ajouter `createTrafficTimelineChart()`** (nouveau chart — area avec zoom)

```javascript
createTrafficTimelineChart(timeSeriesData) {
    // timeSeriesData: [{timestamp: "...", count: N, bytes: N}, ...]
    const chart = this.initChart('trafficTimelineChart');
    if (!chart) return;
    this.echartsInstances.trafficTimeline = chart;

    const t = this.getEChartsTheme();
    if (!timeSeriesData || !timeSeriesData.length) {
        chart.setOption({ backgroundColor: 'transparent', graphic: [{
            type: 'text', left: 'center', top: 'center',
            style: { text: 'Pas de données temporelles', fill: t.textColor }
        }]});
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
            { type: 'slider', start: 0, end: 100, height: 24,
              borderColor: t.grid, textStyle: { color: t.textColor } }
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
```

**Step 3: Appeler `createTrafficTimelineChart` dans `displayResults()`**

Dans `displayResults()`, après les autres `createXxxChart()`, ajouter:
```javascript
const timeSeries = protocol.time_series || results.time_series || [];
this.createTrafficTimelineChart(timeSeries);
```

Et dans `templates/index.html`, ajouter le conteneur (dans la grille des charts overview):
```html
<div class="card chart-card chart-card-wide">
    <div class="chart-header">
        <h3>Trafic dans le Temps</h3>
        <div class="chart-actions">
            <button class="chart-btn" onclick="analyzer.resetZoom('trafficTimeline')" title="Reset zoom">⟲</button>
        </div>
    </div>
    <div id="trafficTimelineChart" style="height: 280px;"></div>
</div>
```

**Step 4: Commit**
```bash
git add static/js/app.js templates/index.html
git commit -m "feat: anomalies rose pie + traffic area chart with zoom — ECharts"
```

---

## Task 9 : JS — DNS charts migration ECharts

**Files:**
- Modify: `static/js/app.js`

**Step 1: Remplacer `createDnsDomainsChart()`**

Trouver (~ligne 1207) et remplacer:
```javascript
createDnsDomainsChart(topDomains) {
    const chart = this.initChart('dnsDomainsChart');
    if (!chart) return;
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
```

**Step 2: Remplacer `createDnsTypesChart()` et `createDnsResponseCodesChart()`** avec la même approche ECharts (donut pour types, bar pour response codes). Appliquer le même pattern que `createFlagsChart` avec `t.colors`.

**Step 3: Vérifier**

Aller dans l'onglet DNS après une analyse — les 3 charts doivent s'afficher.

**Step 4: Commit**
```bash
git add static/js/app.js
git commit -m "feat: DNS charts migrated to ECharts"
```

---

## Task 10 : JS — Heatmap temporelle (nouveau chart)

**Files:**
- Modify: `static/js/app.js`

**Step 1: Ajouter `createTemporalHeatmap()`**

```javascript
createTemporalHeatmap(packets) {
    const chart = this.initChart('heatmapChart');
    if (!chart) return;
    this.echartsInstances.heatmap = chart;

    const t = this.getEChartsTheme();

    // Construire grille heure (0-23) x minute (0-59)
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
            data: Array.from({length: 24}, (_, i) => `${i}h`),
            axisLabel: { color: t.textColor, fontSize: 10 },
            splitArea: { show: true }
        },
        yAxis: {
            type: 'category',
            data: Array.from({length: 12}, (_, i) => `${i*5}min`),
            axisLabel: { color: t.textColor, fontSize: 10 },
            splitArea: { show: true }
        },
        visualMap: {
            min: 0, max: maxVal,
            calculable: true,
            orient: 'horizontal',
            left: 'center',
            bottom: '0%',
            inRange: { color: ['#0f172a', '#06b6d4', '#8b5cf6'] },
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
```

**Step 2: Appeler dans `displayResults()`**

```javascript
// Après loadResults(), quand currentResults est dispo:
const packets = results.packets || [];
this.createTemporalHeatmap(packets);
```

**Step 3: Vérifier**

Le heatmap doit afficher une grille colorée. Si pas de données timestamp, afficher "Pas de données".

**Step 4: Commit**
```bash
git add static/js/app.js
git commit -m "feat: temporal heatmap chart — hour x 5min grid"
```

---

## Task 11 : JS — Treemap protocoles + Sankey network flow

**Files:**
- Modify: `static/js/app.js`

**Step 1: Ajouter `createProtocolTreemap()`**

```javascript
createProtocolTreemap(protocols, ipStats) {
    const chart = this.initChart('treemapChart');
    if (!chart) return;
    this.echartsInstances.treemap = chart;

    const t = this.getEChartsTheme();
    const data = Object.entries(protocols).map(([name, value], i) => ({
        name, value,
        itemStyle: { color: t.colors[i % t.colors.length] }
    }));

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
                fontFamily: 'Inter, sans-serif',
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
        this.filterPacketsByProtocol(params.name);
    });
}
```

**Step 2: Ajouter `createSankeyChart()`**

```javascript
createSankeyChart(ipStats, protocols) {
    const chart = this.initChart('sankeyChart');
    if (!chart) return;
    this.echartsInstances.sankey = chart;

    const t = this.getEChartsTheme();

    // Construire nodes et links depuis top IPs + protocoles
    const topSrc = (ipStats.top_sources || []).slice(0, 5);
    const topDst = (ipStats.top_destinations || []).slice(0, 5);
    const protoList = Object.keys(protocols).slice(0, 5);

    if (!topSrc.length || !protoList.length) {
        chart.setOption({ backgroundColor: 'transparent', graphic: [{
            type: 'text', left: 'center', top: 'center',
            style: { text: 'Données insuffisantes pour Sankey', fill: t.textColor }
        }]});
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
                fontFamily: 'Inter, sans-serif',
                fontSize: 11,
                formatter: (p) => p.name.replace('src:','').replace('dst:','').replace('proto:','')
            },
            itemStyle: { borderWidth: 0 },
            nodeWidth: 16,
            nodeGap: 12
        }]
    });
}
```

**Step 3: Appeler dans `displayResults()`**

```javascript
this.createProtocolTreemap(protocol.protocols || {}, protocol.ip_statistics || {});
this.createSankeyChart(protocol.ip_statistics || {}, protocol.protocols || {});
```

**Step 4: Vérifier**

Les deux charts doivent apparaître. Si les données sont insuffisantes pour le Sankey, le message doit s'afficher.

**Step 5: Commit**
```bash
git add static/js/app.js
git commit -m "feat: protocol treemap + sankey network flow — ECharts"
```

---

## Task 12 : JS — Virtual scroll pour le tableau des paquets

**Files:**
- Modify: `static/js/app.js`
- Modify: `templates/index.html`

**Step 1: Ajouter la structure HTML du tableau avec filtre**

Dans `templates/index.html`, dans l'onglet packets, remplacer la structure du tableau par:
```html
<!-- Filter bar -->
<div class="packet-filter-bar">
    <div class="filter-input-wrapper">
        <span class="filter-icon">🔍</span>
        <input type="text" id="packetFilterInput" placeholder="Filtrer paquets... (ex: 192.168, tcp, port:80)" oninput="analyzer.onPacketFilterInput(this.value)">
    </div>
    <select id="protoFilter" onchange="analyzer.applyPacketFilters()" class="filter-select">
        <option value="">Tous protocoles</option>
        <option value="TCP">TCP</option>
        <option value="UDP">UDP</option>
        <option value="DNS">DNS</option>
        <option value="HTTP">HTTP</option>
        <option value="ICMP">ICMP</option>
        <option value="ARP">ARP</option>
    </select>
    <label class="filter-toggle">
        <input type="checkbox" id="regexToggle" onchange="analyzer.applyPacketFilters()">
        <span>Regex</span>
    </label>
    <button class="btn-secondary btn-sm" onclick="analyzer.saveCurrentFilter()">💾 Sauvegarder</button>
    <div id="savedFilters" class="saved-filters"></div>
</div>

<!-- Stats filtrés -->
<div class="filter-stats" id="filterStats"></div>

<!-- Virtual scroll container -->
<div id="packetVirtualContainer" style="height: 500px; overflow-y: auto; position: relative;">
    <div id="packetVirtualSpacer" style="position: relative;">
        <table class="data-table resizable-table" id="packetTable">
            <thead>
                <tr>
                    <th data-col="num" style="width:60px">#<span class="col-resizer"></span></th>
                    <th data-col="time" style="width:130px">Temps<span class="col-resizer"></span></th>
                    <th data-col="src" style="width:150px">Source<span class="col-resizer"></span></th>
                    <th data-col="dst" style="width:150px">Destination<span class="col-resizer"></span></th>
                    <th data-col="proto" style="width:100px">Protocole<span class="col-resizer"></span></th>
                    <th data-col="len" style="width:80px">Taille<span class="col-resizer"></span></th>
                    <th data-col="flags" style="width:120px">Flags<span class="col-resizer"></span></th>
                    <th data-col="info">Info<span class="col-resizer"></span></th>
                </tr>
            </thead>
            <tbody id="packetTableBody"></tbody>
        </table>
    </div>
</div>
```

**Step 2: Ajouter la classe `VirtualScroll` dans `app.js`** (avant la classe `PCAPAnalyzer`)

```javascript
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

        container.addEventListener('scroll', () => this.onScroll());
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

        this.spacer.style.height = `${total * this.rowHeight}px`;
        this.tbody.innerHTML = '';

        for (let i = startIndex; i < endIndex; i++) {
            const row = this.renderFn(this.filteredData[i], i);
            row.style.position = 'absolute';
            row.style.top = `${i * this.rowHeight}px`;
            row.style.width = '100%';
            this.tbody.appendChild(row);
        }
    }
}
```

**Step 3: Remplacer `loadPackets()` dans `PCAPAnalyzer`**

Trouver et remplacer la méthode `loadPackets()`:
```javascript
async loadPackets() {
    if (!this.currentTaskId) return;
    if (!this.virtualScroll) {
        const container = document.getElementById('packetVirtualContainer');
        const spacer = document.getElementById('packetVirtualSpacer');
        const tbody = document.getElementById('packetTableBody');
        if (!container || !spacer || !tbody) return;
        this.virtualScroll = new VirtualScroll(container, spacer, tbody, 38);
    }

    try {
        const response = await fetch(`/api/analysis/${this.currentTaskId}/packets?limit=10000`);
        const data = await response.json();
        this.allPackets = data.packets || data || [];

        // Pré-calculer index pour filtres rapides
        this.packetIndex = { byProto: {}, byIp: {} };
        this.allPackets.forEach((pkt, i) => {
            const proto = (pkt.protocol || '').toUpperCase();
            if (!this.packetIndex.byProto[proto]) this.packetIndex.byProto[proto] = [];
            this.packetIndex.byProto[proto].push(i);
        });

        this.filteredPackets = this.allPackets;
        this.virtualScroll.setData(this.allPackets, (pkt, idx) => this.renderPacketRow(pkt, idx));
        this.updateFilterStats();
        this.setupResizableColumns();
    } catch (e) {
        console.error('Error loading packets:', e);
    }
}
```

**Step 4: Ajouter `renderPacketRow()`**

```javascript
renderPacketRow(pkt, idx) {
    const proto = (pkt.protocol || 'other').toLowerCase();
    const flags = pkt.tcp_flags || pkt.flags || '';
    const flagBadges = this.renderFlagBadges(flags);

    const tr = document.createElement('tr');
    tr.className = 'packet-row';
    tr.innerHTML = `
        <td style="font-family:monospace;font-size:0.8rem;color:var(--text-muted)">${pkt.number || idx + 1}</td>
        <td style="font-family:monospace;font-size:0.8rem">${pkt.timestamp ? new Date(pkt.timestamp * 1000).toISOString().substr(11, 12) : (pkt.time || '-')}</td>
        <td style="font-family:monospace;font-size:0.8rem">${pkt.src_ip || pkt.source || '-'}</td>
        <td style="font-family:monospace;font-size:0.8rem">${pkt.dst_ip || pkt.destination || '-'}</td>
        <td><span class="proto-badge ${proto}">${(pkt.protocol || '-').toUpperCase()}</span></td>
        <td style="font-size:0.8rem">${pkt.length || pkt.len || '-'}</td>
        <td>${flagBadges}</td>
        <td style="font-size:0.8rem;color:var(--text-muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${pkt.info || '-'}</td>
    `;
    tr.addEventListener('click', () => this.togglePacketDetail(tr, pkt));
    return tr;
}

renderFlagBadges(flags) {
    if (!flags) return '';
    const flagList = typeof flags === 'string' ? flags.split(/[,\s]+/) : Object.keys(flags).filter(f => flags[f]);
    return flagList.filter(Boolean).map(f =>
        `<span class="flag-badge ${f.toLowerCase()}">${f.toUpperCase()}</span>`
    ).join('');
}

togglePacketDetail(tr, pkt) {
    const existing = tr.nextSibling;
    if (existing && existing.classList.contains('packet-detail-row')) {
        existing.remove();
        tr.classList.remove('expanded');
        return;
    }
    tr.classList.add('expanded');
    const detail = document.createElement('tr');
    detail.className = 'packet-detail-row visible';
    detail.innerHTML = `<td colspan="8">
        <div class="packet-detail-content">
            <pre>${JSON.stringify(pkt, null, 2)}</pre>
        </div>
    </td>`;
    tr.insertAdjacentElement('afterend', detail);
}
```

**Step 5: Commit**
```bash
git add static/js/app.js templates/index.html
git commit -m "feat: virtual scroll packet table — VirtualScroll class, proto/flag badges, expand detail"
```

---

## Task 13 : JS — Filtres avancés + colonnes redimensionnables

**Files:**
- Modify: `static/js/app.js`

**Step 1: Ajouter `onPacketFilterInput()` + `applyPacketFilters()`**

```javascript
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

    // Filtre protocole (index pré-calculé)
    if (protoFilter) {
        const indices = this.packetIndex.byProto[protoFilter.toUpperCase()] || [];
        results = indices.map(i => this.allPackets[i]);
    }

    // Filtre texte
    if (text) {
        try {
            const pattern = useRegex ? new RegExp(text, 'i') : null;
            results = results.filter(pkt => {
                const haystack = JSON.stringify(pkt).toLowerCase();
                return pattern ? pattern.test(haystack) : haystack.includes(text.toLowerCase());
            });
        } catch (e) {
            // Regex invalide — ignorer
        }
    }

    this.filteredPackets = results;
    this.virtualScroll.setFilteredData(results);
    this.updateFilterStats();
}

updateFilterStats() {
    const el = document.getElementById('filterStats');
    if (!el) return;
    const total = this.allPackets?.length || 0;
    const filtered = this.filteredPackets?.length || total;
    el.textContent = filtered === total
        ? `${total.toLocaleString()} paquets`
        : `${filtered.toLocaleString()} / ${total.toLocaleString()} paquets`;
}

filterPacketsByProtocol(proto) {
    const select = document.getElementById('protoFilter');
    if (select) { select.value = proto; }
    const input = document.getElementById('packetFilterInput');
    if (input) { input.value = ''; }
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
```

**Step 2: Ajouter `setupResizableColumns()`**

```javascript
setupResizableColumns() {
    const table = document.getElementById('packetTable');
    if (!table) return;

    table.querySelectorAll('th').forEach(th => {
        const resizer = th.querySelector('.col-resizer');
        if (!resizer) return;

        let startX, startWidth;
        resizer.addEventListener('mousedown', (e) => {
            e.preventDefault();
            startX = e.clientX;
            startWidth = th.offsetWidth;
            resizer.classList.add('resizing');

            const onMove = (e) => {
                th.style.width = Math.max(60, startWidth + e.clientX - startX) + 'px';
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
```

**Step 3: Vérifier**

- Taper "tcp" dans le filtre → seulement les paquets TCP s'affichent
- Activer "Regex" et taper `192\.168\.\d+` → filtre par regex
- Sauvegarder un filtre → badge apparaît, clic rechargé le filtre
- Drag sur un header de colonne → colonne se redimensionne

**Step 4: Commit**
```bash
git add static/js/app.js
git commit -m "feat: packet filters — text, regex, proto, saved filters + resizable columns"
```

---

## Task 14 : Resize ECharts on window resize

**Files:**
- Modify: `static/js/app.js`

**Step 1: Ajouter le listener dans `init()`**

Dans la méthode `init()`, ajouter:
```javascript
window.addEventListener('resize', () => {
    Object.values(this.echartsInstances).forEach(chart => {
        if (chart && !chart.isDisposed()) chart.resize();
    });
});
```

**Step 2: Vérifier**

Redimensionner la fenêtre — tous les charts doivent se redimensionner sans déformation.

**Step 3: Commit**
```bash
git add static/js/app.js
git commit -m "feat: ECharts auto-resize on window resize"
```

---

## Checklist finale

- [ ] ECharts visible en console sans erreur
- [ ] Protocol donut avec drill-down → filtre les paquets
- [ ] Top IPs gradient → filtre les paquets
- [ ] Traffic area chart avec zoom/pan fonctionnel
- [ ] Heatmap temporelle visible
- [ ] Treemap visible avec drill-down
- [ ] Sankey visible (ou message si données insuffisantes)
- [ ] DNS charts migrés
- [ ] Cards avec effet glassmorphism visible (backdrop-filter)
- [ ] Animations fadeInUp au chargement des résultats
- [ ] Risk card pulsante si HIGH/CRITICAL
- [ ] Virtual scroll fluide à 10 000 paquets
- [ ] Proto badges colorés dans le tableau
- [ ] Flag badges (SYN, ACK, etc.) visibles
- [ ] Expand row → JSON du paquet affiché
- [ ] Filtre texte temps réel (<150ms)
- [ ] Filtre regex fonctionnel
- [ ] Filtres sauvegardés → session storage
- [ ] Colonnes redimensionnables
- [ ] Resize fenêtre → charts se réajustent
