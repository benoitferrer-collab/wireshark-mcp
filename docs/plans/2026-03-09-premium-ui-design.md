# PCAP Analyzer Pro V2 — Premium UI Redesign
**Date:** 2026-03-09
**Approche:** B — ECharts + Virtual Scroll + Glassmorphism CSS

---

## 1. Glassmorphism CSS Overhaul

### Palette
- Couleurs conservées : cyan `#06b6d4`, violet `#8b5cf6`
- Fond sombre : `#0f172a` (inchangé)

### Cards & Surfaces
- `background: rgba(30,41,59,0.4)`
- `backdrop-filter: blur(20px)`
- `border: 1px solid rgba(255,255,255,0.08)`
- Glow coloré au hover via `box-shadow`
- Gradient borders cyan→violet via pseudo-éléments `::before`

### Header
- Sticky glassmorphism : `blur(24px)` + `border-bottom` semi-transparent

### Animations
- `@keyframes fadeInUp` sur toutes les cards avec stagger CSS (50ms)
- Loading skeletons animés (shimmer) pendant l'analyse — remplace le spinner
- Risk card pulse rouge/orange si risque élevé
- Upload zone : glow vert au succès, animation concentrique au drop

---

## 2. Migration Apache ECharts

### Remplacement Chart.js → ECharts (CDN ~1MB)
Tous les charts existants sont réécrits avec ECharts.

### Charts Vue Overview
| Chart | Type ECharts | Nouveauté |
|-------|-------------|-----------|
| Distribution protocoles | Donut animé | Drill-down sous-protocoles |
| Trafic dans le temps | Area chart + gradient | Zoom natif, crosshair tooltip |
| Top IPs | Bar horizontal dégradé | Tooltip enrichi geoloc |

### Nouveaux Charts
| Chart | Description |
|-------|-------------|
| Heatmap temporelle | Grille heure×minute, intensité = nb paquets |
| Treemap protocoles | Blocs proportionnels à la bande passante, drill-down → ports |
| Sankey network flow | `IP source → Protocole → IP destination` |

### Interactivité Globale
- Zoom/pan natif sur tous les charts temporels
- Clic segment → filtre automatique de la vue paquets
- Tooltips riches avec mini-sparkline intégré
- Boutons "Reset zoom" et "Fullscreen" sur chaque chart
- Export PNG/SVG natif ECharts par chart

---

## 3. Tableau des Paquets

### Virtual Scroll
- Rendu limité aux lignes visibles (~20 lignes dans le DOM)
- Scroll fluide pour 1M+ paquets
- Index pré-calculé au chargement (par protocole, IP, port)

### Visuels
- Badge coloré par protocole (TCP=cyan, UDP=violet, DNS=vert, HTTP=orange, ICMP=rouge)
- Mini-badges flags TCP inline : `SYN`, `ACK`, `FIN`, `RST`
- Expand row : détails complets + payload hex si disponible
- Colonnes redimensionnables via drag sur les headers

### Filtres
- Barre globale : filtre temps réel toutes colonnes
- Filtres par colonne : dropdown protocole, range port, range taille, range timestamp
- Mode regex : toggle pour activer sur la recherche globale
- Filtres sauvegardés : nommés et réutilisables dans la session

---

## Fichiers impactés
- `static/css/style.css` — refonte glassmorphism complète
- `static/js/app.js` — migration ECharts + virtual scroll + filtres
- `templates/index.html` — CDN ECharts, nouveaux conteneurs charts, structure tableau

## Fichiers non impactés
- Tous les fichiers Python backend (`app/`, `tests/`) — aucun changement
