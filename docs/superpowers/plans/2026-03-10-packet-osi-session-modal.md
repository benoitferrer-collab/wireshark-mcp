# Packet OSI Modal & IP Session Modal — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a full OSI L1-L7 accordion modal for packet inspection and an IP-centric session modal showing all sessions/protocols for a selected IP.

**Architecture:** Backend enriches `GET /api/analysis/{task_id}/packet/{packet_num}` by re-reading the PCAP via Scapy `PcapReader` to extract per-layer fields. Frontend replaces the raw JSON inline-expand with a glassmorphism accordion modal (L1-L7, colored per layer). A second all-frontend modal pivots on the IP of any clicked session row to show all related sessions + mini ECharts.

**Tech Stack:** Python/FastAPI + Scapy (backend), vanilla JS + Apache ECharts 5 (frontend), glassmorphism CSS (existing design system)

---

## Chunk 1: Backend — Enrich packet details endpoint

### Task 1: Extract OSI layers in `routes.py`

**Files:**
- Modify: `app/api/routes.py` — function `get_packet_details` (~line 1027)
- Test: `tests/test_packet_osi.py` (new)

#### Context

`storage_service.get_pcap_path(task_id)` already returns the PCAP path or `None`. `PcapReader` lets us iterate a PCAP with minimal memory; skip to index N by reading N packets without loading them all.

The current endpoint returns `{packet_num, basic_info, dns_info, http_info}`. We will add `l1_physical`, `l2_datalink`, `l3_network`, `l4_transport`, `l5_session`, `l6_presentation`, `l7_application`, `raw_hex`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_packet_osi.py`:

```python
"""Tests for enriched packet details endpoint (OSI layers)."""
import pytest
from unittest.mock import patch, MagicMock


def make_fake_results(num_packets=3):
    return {
        'packets_index': [
            {'idx': i, 'timestamp': 1700000000.0 + i, 'length': 74,
             'src_ip': f'10.0.0.{i+1}', 'dst_ip': '8.8.8.8',
             'src_port': 12345, 'dst_port': 53, 'protocol': 'DNS', 'info': ''}
            for i in range(num_packets)
        ],
        'tcp_analysis': {'sessions': []},
        'tls_analysis': {'sessions': []},
        'dns_analysis': {'queries': [], 'responses': []},
        'http_analysis': {'requests': [], 'responses': []},
    }


def test_extract_osi_layers_returns_all_keys():
    """extract_osi_layers returns a dict with all 7 layer keys."""
    from app.api.routes import extract_osi_layers

    mock_pkt = MagicMock()
    # IP layer
    mock_pkt.haslayer = lambda cls: cls.__name__ in ('IP', 'TCP', 'Ether')
    mock_ip = MagicMock()
    mock_ip.src = '10.0.0.1'
    mock_ip.dst = '8.8.8.8'
    mock_ip.ttl = 64
    mock_ip.version = 4
    mock_ip.ihl = 5
    mock_ip.tos = 0
    mock_ip.frag = 0
    mock_ip.chksum = 0x1a2b
    mock_ip.proto = 6
    mock_pkt.__getitem__ = lambda self, cls: mock_ip

    result = extract_osi_layers(mock_pkt, packet_info={
        'src_ip': '10.0.0.1', 'dst_ip': '8.8.8.8',
        'src_port': 12345, 'dst_port': 443,
        'protocol': 'TCP', 'length': 74
    })

    for key in ('l1_physical', 'l2_datalink', 'l3_network', 'l4_transport',
                'l5_session', 'l6_presentation', 'l7_application', 'raw_hex'):
        assert key in result, f"Missing key: {key}"


def test_extract_osi_layers_l3_fields():
    """L3 fields map correctly from IP layer."""
    from app.api.routes import extract_osi_layers
    from unittest.mock import patch, MagicMock

    mock_pkt = MagicMock()

    ip_mock = MagicMock()
    ip_mock.src = '192.168.1.1'
    ip_mock.dst = '1.1.1.1'
    ip_mock.ttl = 128
    ip_mock.version = 4
    ip_mock.ihl = 5
    ip_mock.tos = 0
    ip_mock.frag = 0
    ip_mock.chksum = 0xabcd
    ip_mock.proto = 17  # UDP

    def haslayer(cls):
        return cls.__name__ in ('IP',)
    mock_pkt.haslayer = haslayer
    mock_pkt.__getitem__ = lambda self, cls: ip_mock

    result = extract_osi_layers(mock_pkt, packet_info={
        'src_ip': '192.168.1.1', 'dst_ip': '1.1.1.1',
        'src_port': 5353, 'dst_port': 53,
        'protocol': 'UDP', 'length': 50
    })

    assert result['l3_network']['src_ip'] == '192.168.1.1'
    assert result['l3_network']['ttl'] == 128
    assert result['l3_network']['version'] == 4
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd "/Users/bfe/Downloads/pcap_analyzer_pro_v2 (1)"
python -m pytest tests/test_packet_osi.py -v 2>&1 | head -30
```

Expected: `ImportError` or `AttributeError` — `extract_osi_layers` does not exist yet.

- [ ] **Step 3: Add `extract_osi_layers` helper + enrich `get_packet_details` in `routes.py`**

Find the import block at the top of `app/api/routes.py` and ensure Scapy imports are present (they likely already are). Then add the helper function and update the endpoint.

**Add this helper function** just before the `get_packet_details` route (around line 1026):

```python
def extract_osi_layers(pkt, packet_info: dict) -> dict:
    """Extract OSI L1-L7 fields from a Scapy packet."""
    from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, DNS, Raw
    try:
        from scapy.layers.tls.all import TLS
    except ImportError:
        TLS = None

    result = {
        'l1_physical': {
            'medium': 'Ethernet',
            'capture_len': packet_info.get('length', len(pkt)),
            'original_len': len(pkt),
        },
        'l2_datalink': {'src_mac': None, 'dst_mac': None, 'ethertype': None},
        'l3_network': {
            'src_ip': packet_info.get('src_ip'),
            'dst_ip': packet_info.get('dst_ip'),
            'ttl': None, 'version': None, 'ihl': None,
            'tos': None, 'fragment_offset': None, 'checksum': None, 'protocol_num': None,
        },
        'l4_transport': {
            'protocol': packet_info.get('protocol'),
            'src_port': packet_info.get('src_port'),
            'dst_port': packet_info.get('dst_port'),
            'seq': None, 'ack': None, 'window': None,
            'flags': [], 'checksum': None, 'urgent': None,
            'udp_len': None,
        },
        'l5_session': {'stream_id': None, 'direction': None, 'state': None},
        'l6_presentation': {'tls_version': None, 'cipher_suite': None, 'sni': None},
        'l7_application': {'protocol': None, 'detail': {}},
        'raw_hex': '',
    }

    # L2 — Ethernet
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        result['l2_datalink']['src_mac'] = eth.src
        result['l2_datalink']['dst_mac'] = eth.dst
        result['l2_datalink']['ethertype'] = f'0x{eth.type:04x}'

    # L3 — IP
    if pkt.haslayer(IP):
        ip = pkt[IP]
        result['l3_network'].update({
            'src_ip': ip.src, 'dst_ip': ip.dst,
            'ttl': ip.ttl, 'version': ip.version, 'ihl': ip.ihl * 4,
            'tos': ip.tos, 'fragment_offset': ip.frag,
            'checksum': hex(ip.chksum) if ip.chksum else None,
            'protocol_num': ip.proto,
        })
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        result['l3_network'].update({
            'src_ip': ip6.src, 'dst_ip': ip6.dst,
            'ttl': ip6.hlim, 'version': 6,
        })

    # L4 — TCP/UDP/ICMP
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        flags = []
        flag_map = [('S','SYN'),('A','ACK'),('F','FIN'),('R','RST'),('P','PSH'),('U','URG'),('E','ECE'),('C','CWR')]
        for attr, name in flag_map:
            try:
                if getattr(tcp.flags, attr, False):
                    flags.append(name)
            except Exception:
                pass
        result['l4_transport'].update({
            'protocol': 'TCP',
            'src_port': tcp.sport, 'dst_port': tcp.dport,
            'seq': tcp.seq, 'ack': tcp.ack,
            'window': tcp.window, 'flags': flags,
            'checksum': hex(tcp.chksum) if tcp.chksum else None,
            'urgent': tcp.urgptr,
        })
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        result['l4_transport'].update({
            'protocol': 'UDP',
            'src_port': udp.sport, 'dst_port': udp.dport,
            'checksum': hex(udp.chksum) if udp.chksum else None,
            'udp_len': udp.len,
        })
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        result['l4_transport']['protocol'] = 'ICMP'
        result['l7_application'] = {
            'protocol': 'ICMP',
            'detail': {'type': icmp.type, 'code': icmp.code},
        }

    # L7 — DNS
    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        if dns.qd:
            qname = dns.qd.qname.decode('utf-8', errors='ignore') if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname)
            result['l7_application'] = {
                'protocol': 'DNS',
                'detail': {
                    'type': 'query' if dns.qr == 0 else 'response',
                    'domain': qname,
                    'qtype': dns.qd.qtype if dns.qd else None,
                    'rcode': dns.rcode if dns.qr == 1 else None,
                }
            }

    # L7 — Raw HTTP (basic detection)
    if pkt.haslayer(Raw):
        try:
            payload = bytes(pkt[Raw]).decode('utf-8', errors='ignore')
            if payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'HTTP/')):
                first_line = payload.split('\n')[0].strip()
                result['l7_application'] = {
                    'protocol': 'HTTP',
                    'detail': {'first_line': first_line, 'body_preview': payload[:200]},
                }
        except Exception:
            pass

    # Raw hex (first 256 bytes)
    try:
        raw_bytes = bytes(pkt)[:256]
        result['raw_hex'] = ' '.join(f'{b:02x}' for b in raw_bytes)
    except Exception:
        result['raw_hex'] = ''

    return result
```

**Update `get_packet_details`** — replace the `return` block (lines 1069-1074) with:

```python
    # Re-read PCAP for full layer data
    layers = {}
    pcap_path = storage_service.get_pcap_path(task_id)
    if pcap_path:
        try:
            from scapy.all import PcapReader
            with PcapReader(pcap_path) as reader:
                for i, raw_pkt in enumerate(reader):
                    if i == packet_num:
                        layers = extract_osi_layers(raw_pkt, packet)
                        break
        except Exception as e:
            logger.warning(f"Could not re-read PCAP for packet {packet_num}: {e}")

    # Enrich L5 from tcp sessions
    if layers:
        src = f"{packet.get('src_ip')}:{packet.get('src_port')}"
        dst = f"{packet.get('dst_ip')}:{packet.get('dst_port')}"
        for idx, s in enumerate(results.get('tcp_analysis', {}).get('sessions', [])):
            if (s.get('src') == src and s.get('dst') == dst) or \
               (s.get('src') == dst and s.get('dst') == src):
                layers['l5_session'] = {
                    'stream_id': idx,
                    'state': s.get('state'),
                    'direction': 'client_to_server' if s.get('src') == src else 'server_to_client',
                }
                break

        # Enrich L6 from tls sessions
        for tls_s in results.get('tls_analysis', {}).get('sessions', []):
            sni = tls_s.get('sni') or tls_s.get('server_name')
            tls_src = tls_s.get('src_ip') or tls_s.get('client_ip')
            if tls_src == packet.get('src_ip') or tls_src == packet.get('dst_ip'):
                layers['l6_presentation'] = {
                    'tls_version': tls_s.get('version') or tls_s.get('tls_version'),
                    'cipher_suite': tls_s.get('cipher_suite'),
                    'sni': sni,
                }
                break

    return {
        'packet_num': packet_num,
        'basic_info': packet,
        'dns_info': dns_info,
        'http_info': http_info,
        **layers,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd "/Users/bfe/Downloads/pcap_analyzer_pro_v2 (1)"
python -m pytest tests/test_packet_osi.py -v
```

Expected: all tests PASS.

- [ ] **Step 5: Smoke-test the endpoint manually**

```bash
# After starting the server, run a real analysis then:
curl -s http://localhost:8000/api/analysis/<task_id>/packet/0 | python3 -m json.tool | head -60
```

Verify `l1_physical`, `l2_datalink`, `l3_network`, `l4_transport`, `raw_hex` are present in response.

---

## Chunk 2: Frontend — OSI Layer Modal CSS

### Task 2: Add OSI accordion CSS to `index.html`

**Files:**
- Modify: `templates/index.html` — `<style>` block

- [ ] **Step 1: Add OSI layer CSS**

Locate the closing `</style>` tag in `templates/index.html` and insert before it:

```css
/* ========== OSI LAYER MODAL ========== */
.osi-modal-header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 1rem 1.5rem;
    border-bottom: 1px solid var(--border-glass);
    position: sticky;
    top: 0;
    background: var(--bg-card);
    z-index: 1;
    border-radius: var(--radius-lg) var(--radius-lg) 0 0;
}
.osi-modal-header .pkt-badges {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
    align-items: center;
}
.osi-layer {
    border-bottom: 1px solid var(--border-glass);
    overflow: hidden;
}
.osi-layer:last-child { border-bottom: none; }
.osi-layer-header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.75rem 1.25rem;
    cursor: pointer;
    user-select: none;
    transition: background 0.15s;
}
.osi-layer-header:hover { background: rgba(255,255,255,0.04); }
.osi-layer-badge {
    font-size: 0.7rem;
    font-weight: 700;
    padding: 0.2rem 0.55rem;
    border-radius: 99px;
    color: #fff;
    min-width: 2.2rem;
    text-align: center;
}
.osi-layer-title { font-weight: 600; font-size: 0.9rem; flex: 1; }
.osi-layer-summary { font-size: 0.78rem; color: var(--text-muted); }
.osi-chevron { transition: transform 0.2s; color: var(--text-muted); font-size: 0.75rem; }
.osi-layer.open .osi-chevron { transform: rotate(90deg); }
.osi-layer-body {
    display: none;
    padding: 0.5rem 1.25rem 1rem 1.25rem;
}
.osi-layer.open .osi-layer-body { display: block; }
.osi-layer.empty .osi-layer-header { opacity: 0.45; cursor: default; }
.osi-fields {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 0.5rem 1.5rem;
}
.osi-field { display: flex; flex-direction: column; gap: 0.15rem; }
.osi-field-label { font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
.osi-field-value { font-size: 0.85rem; font-family: monospace; color: var(--text-primary); word-break: break-all; }
.hex-dump {
    font-family: monospace;
    font-size: 0.78rem;
    color: var(--text-muted);
    background: var(--bg-tertiary);
    border-radius: var(--radius-sm);
    padding: 0.75rem 1rem;
    word-break: break-all;
    line-height: 1.8;
    max-height: 180px;
    overflow-y: auto;
}
.hex-dump .hex-group { margin-right: 0.3rem; }
.hex-toggle {
    background: none;
    border: 1px solid var(--border-glass);
    color: var(--text-muted);
    border-radius: var(--radius-sm);
    padding: 0.35rem 0.75rem;
    font-size: 0.78rem;
    cursor: pointer;
    margin: 0.75rem 0 0.5rem;
    width: 100%;
    text-align: left;
    transition: background 0.15s;
}
.hex-toggle:hover { background: rgba(255,255,255,0.05); }

/* ========== IP SESSION MODAL ========== */
.ip-modal-stats { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1rem; }
.ip-stat-card {
    background: var(--bg-tertiary);
    border-radius: var(--radius-md);
    padding: 0.65rem 1rem;
    text-align: center;
    flex: 1;
    min-width: 90px;
}
.ip-stat-value { font-size: 1.4rem; font-weight: 700; color: var(--accent-cyan); }
.ip-stat-label { font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase; }
.ip-mini-charts { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem; }
.ip-sessions-table { width: 100%; border-collapse: collapse; font-size: 0.83rem; }
.ip-sessions-table th {
    text-align: left;
    padding: 0.4rem 0.6rem;
    font-size: 0.7rem;
    text-transform: uppercase;
    color: var(--text-muted);
    border-bottom: 1px solid var(--border-glass);
}
.ip-sessions-table td { padding: 0.45rem 0.6rem; border-bottom: 1px solid rgba(255,255,255,0.04); }
.ip-sessions-table tr:hover td { background: rgba(255,255,255,0.03); }
.direction-badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 1.6rem;
    height: 1.6rem;
    border-radius: 50%;
    font-size: 0.75rem;
    font-weight: 700;
}
.direction-out { background: rgba(6,182,212,0.15); color: #06b6d4; }
.direction-in  { background: rgba(139,92,246,0.15); color: #8b5cf6; }
```

- [ ] **Step 2: Verify page loads without CSS errors**

Open the app in browser, open DevTools → Console. No CSS parse errors.

---

## Chunk 3: Frontend — Packet OSI Modal JS

### Task 3: Replace `showPacketDetails` and `togglePacketDetail` in `app.js`

**Files:**
- Modify: `static/js/app.js`

The current `showPacketDetails(packetNum)` fetches the API and shows 4 fields. The current `togglePacketDetail(tr, pkt)` shows a raw JSON `<pre>`. Both will be replaced.

#### OSI layer config (colors + labels):

```javascript
const OSI_LAYERS = [
    { key: 'l1_physical',     num: 1, label: 'Physical',     color: '#64748b', icon: '📡' },
    { key: 'l2_datalink',     num: 2, label: 'Data Link',    color: '#3b82f6', icon: '🔗' },
    { key: 'l3_network',      num: 3, label: 'Network',      color: '#10b981', icon: '🌐' },
    { key: 'l4_transport',    num: 4, label: 'Transport',    color: '#f59e0b', icon: '🚀' },
    { key: 'l5_session',      num: 5, label: 'Session',      color: '#eab308', icon: '🔄' },
    { key: 'l6_presentation', num: 6, label: 'Presentation', color: '#8b5cf6', icon: '🎨' },
    { key: 'l7_application',  num: 7, label: 'Application',  color: '#06b6d4', icon: '📦' },
];
```

- [ ] **Step 1: Replace `showPacketDetails` in `app.js`**

Find and replace the entire `showPacketDetails(packetNum)` method (lines ~2340-2365):

```javascript
showPacketDetails(packetNum) {
    const OSI_LAYERS = [
        { key: 'l1_physical',     num: 1, label: 'Physical',     color: '#64748b', icon: '📡' },
        { key: 'l2_datalink',     num: 2, label: 'Data Link',    color: '#3b82f6', icon: '🔗' },
        { key: 'l3_network',      num: 3, label: 'Network',      color: '#10b981', icon: '🌐' },
        { key: 'l4_transport',    num: 4, label: 'Transport',    color: '#f59e0b', icon: '🚀' },
        { key: 'l5_session',      num: 5, label: 'Session',      color: '#eab308', icon: '🔄' },
        { key: 'l6_presentation', num: 6, label: 'Presentation', color: '#8b5cf6', icon: '🎨' },
        { key: 'l7_application',  num: 7, label: 'Application',  color: '#06b6d4', icon: '📦' },
    ];

    this.openModal(`Paquet #${packetNum} — Inspection OSI`, '<div class="loading-spinner"><div class="spinner"></div></div>');

    fetch(`/api/analysis/${this.currentTaskId}/packet/${packetNum}`)
        .then(r => r.json())
        .then(data => {
            const basic = data.basic_info || {};
            const proto = basic.protocol || data.l4_transport?.protocol || '?';
            const src = basic.src_ip ? `${basic.src_ip}${basic.src_port ? ':' + basic.src_port : ''}` : '?';
            const dst = basic.dst_ip ? `${basic.dst_ip}${basic.dst_port ? ':' + basic.dst_port : ''}` : '?';
            const ts  = basic.timestamp ? new Date(basic.timestamp * 1000).toLocaleTimeString() : '';

            let html = `
            <div class="osi-modal-header">
                <span class="protocol-badge ${proto.toLowerCase()}">${proto}</span>
                <div class="pkt-badges">
                    <code style="font-size:0.85rem">${src}</code>
                    <span style="color:var(--text-muted)">→</span>
                    <code style="font-size:0.85rem">${dst}</code>
                    ${ts ? `<span style="color:var(--text-muted);font-size:0.8rem">${ts}</span>` : ''}
                    <span style="color:var(--text-muted);font-size:0.8rem">${basic.length || 0} B</span>
                </div>
            </div>`;

            // Render each OSI layer
            OSI_LAYERS.forEach(layer => {
                const layerData = data[layer.key];
                const hasData = layerData && Object.values(layerData).some(v => v !== null && v !== undefined && v !== '' && !(Array.isArray(v) && v.length === 0));

                // Build field entries from layerData
                const fields = layerData ? Object.entries(layerData)
                    .filter(([, v]) => v !== null && v !== undefined && v !== '' && !(Array.isArray(v) && v.length === 0))
                    .map(([k, v]) => {
                        const label = k.replace(/_/g, ' ');
                        const val = Array.isArray(v) ? v.join(', ') : (typeof v === 'object' ? JSON.stringify(v) : v);
                        return `<div class="osi-field">
                            <span class="osi-field-label">${label}</span>
                            <span class="osi-field-value">${this.escapeHtml(String(val))}</span>
                        </div>`;
                    }).join('') : '';

                // Summary line shown in header when collapsed
                let summary = '';
                if (layer.key === 'l2_datalink' && layerData?.src_mac) summary = `${layerData.src_mac} → ${layerData.dst_mac}`;
                if (layer.key === 'l3_network' && layerData?.src_ip) summary = `TTL ${layerData.ttl} · ${layerData.src_ip} → ${layerData.dst_ip}`;
                if (layer.key === 'l4_transport' && layerData?.protocol) summary = `${layerData.protocol} ${layerData.src_port}→${layerData.dst_port} [${(layerData.flags||[]).join(',')}]`;
                if (layer.key === 'l7_application' && layerData?.protocol) summary = layerData.protocol;

                const openClass = (hasData && layer.num <= 4) ? 'open' : (hasData ? 'open' : 'empty');

                html += `
                <div class="osi-layer ${openClass}" data-layer="${layer.key}">
                    <div class="osi-layer-header" onclick="this.closest('.osi-layer').classList.toggle('open')">
                        <span class="osi-layer-badge" style="background:${layer.color}">${layer.icon} L${layer.num}</span>
                        <span class="osi-layer-title">${layer.label}</span>
                        <span class="osi-layer-summary">${summary}</span>
                        <span class="osi-chevron">▶</span>
                    </div>
                    <div class="osi-layer-body">
                        ${hasData ? `<div class="osi-fields">${fields}</div>` : '<p style="color:var(--text-muted);font-size:0.82rem;margin:0">Aucune donnée disponible pour cette couche.</p>'}
                    </div>
                </div>`;
            });

            // Raw hex dump
            if (data.raw_hex) {
                const groups = data.raw_hex.match(/.{1,23}/g) || [];
                const hexHtml = groups.map(g => `<span class="hex-group">${g}</span>`).join('');
                html += `
                <div style="padding: 0 1.25rem 1.25rem">
                    <button class="hex-toggle" onclick="this.nextElementSibling.style.display = this.nextElementSibling.style.display === 'none' ? 'block' : 'none'; this.textContent = this.textContent.includes('▼') ? '▲ Masquer hex dump' : '▼ Voir raw hex dump'">▼ Voir raw hex dump</button>
                    <div class="hex-dump" style="display:none">${hexHtml}</div>
                </div>`;
            }

            const modalBody = document.getElementById('modalBody');
            if (modalBody) modalBody.innerHTML = html;
        })
        .catch(() => {
            const modalBody = document.getElementById('modalBody');
            if (modalBody) modalBody.innerHTML = '<p style="color:var(--danger)">Erreur de chargement du paquet.</p>';
        });
}
```

- [ ] **Step 2: Replace `togglePacketDetail` to open modal instead of inline JSON**

Find `togglePacketDetail(tr, pkt)` (~line 1081) and replace:

```javascript
togglePacketDetail(tr, pkt) {
    // Open full OSI modal instead of inline raw JSON
    const packetNum = pkt.idx !== undefined ? pkt.idx : (pkt.packet_num !== undefined ? pkt.packet_num : null);
    if (packetNum !== null) {
        this.showPacketDetails(packetNum);
    }
}
```

- [ ] **Step 3: Add `escapeHtml` utility if not present**

Search `app.js` for `escapeHtml`. If not found, add it in the `// ==================== UTILITIES ====================` section:

```javascript
escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
```

- [ ] **Step 4: Manual test in browser**

1. Upload a PCAP, wait for analysis
2. Go to Paquets tab
3. Click any row → modal should open with OSI accordion
4. Verify L1-L4 are open by default, show correct IP/port/flags
5. Click a layer header → it collapses/expands
6. Click "Voir raw hex dump" → hex appears

---

## Chunk 4: Frontend — IP Session Modal JS

### Task 4: Add `showIpSessionModal` method in `app.js`

**Files:**
- Modify: `static/js/app.js` — add new method + update session table eye buttons

- [ ] **Step 1: Add `showIpSessionModal` method**

Add this method in `app.js` after `showPacketDetails` (in the modal/utilities section):

```javascript
showIpSessionModal(pivotIp, sessionIdx) {
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
    const topDsts = Object.entries(dstCounts).sort((a,b) => b[1]-a[1]).slice(0,5);

    const uniqueProtos = Object.keys(protoCounts).join(', ') || 'TCP';

    const html = `
    <div class="osi-modal-header">
        <span style="font-size:1.1rem">🔍</span>
        <div>
            <div style="font-weight:700;font-size:1rem"><code>${pivotIp}</code></div>
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
            ${related.length} session(s) impliquant <strong>${pivotIp}</strong>
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
            ${related.map(s => {
                const srcIp = (s.src || '').split(':')[0];
                const dstIp = (s.dst || '').split(':')[0];
                const isOut = srcIp === pivotIp;
                const remoteIp = isOut ? dstIp : srcIp;
                const remotePort = isOut ? (s.dst || '').split(':')[1] : (s.src || '').split(':')[1];
                return `<tr>
                    <td><span class="direction-badge ${isOut ? 'direction-out' : 'direction-in'}">${isOut ? '↗' : '↙'}</span></td>
                    <td><code>${remoteIp || '-'}</code></td>
                    <td><code>${remotePort || '-'}</code></td>
                    <td><span class="state-badge ${s.state || ''}">${s.state || '-'}</span></td>
                    <td>${s.packets || 0}</td>
                    <td>${s.retransmissions || 0}</td>
                    <td>
                        <button class="action-btn" style="font-size:0.72rem;padding:0.25rem 0.5rem"
                            onclick="analyzer.filterByIpFromModal('${pivotIp}')">
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
        // Protocol donut
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
        // Dst bar
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
                    itemStyle: { color: new echarts.graphic.LinearGradient(1,0,0,0,[{offset:0,color:'#06b6d4'},{offset:1,color:'#8b5cf6'}]) }
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
```

- [ ] **Step 2: Update session table eye buttons to call `showIpSessionModal`**

In `populateSessionsTable` (~line 2175), replace:
```javascript
<button class="action-btn view" onclick="analyzer.showStreamDetails(${idx})">👁️</button>
```
with:
```javascript
<button class="action-btn view" onclick="analyzer.showIpSessionModal('${(session.src||'').split(':')[0]}', ${idx})">👁️</button>
```

In `loadStreams` (~line 920), replace:
```javascript
<button class="action-btn view" onclick="analyzer.showStreamDetails(${idx})">👁️ Voir</button>
```
with:
```javascript
<button class="action-btn view" onclick="analyzer.showIpSessionModal('${(session.src||'').split(':')[0]}', ${idx})">👁️ Analyser IP</button>
```

- [ ] **Step 3: Manual test in browser**

1. Go to Vue Globale tab → Sessions table
2. Click the eye icon on any session row
3. Modal should open with IP header, 4 stat cards, 2 mini charts, sessions table
4. Click "Voir paquets" → modal closes, Paquets tab opens with IP pre-filled in filter
5. Same test from Streams tab

---

## Chunk 5: Polish & edge cases

### Task 5: Edge cases + UX polish

**Files:**
- Modify: `static/js/app.js`

- [ ] **Step 1: Handle modal reuse for `initChart` — dispose old charts when modal closes**

The `closeModal` method must dispose any ECharts instances created inside modals to avoid memory leaks and ID conflicts when the modal is reopened.

Find `closeModal()` in `app.js` and update it:

```javascript
closeModal() {
    const modal = document.getElementById('detailModal');
    if (modal) modal.classList.remove('open');
    // Dispose any modal-scoped ECharts instances
    ['ipModalProtoChart', 'ipModalDstChart'].forEach(id => {
        const dom = document.getElementById(id);
        if (dom) {
            const inst = echarts.getInstanceByDom(dom);
            if (inst) inst.dispose();
        }
    });
}
```

- [ ] **Step 2: Graceful degradation when no OSI layer data**

The `showPacketDetails` already shows "Aucune donnée disponible" per layer when the PCAP is gone. Verify by calling the endpoint with a deleted PCAP: only `basic_info` fields should appear in L3/L4, all others show the fallback message.

- [ ] **Step 3: Verify no JS errors in console**

Open DevTools, reproduce all flows:
- Packet modal open/close/reopen
- IP session modal open/close/reopen
- Switch tabs after closing modals
- No `Cannot read properties of undefined` errors

---

## Summary

| Task | Backend | Frontend | Est. complexity |
|------|---------|----------|-----------------|
| 1 — Extract OSI layers (backend) | `routes.py` | — | Medium |
| 2 — OSI CSS | — | `index.html` | Low |
| 3 — OSI accordion modal | — | `app.js` | Medium |
| 4 — IP session modal | — | `app.js` | Medium |
| 5 — Polish + edge cases | — | `app.js` | Low |

No new files created. All changes are additive (no existing functionality removed, stream view still reachable via `showStreamDetails`).
