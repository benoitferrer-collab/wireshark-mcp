"""Tests unitaires du service multi-PCAP."""

from app.services.multi_pcap_service import MultiPcapAnalysisService


def test_score_match_strong_when_same_service_and_overlap():
    service = MultiPcapAnalysisService()

    left = {
        "protocol": "TCP",
        "service_port": 443,
        "participant_ips": ["10.0.0.10", "194.9.97.193"],
        "participant_ports": [52344, 443],
        "server_ip": "194.9.97.193",
        "client_ip": "10.0.0.10",
        "packet_count": 100,
        "duration_seconds": 1.2,
        "reference_ts": 10.0,
        "tcp_metrics": {"syn": 1, "rst": 0},
    }
    right = {
        "protocol": "TCP",
        "service_port": 443,
        "participant_ips": ["10.0.0.10", "194.9.97.193"],
        "participant_ports": [52344, 443],
        "server_ip": "194.9.97.193",
        "client_ip": "10.0.0.10",
        "packet_count": 90,
        "duration_seconds": 1.1,
        "reference_ts": 10.4,
        "tcp_metrics": {"syn": 1, "rst": 0},
    }

    score = service._score_match(left, right, time_tolerance=5.0)
    assert score >= 70


def test_detect_hop_changes_finds_nat_and_mss_shift():
    service = MultiPcapAnalysisService()

    capture_points = [
        {"equipment_name": "fw-1"},
        {"equipment_name": "lb-1"},
    ]
    by_capture = {
        0: {
            "client_ip": "10.0.0.10",
            "server_ip": "194.9.97.193",
            "client_port": 52344,
            "server_port": 443,
            "ttl": {"avg": 63},
            "dscp_values": [0],
            "vlan_ids": [10],
            "packet_count": 100,
            "tcp_metrics": {
                "mss_values": [1460],
                "window": {"avg": 65535},
                "retrans_ratio": 0.0,
                "rst": 0,
                "sack_seen": True,
                "timestamp_seen": True,
            },
        },
        1: {
            "client_ip": "172.16.0.5",
            "server_ip": "194.9.97.193",
            "client_port": 61000,
            "server_port": 443,
            "ttl": {"avg": 51},
            "dscp_values": [8],
            "vlan_ids": [20],
            "packet_count": 70,
            "tcp_metrics": {
                "mss_values": [1360],
                "window": {"avg": 32000},
                "retrans_ratio": 0.12,
                "rst": 1,
                "sack_seen": False,
                "timestamp_seen": True,
            },
        },
    }

    changes = service._detect_hop_changes(capture_points, by_capture)
    change_types = {c["type"] for c in changes}

    assert "ip_rewrite" in change_types
    assert "port_rewrite" in change_types
    assert "mss_change" in change_types
    assert "retrans_increase" in change_types


def test_latency_estimation_builds_segments_and_confidence():
    service = MultiPcapAnalysisService()

    capture_points = [
        {"equipment_name": "fw", "capture_index": 0},
        {"equipment_name": "proxy", "capture_index": 1},
    ]

    sessions = []
    for i in range(10):
        base = 1000.0 + i
        sessions.append({
            "hops": [
                {"capture_index": 0, "reference_ts": base},
                {"capture_index": 1, "reference_ts": base + 5.010 + (i * 0.0005)},
            ]
        })

    latency = service._estimate_latency(capture_points, sessions)

    assert latency["segments"]
    seg = latency["segments"][0]
    assert seg["sample_count"] == 10
    assert "latency_ms" in seg
    assert latency["global_confidence"] in {"LOW", "MEDIUM", "HIGH"}


def test_root_cause_scoring_flags_nat_suspect():
    service = MultiPcapAnalysisService()

    changes = [
        {"type": "ip_rewrite", "severity": "MEDIUM"},
        {"type": "port_rewrite", "severity": "MEDIUM"},
    ]
    by_capture = {
        0: {
            "state": "ESTABLISHED",
            "client_ip": "10.0.0.10",
            "client_port": 52344,
            "server_ip": "194.9.97.193",
            "server_port": 443,
            "packet_count": 120,
            "duration_seconds": 2.1,
            "tcp_metrics": {
                "rst": 0,
                "retrans_ratio": 0.0,
                "dup_acks": 0,
                "out_of_order": 0,
                "mss_values": [1460],
                "window": {"avg": 65535},
            },
        },
        1: {
            "state": "ESTABLISHED",
            "client_ip": "172.16.10.15",
            "client_port": 61123,
            "server_ip": "194.9.97.193",
            "server_port": 443,
            "packet_count": 118,
            "duration_seconds": 2.0,
            "tcp_metrics": {
                "rst": 0,
                "retrans_ratio": 0.0,
                "dup_acks": 0,
                "out_of_order": 0,
                "mss_values": [1460],
                "window": {"avg": 64000},
            },
        },
    }

    risk = service._derive_risk_and_cause(changes, by_capture, total_capture_points=2)
    codes = [s.get("code") for s in risk.get("root_cause_signals", [])]

    assert "nat-suspect" in codes
    assert risk["probable_cause_code"] == "nat-suspect"
    assert risk["risk_score"] >= 40


def test_root_cause_scoring_flags_mtu_blackhole_and_asymmetry():
    service = MultiPcapAnalysisService()

    changes = [
        {"type": "mss_change", "severity": "HIGH"},
        {"type": "retrans_increase", "severity": "HIGH"},
        {"type": "disappearance", "severity": "HIGH"},
        {"type": "appearance", "severity": "MEDIUM"},
    ]
    by_capture = {
        0: {
            "state": "ESTABLISHED",
            "client_ip": "10.0.0.10",
            "client_port": 53210,
            "server_ip": "194.9.97.193",
            "server_port": 443,
            "packet_count": 210,
            "duration_seconds": 1.2,
            "tcp_metrics": {
                "rst": 0,
                "retrans_ratio": 0.01,
                "dup_acks": 1,
                "out_of_order": 0,
                "mss_values": [1460],
                "window": {"avg": 65535},
            },
        },
        2: {
            "state": "SYN_ONLY",
            "client_ip": "10.0.0.10",
            "client_port": 53210,
            "server_ip": "194.9.97.193",
            "server_port": 443,
            "packet_count": 75,
            "duration_seconds": 4.5,
            "tcp_metrics": {
                "rst": 0,
                "retrans_ratio": 0.11,
                "dup_acks": 4,
                "out_of_order": 2,
                "mss_values": [1280],
                "window": {"avg": 28000},
            },
        },
    }

    risk = service._derive_risk_and_cause(changes, by_capture, total_capture_points=3)
    codes = {s.get("code") for s in risk.get("root_cause_signals", [])}

    assert "mtu-blackhole" in codes
    assert "asymmetry" in codes
    assert risk["risk_score"] >= 70


def test_segment_degradation_picks_primary_trigger_segment():
    service = MultiPcapAnalysisService()

    session = {
        "probable_cause_code": "mtu-blackhole",
        "root_cause_signals": [{"code": "mtu-blackhole", "severity": "HIGH", "weight": 34}],
        "hops": [
            {"capture_index": 0, "equipment_name": "fw", "tcp_metrics": {"retransmissions": 1, "rst": 0}},
            {"capture_index": 1, "equipment_name": "proxy", "tcp_metrics": {"retransmissions": 7, "rst": 0}},
            {"capture_index": 2, "equipment_name": "lb", "tcp_metrics": {"retransmissions": 2, "rst": 0}},
        ],
        "changes": [
            {
                "hop": "fw -> proxy",
                "type": "mss_change",
                "severity": "HIGH",
                "description": "MSS changé 1460 -> 1280",
            },
            {
                "hop": "fw -> proxy",
                "type": "retrans_increase",
                "severity": "HIGH",
                "description": "Retransmissions en hausse",
            },
        ],
        "latency_by_hop": [
            {"segment": "fw -> proxy", "from_capture_index": 0, "to_capture_index": 1, "latency_ms": 143.4, "confidence": "HIGH"},
            {"segment": "proxy -> lb", "from_capture_index": 1, "to_capture_index": 2, "latency_ms": 8.2, "confidence": "MEDIUM"},
        ],
    }

    segments, primary = service._derive_segment_degradation(session)

    assert segments
    assert primary is not None
    assert primary["segment"] == "fw -> proxy"
    assert bool(primary["triggered"]) is True
    assert int(primary["score"]) >= 70


# ----------------------------------------------------------------------
# Chaîne: bande passante, appariement paquet, goulot d'étranglement
# ----------------------------------------------------------------------


def _flow(client_port: int, packet_count: int = 100, reference_ts: float = 10.0):
    return {
        "protocol": "TCP",
        "service_port": 443,
        "participant_ips": ["10.0.0.10", "192.168.50.20"],
        "participant_ports": [client_port, 443],
        "server_ip": "192.168.50.20",
        "client_ip": "10.0.0.10",
        "client_port": client_port,
        "packet_count": packet_count,
        "duration_seconds": 1.2,
        "reference_ts": reference_ts,
        "tcp_metrics": {"syn": 1, "rst": 0},
    }


def test_score_match_prefers_exact_client_port_over_nat_bonus():
    """Régression: deux connexions d'un même poste vers un même serveur.

    Le bonus NAT se déclenchait sur un simple écart de port source et faisait
    gagner le MAUVAIS candidat (le port client est pourtant le signal
    d'identité le plus fort hors NAT).
    """
    service = MultiPcapAnalysisService()
    reference = _flow(40000)

    exact = service._score_match(reference, _flow(40000, packet_count=95, reference_ts=10.3), 5.0)
    other = service._score_match(reference, _flow(40001, packet_count=95, reference_ts=10.3), 5.0)

    assert exact > other, f"appariement exact ({exact}) doit primer sur l'autre flux ({other})"


def test_score_match_still_rewards_real_nat_rewrite():
    """Une vraie réécriture NAT (IP client différente) reste valorisée."""
    service = MultiPcapAnalysisService()
    left = _flow(40000)
    natted = _flow(40000)
    natted["client_ip"] = "203.0.113.7"
    natted["participant_ips"] = ["203.0.113.7", "192.168.50.20"]

    assert service._score_match(left, natted, 5.0) >= 60


def test_theoretical_limits_window_and_loss():
    service = MultiPcapAnalysisService()

    # 64 Ko de fenêtre sur 40 ms => ~13.1 Mb/s
    limits = service._theoretical_limits(rwnd_bytes=65536, rtt_ms=40.0, mss=1460, loss_ratio=0.0)
    assert 12.0 <= limits["window_limited_mbps"] <= 14.0
    assert limits["loss_limited_mbps"] is None
    assert limits["limiting_factor"] == "window"

    # Avec 1% de pertes, la borne de Mathis devient contraignante
    with_loss = service._theoretical_limits(rwnd_bytes=65536, rtt_ms=40.0, mss=1460, loss_ratio=0.01)
    assert with_loss["loss_limited_mbps"] is not None
    assert with_loss["limiting_factor"] == "loss"

    # RTT inconnu => aucune borne exploitable
    assert service._theoretical_limits(0, 0.0, 1460, 0.0)["limiting_factor"] is None


def test_direction_throughput_excludes_retransmitted_bytes_from_goodput():
    service = MultiPcapAnalysisService()
    dstat = {
        "wire_bytes": 150_000,
        "payload_bytes": 100_000,
        "retrans_payload_bytes": 20_000,
        "packets": 100,
        "bins": {10: [80_000, 50_000], 11: [70_000, 50_000]},
    }
    out = service._direction_throughput(dstat, duration=2.0)

    assert out["goodput_bytes"] == 80_000
    assert out["avg_mbps"] == round(150_000 * 8 / 2.0 / 1_000_000, 4)
    assert out["peak_mbps"] > out["avg_mbps"]  # pic sur la seconde la plus chargée
    assert out["active_seconds"] == 2


def test_direction_window_applies_scale_shift():
    service = MultiPcapAnalysisService()
    out = service._direction_window({
        "window_scale": 7,
        "eff_window_min": 8192,
        "eff_window_max": 65536,
        "eff_window_sum": 147456,
        "eff_window_count": 2,
        "zero_window_events": 3,
    })
    assert out["scale_shift"] == 7
    assert out["effective_max"] == 65536
    assert out["zero_window_events"] == 3


def test_classify_flow_limitation_detects_receiver_and_network():
    service = MultiPcapAnalysisService()

    receiver = service._classify_flow_limitation({"hops": [{
        "throughput": {"server_to_client": {"goodput_mbps": 2.0}},
        "windows": {"server_to_client": {"zero_window_events": 5}},
        "theoretical_limits": {},
        "tcp_metrics": {"retrans_ratio": 0.0},
    }]})
    assert receiver["class"] == "RECEIVER_LIMITED"

    network = service._classify_flow_limitation({"hops": [{
        "throughput": {"server_to_client": {"goodput_mbps": 2.0}},
        "windows": {"server_to_client": {"zero_window_events": 0}},
        "theoretical_limits": {},
        "tcp_metrics": {"retrans_ratio": 0.05},
    }]})
    assert network["class"] == "NETWORK_LIMITED"

    assert service._classify_flow_limitation({"hops": []})["class"] == "UNKNOWN"


def test_bottleneck_verdict_ranks_lossy_segment_first():
    service = MultiPcapAnalysisService()
    bandwidth = {"segments": [
        {"from_capture_index": 0, "to_capture_index": 1, "segment": "A -> B",
         "from_equipment": "A", "to_equipment": "B", "goodput_loss_pct": 0.0},
        {"from_capture_index": 1, "to_capture_index": 2, "segment": "B -> C",
         "from_equipment": "B", "to_equipment": "C", "goodput_loss_pct": 25.0},
    ]}
    packet_match = {"segments": [
        {"from_capture_index": 0, "to_capture_index": 1, "segment": "A -> B",
         "loss_ratio": 0.0, "relative_delay_ms": {"min": 0.0, "p95": 0.5},
         "queuing_jitter_ms": 0.5, "confidence": "HIGH"},
        {"from_capture_index": 1, "to_capture_index": 2, "segment": "B -> C",
         "loss_ratio": 0.09, "relative_delay_ms": {"min": 0.0, "p95": 4.0},
         "queuing_jitter_ms": 4.0, "confidence": "HIGH"},
    ]}

    verdicts = service._build_bottleneck_verdicts(bandwidth, packet_match)

    assert verdicts[0]["segment"] == "B -> C"
    assert verdicts[0]["bottleneck_score"] > verdicts[1]["bottleneck_score"]
    assert verdicts[0]["severity"] in {"HIGH", "MEDIUM"}
    # Pertes sans file d'attente => signature policing
    assert verdicts[0]["traffic_shaping_signature"] == "POLICING"


def test_bottleneck_verdict_flags_shaping_when_delay_without_loss():
    service = MultiPcapAnalysisService()
    verdicts = service._build_bottleneck_verdicts(
        {"segments": [{"from_capture_index": 0, "to_capture_index": 1, "segment": "A -> B",
                       "from_equipment": "A", "to_equipment": "B", "goodput_loss_pct": 0.0}]},
        {"segments": [{"from_capture_index": 0, "to_capture_index": 1, "segment": "A -> B",
                       "loss_ratio": 0.0, "relative_delay_ms": {"min": 2.0, "p95": 160.0},
                       "queuing_jitter_ms": 158.0, "confidence": "HIGH"}]},
    )
    assert verdicts[0]["traffic_shaping_signature"] == "SHAPING"
    assert any("bufferbloat" in r.lower() for r in verdicts[0]["recommendations"])


def test_packet_loss_raises_session_risk_and_names_segment():
    """Un flux qui perd des paquets sur un segment doit être remonté.

    Régression: les détecteurs historiques comparent des agrégats de session et
    laissaient « stable » un flux amputé de 10% de ses paquets.
    """
    service = MultiPcapAnalysisService()
    session = {
        "risk_score": 10,
        "problematic": False,
        "probable_cause": "Flux globalement stable",
        "probable_cause_code": "stable",
        "cause_details": "",
        "changes": [],
        "root_cause_signals": [],
        "hops": [
            {"capture_index": 0, "equipment_name": "B_firewall"},
            {"capture_index": 1, "equipment_name": "C_wan"},
        ],
        "packet_match_by_segment": [{
            "from_capture_index": 0, "to_capture_index": 1,
            "upstream_packets": 152, "lost_packets": 18, "loss_ratio": 0.1184,
        }],
    }

    service._apply_packet_loss_to_risk(session)

    assert session["problematic"] is True
    assert session["risk_score"] >= 45
    assert session["probable_cause_code"] == "packet_loss_segment"
    assert "B_firewall -> C_wan" in session["probable_cause"]
    assert "11.84%" in session["cause_details"]
    assert session["root_cause_signals"][0]["severity"] == "HIGH"
    assert session["changes"][0]["type"] == "packet_loss"


def test_negligible_packet_loss_leaves_session_untouched():
    service = MultiPcapAnalysisService()
    session = {
        "risk_score": 10, "problematic": False, "probable_cause": "Flux globalement stable",
        "probable_cause_code": "stable", "cause_details": "", "changes": [], "root_cause_signals": [],
        "hops": [], "packet_match_by_segment": [{
            "from_capture_index": 0, "to_capture_index": 1,
            "upstream_packets": 1000, "lost_packets": 3, "loss_ratio": 0.003,
        }],
    }

    service._apply_packet_loss_to_risk(session)

    assert session["risk_score"] == 10
    assert session["problematic"] is False
    assert session["probable_cause_code"] == "stable"


def test_packet_loss_realigns_trigger_segment():
    """Le « segment déclencheur » doit désigner le segment qui perd les paquets.

    L'heuristique de latence pouvait pointer un segment sain pendant que le
    verdict incriminait l'autre: deux panneaux se contredisaient à l'écran.
    """
    service = MultiPcapAnalysisService()
    session = {
        "risk_score": 10, "problematic": False, "probable_cause": "Flux globalement stable",
        "probable_cause_code": "stable", "cause_details": "", "changes": [], "root_cause_signals": [],
        "hops": [
            {"capture_index": 0, "equipment_name": "A_core"},
            {"capture_index": 1, "equipment_name": "B_firewall"},
            {"capture_index": 2, "equipment_name": "C_wan"},
        ],
        "degradation_segments": [
            {"segment": "A_core -> B_firewall", "from_capture_index": 0, "to_capture_index": 1,
             "score": 12, "severity": "LOW", "triggered": True, "reasons": [], "change_types": []},
            {"segment": "B_firewall -> C_wan", "from_capture_index": 1, "to_capture_index": 2,
             "score": 0, "severity": "LOW", "triggered": False, "reasons": [], "change_types": []},
        ],
        "degradation_primary": {"segment": "A_core -> B_firewall"},
        "packet_match_by_segment": [{
            "from_capture_index": 1, "to_capture_index": 2,
            "upstream_packets": 152, "lost_packets": 16, "loss_ratio": 0.1053,
        }],
    }

    service._apply_packet_loss_to_risk(session)

    assert session["degradation_primary"]["segment"] == "B_firewall -> C_wan"
    assert session["degradation_primary"]["triggered"] is True
    assert session["degradation_segments"][0]["segment"] == "B_firewall -> C_wan"
    assert "packet_loss" in session["degradation_primary"]["change_types"]
