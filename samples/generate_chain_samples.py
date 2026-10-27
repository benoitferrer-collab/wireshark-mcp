#!/usr/bin/env python3
"""
Génère 3 captures PCAP d'une même chaîne réseau, pour tester l'analyse
multi-PCAP (bande passante, appariement paquet, goulot d'étranglement).

    python3 samples/generate_chain_samples.py

Topologie simulée :

    Postes clients ── [1] SW_LAN ── [2] FW_DMZ ── [3] RTR_WAN ── Internet

Défauts INJECTÉS (vérité terrain, à retrouver dans l'application) :

  Segment SW_LAN -> FW_DMZ   : +45 ms de mise en file d'attente, AUCUNE perte
                               => signature SHAPING (bufferbloat)
  Segment FW_DMZ -> RTR_WAN  : 11 % de pertes, délai quasi nul
                               => signature POLICING (rate-limiter)

  Horloges désynchronisées   : SW_LAN 0 s, FW_DMZ +2,5 s, RTR_WAN -1,25 s
                               => l'app doit annoncer des délais RELATIFS

Comportements par flux (pour la classification « pourquoi c'est lent ») :
  - flux HTTPS sains                 -> transfert normal
  - flux avec fenêtre nulle répétée  -> limité par le récepteur
  - flux avec retransmissions        -> limité par le réseau
  - flux SMB / HTTP / DNS            -> variété protocolaire
"""

import random
import struct
from pathlib import Path

random.seed(20260802)

OUT_DIR = Path(__file__).resolve().parent
T0 = 1_764_600_000.0  # 2025-12-01 ~14:00 UTC

# Décalage d'horloge de chaque sonde (secondes)
CLOCK_SKEW = {"SW_LAN": 0.0, "FW_DMZ": +2.5, "RTR_WAN": -1.25}

# Segment 1 : file d'attente (shaping) — délai variable, pas de perte
SEG1_BASE_DELAY = 0.0015
SEG1_QUEUE_MAX = 0.045
SEG1_LOSS = 0.0

# Segment 2 : rate-limiter (policing) — pertes, délai stable
SEG2_BASE_DELAY = 0.0020
SEG2_JITTER = 0.0008
SEG2_LOSS = 0.11

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
WSCALE_SHIFT = 7


# ----------------------------------------------------------------------
# Construction des paquets (écriture pcap directe : rapide et sans scapy)
# ----------------------------------------------------------------------

def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ip(addr: str) -> bytes:
    return bytes(int(x) for x in addr.split("."))


def build_tcp(src, dst, sport, dport, seq, ack, flags, window, payload=b"",
              ip_id=0, ttl=64, with_options=False, mss=1460):
    """Paquet Ethernet/IPv4/TCP complet, sommes de contrôle valides."""
    opts = b""
    if with_options:
        opts = (struct.pack("!BBH", 2, 4, mss)          # MSS
                + struct.pack("!BBB", 3, 3, WSCALE_SHIFT)  # Window Scale
                + struct.pack("!BB", 4, 2)              # SACK permitted
                + b"\x01\x00")                          # NOP + EOL (alignement)
    data_offset = (20 + len(opts)) // 4

    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                      data_offset << 4, flags, window, 0, 0) + opts
    src_b, dst_b = _ip(src), _ip(dst)

    pseudo = src_b + dst_b + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    csum = _checksum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack("!H", csum) + tcp[18:]

    total_len = 20 + len(tcp) + len(payload)
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ip_id & 0xFFFF,
                         0x4000, ttl, 6, 0, src_b, dst_b)
    ip_hdr = ip_hdr[:10] + struct.pack("!H", _checksum(ip_hdr)) + ip_hdr[12:]

    eth = b"\x00\x50\x56\xa1\xb2\xc3" + b"\x00\x1b\x21\x44\x55\x66" + b"\x08\x00"
    return eth + ip_hdr + tcp + payload


def build_udp(src, dst, sport, dport, payload, ip_id=0, ttl=64):
    udp_len = 8 + len(payload)
    src_b, dst_b = _ip(src), _ip(dst)
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0) + payload
    pseudo = src_b + dst_b + struct.pack("!BBH", 0, 17, udp_len)
    csum = _checksum(pseudo + udp) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", csum) + udp[8:]

    total_len = 20 + udp_len
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ip_id & 0xFFFF,
                         0x4000, ttl, 17, 0, src_b, dst_b)
    ip_hdr = ip_hdr[:10] + struct.pack("!H", _checksum(ip_hdr)) + ip_hdr[12:]
    eth = b"\x00\x50\x56\xa1\xb2\xc3" + b"\x00\x1b\x21\x44\x55\x66" + b"\x08\x00"
    return eth + ip_hdr + udp


def dns_query(name: str, txid: int) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


def dns_response(name: str, txid: int, ip: str) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    header = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    question = q + struct.pack("!HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + _ip(ip)
    return header + question + answer


def write_pcap(path: Path, records):
    records.sort(key=lambda r: r[0])
    with open(path, "wb") as f:
        f.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, raw in records:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000)) % 1_000_000
            f.write(struct.pack("!IIII", sec, usec, len(raw), len(raw)))
            f.write(raw)


# ----------------------------------------------------------------------
# Scénarios de trafic
# ----------------------------------------------------------------------

class Chain:
    """Rejoue chaque paquet aux 3 points de capture, avec délais et pertes."""

    def __init__(self):
        self.a, self.b, self.c = [], [], []
        self.ip_id = 1000

    def next_id(self) -> int:
        self.ip_id = (self.ip_id + 1) % 65535
        return self.ip_id

    def emit(self, ts: float, raw: bytes, protected: bool = False):
        """protected=True : paquet jamais perdu (handshake, DNS, contrôle)."""
        self.a.append((ts + CLOCK_SKEW["SW_LAN"], raw))

        # Segment 1 : mise en file d'attente croissante, aucune perte
        queue = random.random() ** 2 * SEG1_QUEUE_MAX
        ts_b = ts + SEG1_BASE_DELAY + queue
        if not protected and random.random() < SEG1_LOSS:
            return
        self.b.append((ts_b + CLOCK_SKEW["FW_DMZ"], raw))

        # Segment 2 : rate-limiter, pertes franches, délai stable
        ts_c = ts_b + SEG2_BASE_DELAY + random.uniform(0, SEG2_JITTER)
        if not protected and random.random() < SEG2_LOSS:
            return
        self.c.append((ts_c + CLOCK_SKEW["RTR_WAN"], raw))


def tcp_transfer(chain: Chain, start: float, client: str, cport: int, server: str,
                 sport: int, segments: int, mss: int = 1460, rtt: float = 0.024,
                 pacing: float = 0.0018, zero_window_at=None, retrans_at=None,
                 client_window: int = 501, app_gap: float = 0.0):
    """Un transfert TCP descendant complet (handshake, données, ACKs, FIN)."""
    t = start
    seq_c = random.randint(1_000_000, 9_000_000)
    seq_s = random.randint(1_000_000, 9_000_000)

    # Handshake — protégé pour que la session reste corrélable partout
    chain.emit(t, build_tcp(client, server, cport, sport, seq_c, 0, SYN, 64240,
                            ip_id=chain.next_id(), with_options=True, mss=mss), protected=True)
    chain.emit(t + rtt / 2, build_tcp(server, client, sport, cport, seq_s, seq_c + 1,
                                      SYN | ACK, 65535, ip_id=chain.next_id(),
                                      ttl=57, with_options=True, mss=mss), protected=True)
    chain.emit(t + rtt, build_tcp(client, server, cport, sport, seq_c + 1, seq_s + 1,
                                  ACK, client_window, ip_id=chain.next_id()), protected=True)

    t += rtt + 0.004
    s_seq = seq_s + 1
    zero_window_at = set(zero_window_at or [])
    retrans_at = set(retrans_at or [])

    for i in range(segments):
        payload = bytes([(i * 7 + 13) % 251]) * mss
        chain.emit(t, build_tcp(server, client, sport, cport, s_seq, seq_c + 1,
                                PSH | ACK, 512, payload, ip_id=chain.next_id(), ttl=57))

        # Retransmission : même seq renvoyé un peu plus tard
        if i in retrans_at:
            chain.emit(t + 0.28, build_tcp(server, client, sport, cport, s_seq, seq_c + 1,
                                           PSH | ACK, 512, payload,
                                           ip_id=chain.next_id(), ttl=57))

        s_seq += mss
        t += pacing

        if i % 4 == 3:
            # Fenêtre nulle : le récepteur ne draine plus (limité par le récepteur)
            win = 0 if i in zero_window_at else client_window
            chain.emit(t, build_tcp(client, server, cport, sport, seq_c + 1, s_seq,
                                    ACK, win, ip_id=chain.next_id()), protected=(win == 0))
            if win == 0:
                t += 0.22  # pause de persistance
                chain.emit(t, build_tcp(client, server, cport, sport, seq_c + 1, s_seq,
                                        ACK, client_window, ip_id=chain.next_id()),
                           protected=True)
        if app_gap and i % 25 == 24:
            t += app_gap  # l'émetteur se tait (limité par l'application)

    # Clôture
    chain.emit(t, build_tcp(server, client, sport, cport, s_seq, seq_c + 1,
                            FIN | ACK, 512, ip_id=chain.next_id(), ttl=57), protected=True)
    chain.emit(t + rtt / 2, build_tcp(client, server, cport, sport, seq_c + 1, s_seq + 1,
                                      FIN | ACK, client_window, ip_id=chain.next_id()),
               protected=True)


def main():
    chain = Chain()

    # --- Flux HTTPS sains : gros transferts, référence de débit ---
    for i in range(4):
        tcp_transfer(chain, start=T0 + 0.5 + i * 1.7,
                     client=f"10.20.30.{40 + i}", cport=49500 + i,
                     server="203.0.113.25", sport=443,
                     segments=110, rtt=0.022 + i * 0.003)

    # --- Flux limités par le RÉCEPTEUR : fenêtre nulle répétée ---
    for i in range(2):
        tcp_transfer(chain, start=T0 + 8.0 + i * 2.0,
                     client=f"10.20.30.{60 + i}", cport=51200 + i,
                     server="203.0.113.25", sport=443,
                     segments=90, rtt=0.020,
                     zero_window_at={11, 23, 35, 47, 59, 71},
                     client_window=96)

    # --- Flux limités par le RÉSEAU : retransmissions marquées ---
    for i in range(2):
        tcp_transfer(chain, start=T0 + 13.0 + i * 1.5,
                     client=f"10.20.30.{80 + i}", cport=52300 + i,
                     server="198.51.100.77", sport=443,
                     segments=95, rtt=0.055,
                     retrans_at=set(range(3, 95, 6)))

    # --- Flux limité par l'APPLICATION : émetteur qui marque des pauses ---
    tcp_transfer(chain, start=T0 + 17.0, client="10.20.30.95", cport=53400,
                 server="203.0.113.25", sport=443, segments=80,
                 rtt=0.018, pacing=0.0022, app_gap=0.45)

    # --- Trafic HTTP en clair (visible dans l'analyse applicative) ---
    for i in range(2):
        t = T0 + 20.0 + i * 1.2
        c, cp = f"10.20.30.{110 + i}", 54100 + i
        srv = "203.0.113.90"
        seq_c, seq_s = 500000 + i, 900000 + i
        chain.emit(t, build_tcp(c, srv, cp, 80, seq_c, 0, SYN, 64240,
                                ip_id=chain.next_id(), with_options=True), protected=True)
        chain.emit(t + 0.012, build_tcp(srv, c, 80, cp, seq_s, seq_c + 1, SYN | ACK,
                                        65535, ip_id=chain.next_id(), ttl=56,
                                        with_options=True), protected=True)
        chain.emit(t + 0.024, build_tcp(c, srv, cp, 80, seq_c + 1, seq_s + 1, ACK, 501,
                                        ip_id=chain.next_id()), protected=True)
        req = (f"GET /rapports/trimestre-{i + 1}.pdf HTTP/1.1\r\n"
               f"Host: intranet.exemple.fr\r\n"
               f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
               f"Accept: */*\r\n\r\n").encode()
        chain.emit(t + 0.026, build_tcp(c, srv, cp, 80, seq_c + 1, seq_s + 1,
                                        PSH | ACK, 501, req, ip_id=chain.next_id()))
        resp = (b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"
                b"Content-Type: application/pdf\r\nContent-Length: 62000\r\n\r\n")
        chain.emit(t + 0.05, build_tcp(srv, c, 80, cp, seq_s + 1, seq_c + 1 + len(req),
                                       PSH | ACK, 512, resp, ip_id=chain.next_id(), ttl=56))
        s_seq = seq_s + 1 + len(resp)
        for k in range(42):
            chain.emit(t + 0.055 + k * 0.0016,
                       build_tcp(srv, c, 80, cp, s_seq, seq_c + 1 + len(req), PSH | ACK,
                                 512, bytes([k % 251]) * 1460,
                                 ip_id=chain.next_id(), ttl=56))
            s_seq += 1460

    # --- Partage de fichiers SMB (protocole entreprise) ---
    t = T0 + 24.0
    seq_c, seq_s = 300000, 700000
    chain.emit(t, build_tcp("10.20.30.41", "10.20.40.10", 55200, 445, seq_c, 0, SYN,
                            64240, ip_id=chain.next_id(), with_options=True), protected=True)
    chain.emit(t + 0.002, build_tcp("10.20.40.10", "10.20.30.41", 445, 55200, seq_s,
                                    seq_c + 1, SYN | ACK, 65535, ip_id=chain.next_id(),
                                    ttl=63, with_options=True), protected=True)
    chain.emit(t + 0.004, build_tcp("10.20.30.41", "10.20.40.10", 55200, 445, seq_c + 1,
                                    seq_s + 1, ACK, 501, ip_id=chain.next_id()), protected=True)
    smb = b"\x00\x00\x00\x54\xfeSMB" + b"\x00" * 60 + b"partage-compta"
    s_seq = seq_s + 1
    for k in range(30):
        chain.emit(t + 0.006 + k * 0.0022,
                   build_tcp("10.20.40.10", "10.20.30.41", 445, 55200, s_seq, seq_c + 1,
                             PSH | ACK, 512, smb + bytes([k % 251]) * 1300,
                             ip_id=chain.next_id(), ttl=63))
        s_seq += len(smb) + 1300

    # --- Résolutions DNS (UDP) ---
    domaines = ["intranet.exemple.fr", "cdn.exemple.fr", "api.partenaire.net",
                "maj.editeur-logiciel.com", "telemetrie.service-cloud.io"]
    for i, nom in enumerate(domaines):
        ts = T0 + 2.0 + i * 3.4
        txid = 0x4000 + i
        chain.emit(ts, build_udp(f"10.20.30.{40 + (i % 4)}", "10.20.40.5",
                                 40000 + i, 53, dns_query(nom, txid),
                                 ip_id=chain.next_id()), protected=True)
        chain.emit(ts + 0.006, build_udp("10.20.40.5", f"10.20.30.{40 + (i % 4)}",
                                         53, 40000 + i,
                                         dns_response(nom, txid, f"203.0.113.{25 + i}"),
                                         ip_id=chain.next_id(), ttl=63), protected=True)

    fichiers = [
        ("1_SW_LAN.pcap", chain.a, "SW_LAN"),
        ("2_FW_DMZ.pcap", chain.b, "FW_DMZ"),
        ("3_RTR_WAN.pcap", chain.c, "RTR_WAN"),
    ]
    print("Captures générées dans", OUT_DIR)
    for nom, recs, equip in fichiers:
        write_pcap(OUT_DIR / nom, recs)
        taille = (OUT_DIR / nom).stat().st_size
        print(f"  {nom:18s} {len(recs):6d} paquets  {taille / 1024:8.1f} Ko  (équipement « {equip} »)")

    perdus_1 = len(chain.a) - len(chain.b)
    perdus_2 = len(chain.b) - len(chain.c)
    print(f"\nPertes injectées : SW_LAN->FW_DMZ = {perdus_1} paquets, "
          f"FW_DMZ->RTR_WAN = {perdus_2} paquets "
          f"({perdus_2 / max(1, len(chain.b)) * 100:.1f} %)")


if __name__ == "__main__":
    main()
