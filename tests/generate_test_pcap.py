"""
Script pour générer un fichier PCAP de test
Utilise Scapy pour créer un trafic réseau réaliste
"""

import sys
from pathlib import Path

# Ajouter le chemin du projet
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from scapy.all import (
        Ether, IP, TCP, UDP, ICMP, Raw,
        wrpcap, RandMAC, RandIP, RandShort
    )
except ImportError:
    print("Scapy n'est pas installé. Installez-le avec: pip install scapy")
    sys.exit(1)

import random
import time


def generate_tcp_handshake(src_ip, dst_ip, src_port, dst_port, base_time):
    """Génère un handshake TCP complet (SYN, SYN-ACK, ACK)"""
    packets = []
    seq = random.randint(1000, 100000)
    ack = random.randint(1000, 100000)
    
    # SYN
    syn = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(
        sport=src_port, dport=dst_port, flags='S', seq=seq
    )
    syn.time = base_time
    packets.append(syn)
    
    # SYN-ACK
    syn_ack = Ether()/IP(src=dst_ip, dst=src_ip)/TCP(
        sport=dst_port, dport=src_port, flags='SA', seq=ack, ack=seq+1
    )
    syn_ack.time = base_time + 0.001
    packets.append(syn_ack)
    
    # ACK
    ack_pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(
        sport=src_port, dport=dst_port, flags='A', seq=seq+1, ack=ack+1
    )
    ack_pkt.time = base_time + 0.002
    packets.append(ack_pkt)
    
    return packets


def generate_tcp_data_transfer(src_ip, dst_ip, src_port, dst_port, base_time, num_packets=10):
    """Génère des paquets de transfert de données TCP"""
    packets = []
    seq = random.randint(1000, 100000)
    
    for i in range(num_packets):
        pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(
            sport=src_port, dport=dst_port, flags='PA', seq=seq + i*100
        )/Raw(load=b'X' * random.randint(100, 1400))
        pkt.time = base_time + i * 0.01
        packets.append(pkt)
    
    return packets


def generate_tcp_fin(src_ip, dst_ip, src_port, dst_port, base_time):
    """Génère une terminaison TCP propre"""
    packets = []
    
    # FIN
    fin = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(
        sport=src_port, dport=dst_port, flags='FA'
    )
    fin.time = base_time
    packets.append(fin)
    
    # FIN-ACK
    fin_ack = Ether()/IP(src=dst_ip, dst=src_ip)/TCP(
        sport=dst_port, dport=src_port, flags='FA'
    )
    fin_ack.time = base_time + 0.001
    packets.append(fin_ack)
    
    return packets


def generate_tcp_rst(src_ip, dst_ip, src_port, dst_port, base_time):
    """Génère un RST TCP"""
    rst = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(
        sport=src_port, dport=dst_port, flags='R'
    )
    rst.time = base_time
    return [rst]


def generate_udp_traffic(src_ip, dst_ip, src_port, dst_port, base_time, num_packets=5):
    """Génère du trafic UDP"""
    packets = []
    
    for i in range(num_packets):
        pkt = Ether()/IP(src=src_ip, dst=dst_ip)/UDP(
            sport=src_port, dport=dst_port
        )/Raw(load=b'UDP Data ' + str(i).encode())
        pkt.time = base_time + i * 0.005
        packets.append(pkt)
    
    return packets


def generate_icmp_traffic(src_ip, dst_ip, base_time, num_pings=3):
    """Génère du trafic ICMP (ping)"""
    packets = []
    
    for i in range(num_pings):
        # Echo Request
        request = Ether()/IP(src=src_ip, dst=dst_ip)/ICMP(type=8, code=0)
        request.time = base_time + i * 0.1
        packets.append(request)
        
        # Echo Reply
        reply = Ether()/IP(src=dst_ip, dst=src_ip)/ICMP(type=0, code=0)
        reply.time = base_time + i * 0.1 + 0.01
        packets.append(reply)
    
    return packets


def generate_port_scan(src_ip, dst_ip, base_time, num_ports=30):
    """Génère un scan de ports (SYN scan)"""
    packets = []
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080]
    ports = common_ports + [random.randint(1024, 65535) for _ in range(num_ports - len(common_ports))]
    
    for i, port in enumerate(ports[:num_ports]):
        syn = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(
            sport=random.randint(40000, 60000), dport=port, flags='S'
        )
        syn.time = base_time + i * 0.001
        packets.append(syn)
    
    return packets


def generate_syn_flood_sample(attacker_ip, victim_ip, base_time, num_syns=50):
    """Génère un échantillon de SYN flood"""
    packets = []
    
    for i in range(num_syns):
        syn = Ether()/IP(src=attacker_ip, dst=victim_ip)/TCP(
            sport=random.randint(1024, 65535), dport=80, flags='S'
        )
        syn.time = base_time + i * 0.001
        packets.append(syn)
    
    return packets


def generate_test_pcap(output_path: str = 'tests/test_sample.pcap'):
    """
    Génère un fichier PCAP de test avec différents types de trafic
    """
    print("Génération du fichier PCAP de test...")
    
    all_packets = []
    base_time = time.time()
    
    # Définition des IPs
    client1 = '192.168.1.100'
    client2 = '192.168.1.101'
    server_web = '10.0.0.1'
    server_db = '10.0.0.2'
    attacker = '203.0.113.50'
    dns_server = '8.8.8.8'
    
    print("  - Génération de sessions TCP normales...")
    
    # Session 1: HTTP normale
    t = 0
    all_packets.extend(generate_tcp_handshake(client1, server_web, 50001, 80, base_time + t))
    t += 0.01
    all_packets.extend(generate_tcp_data_transfer(client1, server_web, 50001, 80, base_time + t, 20))
    t += 0.3
    all_packets.extend(generate_tcp_fin(client1, server_web, 50001, 80, base_time + t))
    
    # Session 2: HTTPS normale
    t += 0.1
    all_packets.extend(generate_tcp_handshake(client1, server_web, 50002, 443, base_time + t))
    t += 0.01
    all_packets.extend(generate_tcp_data_transfer(client1, server_web, 50002, 443, base_time + t, 30))
    t += 0.5
    all_packets.extend(generate_tcp_fin(client1, server_web, 50002, 443, base_time + t))
    
    # Session 3: Connexion base de données
    t += 0.2
    all_packets.extend(generate_tcp_handshake(client2, server_db, 50003, 3306, base_time + t))
    t += 0.01
    all_packets.extend(generate_tcp_data_transfer(client2, server_db, 50003, 3306, base_time + t, 15))
    
    print("  - Génération de sessions avec RST...")
    
    # Session 4: Connexion rejetée (RST)
    t += 0.5
    all_packets.extend(generate_tcp_handshake(client1, server_web, 50004, 8080, base_time + t))
    t += 0.02
    all_packets.extend(generate_tcp_rst(server_web, client1, 8080, 50004, base_time + t))
    
    print("  - Génération de trafic UDP (DNS)...")
    
    # Trafic UDP (DNS-like)
    t += 0.1
    all_packets.extend(generate_udp_traffic(client1, dns_server, 53421, 53, base_time + t, 10))
    t += 0.2
    all_packets.extend(generate_udp_traffic(client2, dns_server, 53422, 53, base_time + t, 8))
    
    print("  - Génération de trafic ICMP...")
    
    # Trafic ICMP
    t += 0.3
    all_packets.extend(generate_icmp_traffic(client1, server_web, base_time + t, 5))
    all_packets.extend(generate_icmp_traffic(client2, server_db, base_time + t + 0.1, 3))
    
    print("  - Génération d'un échantillon de port scan...")
    
    # Port scan (simulant une reconnaissance)
    t += 1
    all_packets.extend(generate_port_scan(attacker, server_web, base_time + t, 25))
    
    print("  - Génération de quelques SYN suspects...")
    
    # Quelques SYN suspects (petit échantillon pour détection)
    t += 2
    all_packets.extend(generate_syn_flood_sample(attacker, server_web, base_time + t, 30))
    
    # Trier par timestamp
    all_packets.sort(key=lambda p: p.time)
    
    # Écrire le fichier PCAP
    output_file = Path(__file__).parent.parent / output_path
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    wrpcap(str(output_file), all_packets)
    
    print(f"\n✅ Fichier PCAP généré: {output_file}")
    print(f"   Nombre de paquets: {len(all_packets)}")
    print(f"   Taille: {output_file.stat().st_size / 1024:.2f} KB")
    
    return str(output_file)


if __name__ == '__main__':
    generate_test_pcap()
