# Design : Modal OSI L1-L7 & Modal IP Sessions

Date: 2026-03-10

## Contexte

L'application PCAP Analyzer Pro affiche des paquets et des sessions TCP. Actuellement :
- Clic œil sur paquet → raw JSON peu lisible
- Clic œil sur session → vue stream conversation (payload raw)

## Objectif

1. **Modal paquet OSI** : afficher toutes les informations d'un paquet structurées par couche OSI L1→L7 avec accordion coloré et dump hex
2. **Modal IP sessions** : clic sur une session → pivot sur l'IP source, affiche toutes les sessions/protocoles de cette IP avec mini-charts

---

## Feature 1 — Modal Paquet OSI L1-L7

### Backend

**Endpoint existant à enrichir** : `GET /api/analysis/{task_id}/packet/{packet_num}`

Ajouter une re-lecture Scapy du paquet depuis le fichier PCAP original (seek par index), extraire toutes les couches et retourner :

```json
{
  "packet_num": 42,
  "l1_physical": { "medium": "Ethernet", "capture_len": 74, "original_len": 74 },
  "l2_datalink": { "src_mac": "aa:bb:cc:dd:ee:ff", "dst_mac": "00:11:22:33:44:55", "ethertype": "0x0800 (IPv4)" },
  "l3_network": { "src_ip": "192.168.1.1", "dst_ip": "8.8.8.8", "ttl": 64, "version": 4, "ihl": 20, "tos": 0, "fragment_offset": 0, "checksum": "0x1a2b", "protocol_num": 6 },
  "l4_transport": { "protocol": "TCP", "src_port": 1337, "dst_port": 443, "seq": 1234567, "ack": 9876543, "window": 65535, "flags": ["SYN", "ACK"], "checksum": "0xabcd", "urgent": 0 },
  "l5_session": { "stream_id": null, "direction": null, "state": null },
  "l6_presentation": { "tls_version": null, "cipher_suite": null, "sni": null },
  "l7_application": { "protocol": "DNS", "detail": { "type": "query", "domain": "example.com", "qtype": "A" } },
  "raw_hex": "45 00 00 3c ...",
  "basic_info": { ... }
}
```

**Implémentation** :
- Récupérer `pcap_path` depuis `storage_service` (déjà disponible dans le contexte de la route)
- Utiliser `PcapReader` Scapy avec skip par index pour éviter de charger tout le fichier
- Si PCAP non disponible (supprimé), retourner uniquement les données de `packets_index` (graceful degradation)
- Enrichir `l5_session` depuis `results.tcp_analysis.sessions` en cherchant la paire src:port/dst:port
- Enrichir `l6_presentation` depuis `results.tls_analysis` si dispo

### Frontend

Remplacer `showPacketDetails()` et `togglePacketDetail()` par un modal accordion :

**Structure HTML du modal** :
```
[sticky header] Paquet #N · <badge proto> · src_ip → dst_ip
[accordion layers L1..L7]
  chaque layer = barre colorée cliquable + champs en grille
[collapsible hex dump]
```

**Couleurs par couche** :
- L1 Physical : `#64748b` (gris)
- L2 Data Link : `#3b82f6` (bleu)
- L3 Network : `#10b981` (vert)
- L4 Transport : `#f59e0b` (orange)
- L5 Session : `#eab308` (jaune)
- L6 Presentation : `#8b5cf6` (violet)
- L7 Application : `#06b6d4` (cyan)

**Comportement** :
- L1-L4 : ouvertes par défaut
- L5-L7 : ouvertes si données disponibles, grisées fermées sinon
- Raw hex : collapsible, monospace, groupes de 8 octets séparés par espace
- Clic sur ligne de table paquet (VirtualScroll) → ouvre ce modal (remplace le inline expand)

---

## Feature 2 — Modal IP Sessions

### Frontend uniquement (pas de backend call supplémentaire)

Données sources : `this.currentResults.tcp_analysis.sessions` + `this.currentResults.packets_index`

**Déclencheur** : clic œil sur une ligne session (overview `#sessionsTable` ET streams tab `#streamsTable`)

**IP pivot** : extraire `src_ip` de la session sélectionnée (partie avant le `:port` du champ `session.src`)

**Contenu du modal** :

1. **Header** : IP pivot + badges stats (nb sessions, nb paquets, protocoles uniques)
2. **Mini-charts** (2 côte à côte, `height: 160px`) :
   - Donut : répartition protocoles pour cette IP
   - Bar horizontal : top 5 IPs de destination
3. **Table sessions** : toutes les sessions où src_ip OU dst_ip == IP pivot
   - Colonnes : direction (→/←), IP:port distant, protocole, état, paquets, bouton "Filtrer paquets"
4. **Bouton "Filtrer paquets"** : ferme modal, switch tab paquets, pré-remplit `packetFilterInput` avec l'IP

**Logique de filtrage** : côté client, O(n) sur `sessions` array (déjà en mémoire)

---

## Fichiers modifiés

| Fichier | Changement |
|---------|-----------|
| `app/api/routes.py` | Enrichir `get_packet_details()` avec re-lecture Scapy + extraction couches |
| `static/js/app.js` | Remplacer `showPacketDetails()` + `togglePacketDetail()`, ajouter `showIpSessionModal()` |
| `templates/index.html` | Ajouter CSS couches OSI dans `<style>`, pas de nouveau HTML structurel (modals dynamiques) |

---

## Contraintes

- Si PCAP original supprimé → modal affiche données `packets_index` (dégradé gracieux, message info)
- Performance : PcapReader seek par index, pas `rdpcap()` complet
- Mobile : accordion collapse par défaut sur petit écran
