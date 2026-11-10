# Protocoles et santé par session

Le menu Protocoles conserve DNS, HTTP/HTTPS et Audit TLS et ajoute ICMP/ICMPv6,
DHCP/DHCPv6, SSH, SMB/SMB2, RDP, NTP, QUIC, TCP et UDP. Chaque vue inspecte le
PCAP original avec un filtre Wireshark fixe. Le filtrage repose sur le décodage,
pas sur une simple présomption liée aux ports. Une capture partielle ou un
protocole chiffré/non reconnu peut donc ne pas fournir de détails applicatifs.

Santé TCP conserve intégralement sa vue globale. Le bouton « Par session TCP »
ouvre une liste paginée de connexions `tcp.stream` avec sélection d’un identifiant
précis, y compris zéro. Ces identifiants Wireshark ne correspondent pas forcément
aux identifiants de l’ancien analyseur Scapy du menu Flux réseau.

Les mesures par session sont isolées par le filtre `tcp.stream`. Les métriques
comprennent RTT ACK moyen et échantillons, retransmissions, resets, Zero Window,
ACK dupliqués et références vers les trames originales. Un RTT absent reste nul
dans l’API et s’affiche « Non mesuré ». Une retransmission ou un segment précédent
non observé ne constitue pas une preuve de perte réseau ni de responsabilité.
Les extrémités A/B sont celles du premier paquet, sans attribution client/serveur.

API : `GET /api/analysis/{task}/protocols/{protocol}` avec `stream` pour TCP,
`after_frame`, `limit` (1–50) et `session_offset` (pages de 50 sessions).
Le middleware d’authentification existant protège ces routes ; aucun nouveau
contournement d’authentification ou accès public n’est ajouté.

Chaque lecture est bornée à 250 000 paquets d’entrée, 20 secondes et 8 Mo de
sortie ; un seul processus d’investigation est exécuté à la fois. Une lecture
partielle affiche sa limite. Le PCAP original doit être disponible.
Les réponses sont `no-store` et limitées aux métadonnées autorisées ; aucun
payload, nom d’utilisateur, cookie, clé ou URL applicative n’est retourné.
Les détails incluent types/codes ICMP, type DHCPv4, mode/stratum NTP,
commande/statut SMB2 et version QUIC quand ils sont observables. DHCPv6,
SSH et RDP disposent actuellement d’une vue paquets/transport, sans reconstruction
de conversation ni déchiffrement.
