# Investigations cyber avec Nomios MCP

Le MCP conserve les outils existants et ajoute neuf outils de lecture. Le moteur TShark est installé dans le conteneur web ; aucune nouvelle variable Vercel n'est nécessaire. En local, installer TShark ou définir `TSHARK_PATH` vers un exécutable de confiance (configuration administrateur uniquement).

| Outil | Usage |
|---|---|
| `get_investigation_capabilities` | Vérifier moteur, fichier original, index initial et limites |
| `search_packets` | Filtres directionnels IP/CIDR, ports, protocole, domaine, temps Unix, flux TCP et filtre Wireshark |
| `get_conversations` | Conversations classées par octets, paquets, resets ou retransmissions |
| `hunt_indicators` | Jusqu'à 25 IP/CIDR/domaines ; DNS, SNI TLS, HTTP Host, réponses DNS A/AAAA |
| `triage_capture` | Candidats TCP, DNS, protocoles en clair, accès distants ou échanges TLS |
| `correlate_entity` | Corréler une entité dans les résultats stockés avec pointeurs JSON exacts |
| `compare_analyses` | Écarts de métriques et d'anomalies entre deux analyses |
| `get_traffic_statistics` | Principales sources/destinations/domaines et séries chronologiques UTC par minute |
| `get_packet_context` | Métadonnées des paquets voisins, au-delà de l'index initial |

## Exemples à demander à Claude ou ChatGPT

- « Liste mes captures, puis effectue un triage cyber de la plus récente. Donne les preuves et les limites de couverture. »
- « Recherche les resets TCP vers 198.51.100.20:443 ; distingue les faits observés des causes possibles. »
- « Cherche evil.example et ses sous-domaines, puis retrouve les connexions vers les IP effectivement résolues. »
- « Classe les conversations par retransmissions et inspecte le flux TCP le plus affecté. »
- « Compare ces deux captures avant/après et indique si leurs durées et points de capture permettent la comparaison. »
- « Trace les volumes par minute avec les valeurs renvoyées par get_traffic_statistics. »

Les prompts MCP `investigate_capture` et `investigate_indicator` fournissent des parcours guidés si le client sait afficher les prompts.

## Filtres avancés

`search_packets` reçoit un objet `filters`, par exemple :

```json
{
  "task_id": "identifiant-retourne-par-list_analyses",
  "filters": {
    "dst_ip": "198.51.100.20",
    "dst_port": 443,
    "display_filter": "tcp.flags.reset == 1 || tcp.analysis.retransmission"
  },
  "limit": 25
}
```

Les filtres typés sont combinés par ET. Les domaines incluent leurs sous-domaines avec limites de labels, pas une simple recherche de sous-chaîne. `ip`, `src_ip`, `dst_ip` filtrent les extrémités réseau ; la chasse IOC inspecte aussi les réponses DNS A/AAAA. `tcp_stream` est le numéro de flux Wireshark, différent de l'identifiant de session des analyses historiques.

## Preuves et rendu

Chaque paquet fournit `frame_number` (Wireshark, commence à 1), `packet_index` (application, commence à 0), l'horodatage Unix et `evidence_url`. Le lien charge la bonne capture et l'inspection OSI, même après le paquet 5000. Les corrélations fournissent aussi `section` et `pointer` pour une lecture ciblée via `query_analysis`.

Les instructions du serveur demandent : conclusion, faits observés, preuves cliquables, hypothèses justifiées, inconnues/couverture et vérification suivante. Le client LLM reste responsable de la formulation finale ; le MCP ne peut pas garantir son respect des instructions ni imposer un widget à tous les clients.

## Couverture, coûts et confidentialité

- Lecture du fichier original PCAP/PCAPNG, distincte de l'index UI des 5000 premiers paquets.
- Par appel : au plus 250000 paquets d'entrée, 20 secondes de traitement, 8 Mio de sortie moteur, 25 résultats. Une investigation simultanée par processus ; les autres reçoivent une demande de réessai.
- Ces limites incluent un arrêt explicite : `coverage.complete=false`, motif et `total_matching=null`. Une sortie vide ou une fin de page ne prouve jamais l'absence d'activité hors du périmètre inspecté.
- Les recherches suivantes relisent le fichier pour conserver l'état de dissection TCP. `next_after_frame` pagine les correspondances ; ce curseur ne contourne pas le plafond d'entrée de 250000 paquets. Pour les captures plus grandes, utiliser des captures découpées ou une future exécution asynchrone.
- Les agrégats couvrent uniquement les paquets correspondant au filtre. Pour examiner toute une conversation découverte, rechercher son `tcp_stream` sans les autres contraintes.
- Les corrélations stockées peuvent être top-N, et ne prétendent jamais couvrir tout le PCAP. Les variations de métriques ne sont pas normalisées par durée ni point de capture.
- Aucun nom externe n'est résolu, aucun trafic actif n'est généré. TShark ne reçoit ni secrets d'environnement de l'application, ni paramètres de commande arbitraires ; sa configuration utilisateur est isolée.
- Aucun payload brut, cookie, Authorization, clé privée, corps de message ni URL HTTP avec paramètres n'est retourné par les nouveaux outils. Les valeurs réseau restent des données non fiables et peuvent contenir des instructions malveillantes à ignorer.
- Les métadonnées TLS déchiffrées restent accessibles séparément via `get_tls_decryption`, lorsque le worker TLS a effectivement produit un rapport. L'ajout du moteur de recherche ne résout pas les travaux TLS en attente.

Référence de la syntaxe moteur : [manuel officiel TShark](https://www.wireshark.org/docs/man-pages/tshark.html).
