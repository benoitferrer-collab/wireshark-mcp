# Comparaison multi-points : preuves et limites

## Parcours ingénieur

1. Ouvrir **Collaboration → Multi-PCAP**.
2. Importer au moins deux captures de la même communication et de la même période.
3. Nommer les équipements et ordonner les points du chemin, par exemple LAN → firewall → WAN.
4. Lancer la corrélation puis lire **Preuves & qualité de la comparaison**.
5. Choisir un segment, vérifier les sens client/serveur et les numéros de trame dans les PCAP d’origine.

La colonne Point A est la capture de référence, pas forcément l’amont physique
du trafic : les paquets serveur→client circulent dans le sens inverse du chemin.

## Correspondances

Les occurrences TCP contenant des données sont indexées avec séquence TCP,
longueur, flags et une empreinte courte des octets capturés. Cette empreinte reste
interne et n’est jamais exportée. Les adresses, ports, TTL et IP-ID ne font pas
partie de cette signature, afin de tolérer le routage et une réécriture NAT/PAT
simple. Le sens logique reste séparé ; aucune recherche dans le sens opposé ne
vient artificiellement augmenter le nombre d’appariements.

Une signature unique concordante fournit une paire candidate avec les numéros
de trame de chaque fichier. Des répétitions sont conservées et appariées en
candidats par ordre d’occurrence ; elles restent ambiguës et sont exclues de
**toutes** les mesures temporelles, brutes et relatives.

Les signatures aident aussi à départager des sessions NAT candidates. Si
l’échantillon de signatures est incomplet, son absence d’intersection n’est pas
utilisée pour rejeter un flux. Une session corrélée reste une hypothèse : une
terminaison proxy/TCP, une modification de séquence ou une segmentation/offload
différente peut empêcher l’appariement.

## Lecture des compteurs

- **Candidats appariés** : occurrences TCP data pouvant correspondre, répétitions comprises.
- **Non retrouvés au point B** : occurrences indexées au point A sans candidat au point B.
- **Uniquement au point B** : occurrences indexées à B sans candidat dans A.
- **Occurrences ambiguës** : répétitions dont l’identité individuelle reste indéterminée.
- **Pertes réseau confirmées** : non établies par ce calcul (`null` dans l’API).

Un non-appariement ne prouve pas une perte. Il faut vérifier fenêtres temporelles,
filtres, SPAN/TAP, asymétrie, pertes du capteur et transformations des paquets.
Les hypothèses de limitation de flux et les scores de tri ne remplacent pas ces
vérifications. Les nouvelles lignes de correspondance ne génèrent pas de cause
racine « perte réseau confirmée ».

## Délais

Les écarts d’horodatage sont centrés sur la médiane **de chaque sens** avant
l’agrégation des variations relatives. Le décalage brut mélange horloge et temps
de transit ; il ne mesure pas le décalage des horloges seul. La dérive des
horloges n’est pas estimée. Aucune latence absolue ni localisation causale n’est
déduite de ces valeurs. Sans paire temporelle univoque, les métriques restent
`null`, jamais zéro par défaut.

## Bornes et compatibilité

- Au plus 250 000 paquets par capture par défaut, avec signalement si le fichier continue.
- Au plus 150 000 occurrences TCP data indexées par capture, répétitions incluses.
- Au plus 2 000 échantillons temporels par session et sens, 5 000 retenus par segment et sens.
- Au plus 12 exemples de trames publiés par segment.
- Les trames tronquées par snaplen sont signalées et exclues des signatures.
- Une lecture ou un index incomplet réduit la confiance à LOW. Les pertes du capteur restent inconnues même si le fichier est lu entièrement.

Les données TCP d’origine sont lues sans re-sérialiser les objets Scapy TLS.
Ni contenu applicatif ni empreinte interne ne sont inclus dans le JSON de preuve.
Les captures UDP, les ACK seuls et les SYN/FIN/RST sans données ne sont pas
couverts par cet appariement de données TCP ; ils restent analysés par les autres
métriques du module.

Relancer une ancienne analyse Multi-PCAP pour obtenir le schéma de preuves v2.
Les anciennes clés de mesure sont conservées quand nécessaire pour les vues et
exports ; `lost_packets`/`loss_ratio` des nouvelles preuves valent `null`, tandis
que `unmatched_packets`/`unmatched_ratio` portent l’écart de visibilité observé.
