# Transactions et comparaison avant/après

Ouvrir une capture puis **Transactions** dans la navigation principale.
La colonne A utilise la capture active. Choisir une capture B dans la bibliothèque,
puis un échange de chaque côté. La colonne B ne change pas la capture active.
Les liens de preuve ouvrent le paquet du PCAP concerné dans un autre onglet.

## Mesures

- DNS : requête et réponse corrélées par Wireshark, avec le code retour.
- TCP : SYN jusqu’au premier ACK visible correspondant aux numéros de séquence
  attendus, après un SYN/ACK inverse. La durée inclut ce qui est visible au
  point de capture ; ce n’est pas une mesure de RTT pur.
- TLS : premier ClientHello jusqu’au ServerHello inverse visible. Ce n’est ni
  toute la négociation TLS ni une preuve de succès de la session.
- HTTP : requête jusqu’à la trame de réponse que Wireshark rattache à cette
  requête. Ce n’est pas le temps de traitement serveur seul. Les messages
  HTTP/2 et le HTTP chiffré non déchiffré ne sont pas reconstruits ici.

Une association DNS candidate peut compléter une connexion TCP si le même client
vient de recevoir l’adresse du serveur, avec un nom compatible avec Host/SNI et
une réponse précédente de moins de 60 secondes. Elle est explicitement indiquée
comme candidate ; aucune causalité applicative n’est déduite. Les résultats DNS
restent aussi consultables comme échanges indépendants, y compris les NXDOMAIN.

Les mesures TCP/TLS et les compteurs RST/retransmission sont communs à la connexion,
qui peut être réutilisée par plusieurs requêtes. Ils ne doivent pas être
additionnés pour fabriquer une durée de transaction ni interprétés comme un taux
de perte réseau. Les durées absentes valent `null`, jamais zéro par défaut.

## Comparaison

Le tableau calcule B − A et le pourcentage relatif à A lorsque les deux durées
sont mesurables. Un A nul ne donne pas de pourcentage. Deux échanges de natures
différentes ne donnent pas d’écart calculé. Des méthodes ou services différents
produisent un avertissement. Même avec le même hôte, l’ingénieur doit vérifier
opération métier, charge, point de capture et conditions équivalentes ; les URL
étant masquées, la vue ne peut pas confirmer cette équivalence.

Une différence sur deux échanges ne suffit pas à établir une amélioration globale
ou la causalité d’une correction. Aucune moyenne mélangeant des trafics différents
n’est proposée.

## Périmètre et sécurité

Lecture bornée du PCAP original par le moteur existant : 250 000 premiers paquets,
20 secondes, 8 Mio de sortie et un scan simultané par instance. La pagination
présente dix échanges, au plus 25 via API ; chaque réponse précise si le scan est
partiel. Les messages multiples dans une trame ou les captures asymétriques
peuvent rendre certaines corrélations indisponibles. DNS sur TCP sans SYN est
coalescé pour éviter deux échanges portant le même curseur.

Le sélecteur B présente les 500 captures les plus récentes. Si une capture est
plus ancienne, l’ouvrir comme référence depuis la bibliothèque principale.
L’API respecte les protections Entra et renvoie `Cache-Control: no-store`.
Aucun payload, URL, cookie, mot de passe ou secret de session n’est extrait par
cette vue. Les scans n’effectuent pas de résolution DNS externe et n’héritent pas
des secrets d’environnement de l’application. La vue n’appelle pas de LLM.
