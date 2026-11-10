"""Public metadata only. Tests keep this catalogue aligned with registered tools."""
TOOLS = [
    {'name':name,'title':title,'category':category,'description':description,'access':'Lecture'}
    for name,title,category,description in [
        ('guide_investigation','Investigation guidée','Investigation','S’appuyer sur les preuves du PCAP pour proposer une question ciblée et la vérification suivante.'),
        ('get_support_diagnosis','Diagnostic support corrélé','Diagnostic','Relier les signaux DNS/TCP/HTTP, leurs preuves et prochaines vérifications ; comparer une référence explicite.'),
        ('list_analyses','Captures disponibles','Lecture','Lister les analyses du périmètre partagé autorisé.'),
        ('get_analysis_summary','Synthèse de capture','Lecture','Totaux, sections disponibles et couverture de l’index.'),
        ('query_analysis','Preuves stockées','Lecture','Lire une section autorisée avec pointeur JSON et pagination.'),
        ('get_anomalies','Anomalies','Diagnostic','Consulter les indices heuristiques par source et sévérité.'),
        ('get_packets','Index de paquets','Lecture','Filtrer l’index initial par IP et protocole ; couverture potentiellement partielle.'),
        ('get_packet_details','Inspection OSI','Investigation','Décoder un paquet de la capture ; champs bruts filtrés dans le MCP.'),
        ('get_tcp_session','Session TCP','Investigation','Consulter une session issue de l’analyse stockée.'),
        ('get_tls_decryption','Rapport TLS','Lecture','Lire les métadonnées d’un rapport déjà produit, sans transmettre les secrets TLS.'),
        ('get_diagnostic','Diagnostics réseau','Diagnostic','Calculer ou lire un diagnostic et son cache dérivé, sans modifier le PCAP.'),
        ('get_investigation_capabilities','Périmètre d’investigation','Lecture','Découvrir la disponibilité de la capture et les limites du moteur.'),
        ('search_packets','Recherche Wireshark','Investigation','Interroger le fichier original avec filtres typés et filtres Wireshark.'),
        ('get_conversations','Conversations réseau','Investigation','Classer les échanges par volume, resets ou retransmissions.'),
        ('hunt_indicators','Chasse aux indicateurs','Investigation','Rechercher des IP, CIDR et domaines ; aucun renseignement externe automatique.'),
        ('triage_capture','Triage cyber','Diagnostic','Extraire des candidats TCP, DNS, TLS, accès distants ou protocoles en clair.'),
        ('correlate_entity','Corrélation des preuves','Investigation','Retrouver une entité dans les sections stockées, avec références exactes.'),
        ('compare_analyses','Comparaison de captures','Investigation','Comparer les métriques de deux analyses sans en déduire une causalité.'),
        ('get_traffic_statistics','Statistiques de trafic','Investigation','Calculer les volumes et séries chronologiques côté serveur.'),
        ('get_packet_context','Contexte d’un paquet','Investigation','Lire les métadonnées des trames voisines et leurs références.'),
    ]
]
