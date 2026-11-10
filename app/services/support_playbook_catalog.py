"""Proposed Nomios support workflows; review against each customer's runbooks and SLA."""


def workflow(name, category, objective, evidence, checks, validation):
    return {
        'name': name, 'category': category, 'priority': 'MEDIUM',
        'description': objective, 'icon': '📋',
        'phases': [
            {'phase': '1 · Qualifier le ticket', 'icon': '①', 'tasks': [
                'Relever le service affecté, le symptôme exact, les utilisateurs concernés et la fenêtre horaire avec fuseau.',
                'Confirmer le point de capture, le sens du trafic, la durée, les filtres et les limites de visibilité du PCAP.',
                'Identifier le propriétaire du service, les changements récents et la priorité selon le contrat client ; préserver le PCAP original et sa provenance.',
            ]},
            {'phase': '2 · Rechercher les preuves', 'icon': '②', 'tasks': evidence},
            {'phase': '3 · Vérifier et proposer', 'icon': '③', 'tasks': checks + [
                'Faire valider toute modification par le propriétaire client : périmètre, impact, fenêtre, sauvegarde et retour arrière. Aucune action n’est exécutée par ce playbook.',
                'Escalader au référent réseau/sécurité ou au CSIRT du client si les indices ou l’impact le justifient, avec les preuves et les limites de l’analyse.',
            ]},
            {'phase': '4 · Valider et transmettre', 'icon': '④', 'tasks': validation + [
                'Comparer avant/après sur une reproduction contrôlée ; consigner ce qui reste non vérifié.',
                'Rédiger le ticket : symptôme, chronologie, paquets/flux de référence, faits, hypothèses écartées ou ouvertes, actions approuvées, résultat et prochaine responsabilité.',
            ]},
        ],
        'mitre_techniques': [],
    }


PLAYBOOK_TEMPLATES = {
    'qualification': workflow('Qualification initiale · Support Nomios', 'transverse',
        'Orienter un ticket réseau ou sécurité sans présumer une attaque ni une cause.', [
            'Identifier les échanges client/serveur, les protocoles, les erreurs DNS, les resets et les retransmissions pertinents pour le symptôme.',
            'Comparer une transaction réussie et une transaction en échec avec leurs horodatages et numéros de paquets.',
            'Distinguer un signal de sécurité, un défaut de transport, une erreur applicative et un manque de visibilité.',
        ], [
            'Demander le résultat attendu, la fréquence et la dernière occurrence ; sélectionner le parcours spécialisé correspondant.',
            'Corréler les observations aux journaux de l’équipement ou de l’application ; ne conclure que sur les preuves disponibles.',
        ], ['Confirmer avec le demandeur le périmètre du diagnostic et l’équipe chargée de la suite.']),
    'network_latency': workflow('Latence réseau / application', 'reseau',
        'Séparer délais DNS, établissement TCP/TLS, transport et traitement applicatif.', [
            'Mesurer DNS, SYN→SYN/ACK, négociation TLS et requête→première réponse sur les mêmes transactions lorsque ces échanges sont visibles.',
            'Comparer RTT médian, p95 et valeurs maximales si disponibles, par destination et période ; noter le nombre d’échantillons.',
            'Repérer retransmissions, fenêtres nulles, pauses applicatives et captures asymétriques ; relever les paquets de début et de fin.',
        ], [
            'Comparer avec une capture saine et le niveau habituel du service ; aucun RTT universel ne définit à lui seul une panne.',
            'Corréler interfaces, files, CPU, inspection firewall, proxy et temps serveur ; un point de capture unique ne localise pas toute la latence.',
            'Proposer une capture synchronisée de part et d’autre du chemin pour départager transit et traitement.',
        ], ['Rejouer la transaction et comparer les mêmes mesures avec la référence et les objectifs convenus avec le client.']),
    'packet_loss': workflow('Pertes de paquets / retransmissions', 'reseau',
        'Vérifier les indices de perte et distinguer perte réelle, réordonnancement et artefacts de capture.', [
            'Isoler les flux concernés : retransmissions, Duplicate ACK, SACK, trous de séquence et expirations RTO.',
            'Vérifier la complétude du handshake, le sens capturé, les pertes du capteur, le SPAN, la troncature et les effets d’offload.',
            'Comparer les séquences TCP et horodatages sur deux points synchronisés si disponibles ; une retransmission seule ne localise pas une perte.',
        ], [
            'Corréler les compteurs d’erreurs, CRC, drops, files saturées et événements d’interface ou Wi-Fi pendant la même fenêtre.',
            'Rechercher réordonnancement, changement de chemin, asymétrie et MTU avant d’attribuer la perte à un équipement.',
            'Proposer un test contrôlé autorisé à faible impact avec métriques avant/après ; éviter de déduire le taux de perte réseau du seul taux de retransmission TCP.',
        ], ['Valider la disparition du symptôme et la réduction des indices sur un trafic et une période comparables.']),
    'dns_resolution': workflow('DNS · NXDOMAIN / SERVFAIL / délais', 'reseau',
        'Qualifier les échecs de résolution et les domaines suspects sans confondre NXDOMAIN et attaque.', [
            'Relever nom demandé, type, résolveur, code retour, délai et paquets requête/réponse ; distinguer NXDOMAIN, SERVFAIL, REFUSED et absence de réponse.',
            'Comparer le nombre d’échecs au total des réponses observées et isoler les noms réellement liés au symptôme.',
            'Rechercher noms longs, variations répétées et périodicité comme pistes ; ces caractéristiques ne prouvent ni DGA ni tunnel DNS.',
        ], [
            'Vérifier zone autoritaire, délégation, cache, split DNS, suffixes et résolution via VPN avec l’équipe DNS.',
            'Corréler résolveur, proxy et télémétrie endpoint ; faire valider tout changement ou blocage de domaine.',
        ], ['Confirmer le résultat attendu avec le résolveur et le contexte utilisateur appropriés.']),
    'tls_failure': workflow('TLS · négociation / certificats', 'reseau',
        'Distinguer erreur de négociation, certificat, inspection TLS et problème de transport.', [
            'Relever ClientHello, ServerHello, SNI, ALPN, versions, alertes TLS et resets lorsque visibles.',
            'Identifier le stade exact de l’échec et les certificats visibles ; TLS 1.3 peut masquer ces informations sans secrets de session.',
            'Comparer accès direct et chemin inspecté si ces captures sont disponibles ; distinguer échec TCP et échec TLS.',
        ], [
            'Corréler date/heure, chaîne de confiance, SAN, versions compatibles et journaux d’inspection avec le propriétaire du service.',
            'Si un déchiffrement est nécessaire et autorisé, utiliser le canal sécurisé de l’application ; ne pas coller de clé privée ou secret de session dans un chat.',
            'Proposer une correction de certificat ou de politique validée ; ne pas désactiver globalement la validation TLS.',
        ], ['Vérifier la transaction applicative et la confiance du certificat depuis le client réellement affecté.']),
    'firewall_access': workflow('Firewall · accès refusé / reset', 'reseau',
        'Départager filtrage, routage, NAT, asymétrie et refus du serveur.', [
            'Identifier le quintuplet, les interfaces/zones et le moment de l’échec ; relever SYN sans réponse, ICMP et sens des resets.',
            'Comparer les captures entrée/sortie du firewall si disponibles et tenir compte du NAT.',
            'Un SYN absent ou un RST observé ne prouve pas à lui seul quel équipement bloque.',
        ], [
            'Corréler session, règle réellement appliquée, NAT, routage, inspection et journaux de refus au même instant.',
            'Vérifier la disponibilité du service et le chemin retour avant de demander une ouverture.',
            'Proposer uniquement une règle précise et validée, avec durée et retour arrière ; éviter les règles any/any.',
        ], ['Rejouer le flux attendu et vérifier que les accès non prévus restent refusés.']),
    'vpn_failure': workflow('VPN · tunnel établi / application inaccessible', 'reseau',
        'Qualifier accès VPN, négociation, routage, DNS et transport applicatif.', [
            'Distinguer échec de connexion VPN, tunnel établi sans trafic et interruption intermittente ; relever la fenêtre d’incident.',
            'Pour IPsec, relever IKE/ESP ou NAT-T si visibles ; l’extérieur du tunnel ne révèle pas nécessairement les applications internes.',
            'Après connexion, vérifier DNS, routes, MTU/MSS et les échanges applicatifs sur une capture interne autorisée.',
        ], [
            'Corréler journaux client/concentrateur, événements Entra/MFA pertinents, compteurs de tunnel et changements de route.',
            'Comparer les sélecteurs, politiques et réseaux autorisés sans exporter de secret partagé ; confirmer les hypothèses côté concentrateur.',
        ], ['Confirmer connexion, résolution et transaction métier depuis le poste et le profil VPN affectés.']),
    'c2_beaconing': workflow('Suspicion de C2 / beaconing', 'cyber',
        'Qualifier une communication périodique avant de conclure à un canal de commande.', [
            'Relever destinations, ports, SNI/domaines visibles, intervalles et volumes ; comparer la régularité sur une période suffisante.',
            'Comparer le flux aux mises à jour, sondes et outils d’administration connus du client.',
            'Corréler avec processus endpoint et renseignement de menace autorisé ; une IP réputée ou la périodicité seule ne prouve pas une compromission.',
        ], ['Documenter les indicateurs précis et transmettre à l’équipe sécurité pour validation du contexte.',
            'Si la suspicion est confirmée, proposer confinement ou blocage ciblé avec accord client et préservation des preuves.'],
        ['Rechercher une récidive et vérifier l’impact sur les services légitimes après action approuvée.']),
    'exfiltration': workflow('Suspicion d’exfiltration', 'cyber',
        'Qualifier une sortie de données inhabituelle et sa légitimité.', [
            'Mesurer direction, destinations, volumes et durée avec le périmètre réellement capturé ; distinguer débit de pointe et volume total.',
            'Comparer sauvegardes, réplications, exports métier et habitudes du service.',
            'Corréler DLP, proxy, stockage et endpoint ; un volume sortant élevé ne prouve pas quelles données ont été transférées.',
        ], ['Préserver les preuves et transmettre au responsable sécurité client les faits, l’incertitude et le périmètre potentiel.',
            'Faire approuver toute restriction de flux en évaluant les sauvegardes et les activités métier ; laisser au client la qualification des données et obligations.'],
        ['Contrôler la poursuite éventuelle du transfert et la continuité du service après décision client.']),
    'lateral_movement': workflow('Suspicion de mouvements latéraux', 'cyber',
        'Analyser des accès internes inhabituels sans assimiler administration et intrusion.', [
            'Cartographier source, cibles et services SMB, RDP, WinRM ou SSH visibles, avec chronologie et paquets de référence.',
            'Comparer les flux avec bastions, déploiements, supervision et administration planifiée.',
            'Corréler comptes, authentifications et événements EDR ; le PCAP ne donne pas toujours l’identité ou le résultat d’authentification.',
        ], ['Faire qualifier les actifs et comptes suspects par le client ; proposer une collecte endpoint complémentaire.',
            'Après validation sécurité, préparer un confinement ciblé tenant compte des dépendances et accès de secours.'],
        ['Vérifier absence de nouveaux accès suspects et maintien des usages administratifs approuvés.']),
    'brute_force': workflow('Authentification · échecs répétés', 'cyber',
        'Distinguer attaque, compte mal configuré, tâche planifiée et mécanisme de verrouillage.', [
            'Relever sources, cibles, protocole, fréquence et résultats visibles ; ne pas compter chaque connexion comme un échec d’authentification.',
            'Corréler logs d’identité, application, VPN et endpoint ; les sessions chiffrées peuvent masquer les résultats.',
            'Rechercher un succès après les échecs uniquement dans les sources qui attestent le résultat.',
        ], ['Faire vérifier services et comptes techniques avant de proposer un blocage ou une réinitialisation.',
            'Soumettre au client une réponse ciblée : restriction, MFA, correction d’un service ou revue du compte selon les preuves.'],
        ['Valider le retour à un fonctionnement normal et surveiller les nouvelles tentatives avec l’équipe identité.']),
    'ransomware': workflow('Suspicion de ransomware', 'cyber',
        'Organiser une escalade urgente lorsque des indices concordants sont signalés ; le PCAP seul ne prouve pas un chiffrement de fichiers.', [
            'Recueillir les alertes endpoint, modifications de fichiers et témoignages confirmés ; relever leur chronologie.',
            'Identifier les actifs et partages contactés, les flux internes et les éventuels transferts sortants visibles.',
            'Préserver la capture et demander une collecte forensique par l’équipe habilitée, selon le runbook client.',
        ], ['Escalader immédiatement au responsable d’incident/CSIRT client si le chiffrement ou la propagation est confirmé.',
            'Faire décider l’isolement ciblé, la préservation des preuves et la protection des sauvegardes par l’équipe habilitée ; ne pas lancer de nettoyage improvisé.'],
        ['Faire valider la restauration et les critères de reconnexion par les responsables sécurité et métier.']),
    'network_scan': workflow('Reconnaissance / scan suspect', 'cyber',
        'Qualifier un balayage et distinguer audit autorisé, découverte et reconnaissance hostile.', [
            'Relever source, cibles, ports, cadence et réponses ; tenir compte des réponses DNS vers des ports clients éphémères.',
            'Vérifier les campagnes de vulnérabilité, inventaires et tâches de supervision autorisées.',
            'Comparer la chronologie à d’autres signaux ; des ports multiples ne suffisent pas à conclure à un scan.',
        ], ['Faire qualifier l’origine et la légitimité par l’équipe client avant d’escalader la suspicion.',
            'Préparer une restriction ciblée seulement après validation, avec contrôle de l’impact sur les outils d’administration.'],
        ['Vérifier l’arrêt du comportement non autorisé et documenter les exceptions légitimes.']),
    'traffic_flood': workflow('Saturation / suspicion de déni de service', 'cyber',
        'Distinguer saturation légitime, incident de capacité et trafic potentiellement hostile.', [
            'Mesurer paquets/s, bits/s, destinations, protocoles, sessions et durée avec la couverture disponible.',
            'Comparer à la capacité réelle, au trafic habituel et aux événements métier ; un PCAP partiel ne représente pas nécessairement tout le lien.',
            'Corréler drops, CPU, files et mesures opérateur ; distinguer saturation réseau, pare-feu et ressource applicative.',
        ], ['Escalader à l’équipe réseau/opérateur ou au dispositif anti-DDoS du client selon impact et preuves.',
            'Faire valider une mitigation ciblée et son retour arrière ; vérifier qu’elle ne bloque pas les utilisateurs légitimes.'],
        ['Contrôler la reprise des transactions métier et les métriques de charge après mitigation approuvée.']),
}
