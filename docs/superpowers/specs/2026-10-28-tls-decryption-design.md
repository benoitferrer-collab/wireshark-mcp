# Déchiffrement TLS pour Nomios PcapAnalyzer

Statut : proposition à valider avant implémentation.

## Objectif

Ajouter à une capture PCAP une clé privée RSA serveur (.pem/.key) ou un fichier
de secrets de session au format SSLKEYLOGFILE pour examiner les échanges chiffrés
pendant une investigation. Les deux types ont été demandés par l’utilisateur.
Le service reste entièrement hébergé sur Vercel, avec connexion Entra et accès
aux analyses par le groupe déjà configuré.

## Périmètre proposé

Une option repliable « Déchiffrement TLS — facultatif » dans l’import d’une
capture : type de fichier, sélection du fichier, et mot de passe facultatif
pour une clé PEM chiffrée. Une aide explique les formats et leurs limites.
La même opération peut être lancée depuis une analyse existante pour éviter
de devoir transférer de nouveau le PCAP. Une opération de déchiffrement est
attachée à une capture unique ; le mode Multi-PCAP reste inchangé dans cette
première version. Les analyses classiques ne changent pas sans secret fourni.

Les résultats apparaissent dans HTTP/HTTPS, sans nouveau menu latéral : état
du traitement, nombre de paquets déchiffrés, flux concernés, requêtes HTTP/1
et HTTP/2 (méthode, hôte, chemin sans paramètres sensibles, statut, protocole,
taille et références aux paquets/flux). Un résultat vide distingue « aucun
échange déchiffré » d’une erreur de traitement et ne prouve pas l’absence de
trafic applicatif. Les autres protocoles déchiffrés sont comptés et identifiés,
sans promettre un décodage applicatif complet dans cette première version.

Les corps de messages, les en-têtes d’authentification et les cookies ne sont
pas conservés ni envoyés aux assistants. Les références de trames restent
celles du PCAP original, avec conversion explicite vers les indices zéro
utilisés par l’application. Les vues et diagnostics existants restent présents.

## Compatibilité

- SSLKEYLOGFILE : secrets correspondant à la capture, TLS 1.2 et TLS 1.3 selon
  les capacités de TShark ; une clé sans correspondance donne un résultat vide.
- Clé privée RSA : échange de clés RSA compatible, clé du certificat serveur,
  négociation complète capturée. Pas de déchiffrement TLS 1.3 ni (EC)DHE à
  partir de cette seule clé. La clé d’une autorité de certification ne convient pas.
- Accepter uniquement PEM RSA valide ; déverrouiller une PEM chiffrée pendant
  la validation. Rejeter certificats seuls, clés EC/DSA et formats non supportés
  avec un message adapté. Aucun certificat privé utilisateur n’est demandé
  dans le chat, et aucun véritable secret n’est utilisé pour les tests.

## Architecture — choix proposés par l’implémenteur

Installer TShark dans l’image du worker et utiliser un sous-processus isolé,
sans shell, avec temps, mémoire et taille de sortie limités. Le PCAP d’origine
reste intact. Lire la capture en deux passes avec réassemblage TCP/TLS activé,
extraire uniquement les champs nécessaires au rapport de dépannage. Les
options TShark exactes seront vérifiées sur la version installée, avec des
captures publiques synthétiques de référence.

Créer une tâche durable de déchiffrement séparée de l’analyse Scapy, avec son
propre identifiant, statut et artefact dérivé. Le worker actuel distribue les
deux types de tâches. Cela permet d’ajouter des secrets après une analyse,
de conserver ses résultats et de ne pas relancer tous les diagnostics.
Une génération de tâche désigne le résultat actif pour empêcher un ancien
traitement de remplacer un traitement plus récent. Une suppression de capture
interdit la publication tardive et supprime aussi secrets et résultats dérivés.

Les fichiers secrets passent par une route authentifiée dédiée, limitée en
taille (64 Kio pour RSA, 2 Mio pour keylog) et protégée par session Entra et
CSRF. Ni les outils MCP ni un simple jeton machine ne peuvent appeler cette
route. L’accès est ouvert aux utilisateurs du groupe autorisé, comme le
reste de l’espace partagé ; les résultats dérivés suivent ce même partage.
Le secret doit être validé avant que sa tâche soit mise en file.

Pour traverser la file Vercel, chiffrer le secret côté serveur avant stockage
dans Blob privé, avec une clé de chiffrement serveur dédiée, hors du dépôt.
L’enveloppe lie le secret à sa capture et à sa tâche et porte une expiration.
La file et les manifestes ne contiennent que des références opaques. Aucun
secret, mot de passe, jeton ou sortie de diagnostic TShark n’est journalisé.
Ne pas enregistrer ces fichiers dans le stockage du navigateur.

Le worker déchiffre le fichier dans un dossier temporaire privé, permissions
restrictives. Supprimer les temporaires à chaque tentative. Le secret chiffré
reste disponible pour les relances tant que la tâche n’est pas terminale,
puis est supprimé après succès ou échec définitif. Une expiration de 24 h et
une purge par la maintenance quotidienne couvrent les tâches abandonnées ;
après expiration, aucun worker ne peut l’utiliser, même avant la purge physique.
Ni secret ni mot de passe ne peut être téléchargé depuis l’application.

Exposer au MCP une section dérivée dédiée, paginée et soumise aux protections
existantes, contenant uniquement les métadonnées de dépannage décrites plus
haut. Les outils MCP ne soumettent pas de secrets et ne déclenchent pas de
nouveau déchiffrement. L’assistant doit mentionner les limites de couverture.

## Vérifications avant livraison

Tests avec captures et secrets de test publics : TLS 1.2 RSA compatible,
TLS 1.3 avec keylog, clé incompatible, mauvais mot de passe, keylog sans
correspondance, PEM invalide, capture tronquée et résultat vide. Vérifier
HTTP/1 et HTTP/2, les références de paquets et l’absence de faux succès.
Tester aussi les limites de taille, les droits Entra, CSRF, le refus des
appels machine, la confidentialité des journaux et des artefacts, l’expiration,
les relances, la suppression pendant un traitement et les tâches concurrentes.
Vérifier la navigation et le formulaire sur desktop et écran étroit, puis
la compilation et le déploiement Vercel. La suite existante doit rester verte.

## Référence

https://wiki.wireshark.org/TLS/ — restrictions RSA, secrets de session et
préférences de déchiffrement Wireshark.
