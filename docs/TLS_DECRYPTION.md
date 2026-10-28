# Déchiffrement TLS

Dans **Captures**, ouvrez **Déchiffrement TLS · facultatif**, sélectionnez le type
et le fichier de secrets avant d’importer votre PCAP. Gardez l’onglet ouvert
jusqu’à la fin de l’analyse : le fichier reste seulement en mémoire du navigateur
avant son envoi. Vous pouvez aussi ouvrir une capture individuelle déjà analysée,
puis **Protocoles → HTTP / HTTPS → Ajouter ou remplacer les secrets**.

- **SSLKEYLOGFILE** : fichiers texte issus du client ou serveur correspondant
  aux sessions capturées. Compatible TLS 1.2 / 1.3 selon les secrets disponibles.
  Taille maximale : 2 Mio.
- **RSA PEM** : clé privée du serveur, éventuellement chiffrée par mot de passe.
  Taille maximale : 64 Kio. Nécessite un échange RSA compatible, sans (EC)DHE,
  et la négociation complète ; ne déchiffre pas TLS 1.3. Un certificat ou une
  clé d’autorité de certification ne suffit pas.

Le rapport TLS conserve les métadonnées HTTP/1 et HTTP/2 : méthode, hôte,
chemin sans query/fragment et avec masquage des segments sensibles, statut,
source/destination et références des trames/flux. Les corps, les en-têtes
Authorization/Cookie et les secrets ne sont pas extraits. Le PCAP original
reste inchangé. La première version ne couvre pas Multi-PCAP.

Le rapport indique les limites de couverture, notamment la première occurrence
par champ dans une trame HTTP/2 multiplexée et un plafond de 10 000 lignes.
Le compteur de paquets concerne les protocoles applicatifs effectivement
reconnus sous TLS (HTTP, HTTP/2, SMTP, IMAP, POP, FTP, LDAP, SMB, DNS et MQTT),
non une simple annonce ALPN. Un résultat vide n’est pas une preuve d’absence.
Le détail de paquet ouvre le PCAP original et ses couches initiales ; le
rapport dérivé constitue la vue décodée, sans réécriture du PCAP.

## Hébergement

Le worker installe TShark depuis les paquets Debian officiels. Chaque tâche
s’exécute dans un processus séparé : 200 s pour le moteur, 180 s CPU, 1 Gio
d’espace mémoire TShark sous Linux, et 32 Mio de sortie de métadonnées. Trois
tentatives maximum. Les traitements trop volumineux échouent explicitement.

Configurer **TLS_SECRETS_ENCRYPTION_KEY** avec une clé Fernet dédiée et stable
(secret Vercel de production, jamais de préfixe public). La base PostgreSQL,
Blob privé, la file et l’authentification Entra utilisent les configurations
existantes. Sans cette clé, la fonction n’est pas activée. Ne pas changer la
clé pendant que des tâches attendent : leurs secrets deviendraient illisibles.

Les secrets validés sont chiffrés côté serveur avant Blob ; l’enveloppe lie
capture, tâche, type et expiration. Le mot de passe PEM n’est pas enregistré.
Les fichiers temporaires ont des permissions restrictives et sont supprimés
après chaque tentative. Le secret chiffré est supprimé après succès/échec
terminal, reste disponible pour une relance, expire après 24 h et est purgé
par la maintenance quotidienne. Une suppression de capture supprime aussi les
secrets et rapports associés et empêche la publication tardive.

Seuls les membres autorisés du tenant via une session web peuvent importer
un secret (CSRF obligatoire). Les résultats suivent le partage existant de
l’espace : tous les membres autorisés peuvent les consulter. Le MCP utilise
`get_tls_decryption(task_id, offset=0, limit=20)` pour lire le rapport déjà
produit ; il ne peut ni déposer ni récupérer de clés, ni lancer ce traitement.

## Validation

Fixtures publiques Wireshark dans `tests/fixtures/tls` pour RSA, TLS 1.3 et
HTTP/2. Ces clés sont du matériel de démonstration public, exclu du déploiement.
Tests de taille/format, secret incorrect, chiffrement, expiration, droits,
CSRF, relances, doubles livraisons et suppression pendant publication.
Les tests réels TShark sont ignorés si le binaire n’est pas installé.

Référence : https://wiki.wireshark.org/TLS/
