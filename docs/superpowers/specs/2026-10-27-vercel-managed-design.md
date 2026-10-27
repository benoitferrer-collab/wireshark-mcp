# Vercel géré — espace personnel PCAP

L'utilisateur remplace l'architecture VPS par un déploiement entièrement géré
sur Vercel, dans Benedetto's Repo (closer15, Hobby). Captures habituellement de
quelques Mo, maximum de 100 Mo rare. Préserver les analyses existantes et MCP.

Architecture retenue : service conteneur API + interface FastAPI ; service Node
pour les jetons d'upload direct Blob privé ; service MCP avec binding privé vers
l'API ; worker conteneur Daemon, une instance 2 GiB, Vercel Queues en poll.
Aucun Redis, stockage local durable, serveur Ollama ou VPS requis. OAuth MCP
externe reste nécessaire ; sans configuration le MCP refuse l'accès. Usage
personnel, aucune facturation client ou gestion multi-tenant ajoutée.

100 MiB maximum par fichier, 200 MiB cumulés pour une investigation multi-PCAP,
8 captures maximum. Le navigateur envoie les fichiers directement à Blob.
Un manifeste validé référence uniquement des pathnames captures/<task>/<name>.
La finalisation vérifie les tailles réelles et le propriétaire logique du chemin,
persiste le manifeste puis émet un message idempotent contenant seulement task_id.
Le worker relit le manifeste, valide le magic PCAP, traite un job à la fois dans
un sous-processus, persiste les résultats, résumés et statuts dans Blob. Le lease
est renouvelé par le SDK. Les échecs sont limités à trois livraisons. Supprimer
une analyse pose d'abord un marqueur pour empêcher sa résurrection par un worker.

L'API hydrate les fichiers depuis Blob dans un répertoire temporaire par requête,
nettoyé après la réponse. Les sections dérivées sont également conservées dans
Blob. Les exports sont générés dans le scratch ; les streams retrouvent le PCAP
par storage.get_pcap_path plutôt que par un chemin enregistré sur une autre instance.
Les requêtes /api restent protégées par la clé personnelle. Les callbacks Blob
utilisent la vérification de signature du SDK, pas cette clé. La clé ne doit
jamais devenir une variable frontend ni un paramètre d'URL.

Déploiement : Services avec routes publiques explicites, Daemon production iad1,
Blob privé dans le même projet, secret API généré, SDK Node verrouillé et SDK
Python cloud indépendant des dépendances Docker historiques. Le CLI est connecté
à la bonne équipe. Préparer, tester, puis tenter la mise en ligne dans cette
équipe sans souscrire d'offre payante ; rapporter toute limitation réelle.

Validation : stockage testé sur faux transport persistant entre instances,
limites d'upload et rejeu, annulation et nettoyage, vrai moteur Scapy sur capture
synthétique dans l'image cloud, tests existants et MCP, SDKs réels inspectés,
validation CLI Vercel et test distant si le déploiement aboutit. Ne pas affirmer
que 100 MiB garantit de tenir en 2 GiB (le nombre de paquets influe sur la RAM).
