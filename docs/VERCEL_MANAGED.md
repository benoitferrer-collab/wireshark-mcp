# PCAP Analyzer sur Vercel

## Déploiement actuel

- Application : <https://wireshark-mcp.vercel.app>
- Projet : `wireshark-mcp`, équipe Vercel `closer15` (Benedetto's Repo).
- Dépôt : <https://github.com/benoitferrer-collab/wireshark-mcp>, branche `main`.
- Stockage : Blob **privé**, région `iad1`.
- Calcul : un Daemon d'analyse de 2 Gio, région `iad1`.

L'application est utilisable avec sa clé d'accès. **La connexion MCP aux comptes
Claude/ChatGPT reste à configurer : OAuth n'est pas encore renseigné.** En
attendant, `/mcp` renvoie volontairement 503 et n'expose aucune capture.

Il s'agit d'un espace personnel partagé : les personnes autorisées voient les
mêmes captures. Cette version n'ajoute ni comptes clients isolés ni facturation.

## Utilisation

1. Ouvrir l'application et renseigner la clé d'accès fournie séparément.
2. Importer un `.pcap`, `.pcapng` ou `.cap` depuis l'interface.
3. Attendre l'analyse, puis consulter les résultats ou lancer une comparaison
   multi-PCAP. L'historique et les captures restent dans Blob entre déploiements.

La clé reste dans `sessionStorage` pendant la session du navigateur. Elle donne
accès à l'API complète ; ne pas la publier dans le dépôt ni dans une conversation
avec un LLM. La clé backend n'est pas la connexion OAuth des clients MCP.

## Fonctionnement

Le `vercel.json` utilise Vercel **Services** :

| Composant | Rôle |
| --- | --- |
| `app` | FastAPI, interface, API authentifiée, lecture des résultats |
| `uploads` | Jetons de transfert direct du navigateur vers Blob privé |
| `mcp` | Serveur MCP Streamable HTTP, connexion interne à `app` |
| Daemon `analysis` | Consommation de la queue, analyse Scapy en sous-processus |
| Blob privé | Captures, manifests, statuts, résultats et caches persistants |
| Queues | File `pcap-analysis`, consommateur `pcap-worker` |

Les gros fichiers passent directement vers Blob, puis le navigateur finalise le
travail via `/api/cloud/jobs`. Le worker traite un travail à la fois. Il dispose
de 20 minutes par tentative, avec trois tentatives maximum. Les relectures de
queue ne relancent pas les travaux déjà terminés ou supprimés.

Le disque des conteneurs sert uniquement de répertoire temporaire. Le mode local
Docker historique reste disponible lorsque `PCAP_STORAGE` n'est pas `vercel`.
Redis/Celery ne sont pas requis pour ce déploiement géré. Ollama n'y est pas
installé : les anciennes fonctions IA intégrées qui l'utilisent restent
indisponibles. L'analyse réseau fonctionne sans LLM ; le MCP permet ensuite au
LLM du client d'interroger ses preuves.

## Limites et ressources

- Par capture : **100 Mio** (104 857 600 octets), affichés « 100 Mo » dans l'UI.
- Multi-PCAP : 2 à 8 fichiers, **200 Mio cumulés** maximum.
- Worker : 2 Gio de RAM, traitement séquentiel ; Scapy peut utiliser beaucoup
  plus de mémoire que la taille du fichier.
- Un fichier synthétique de presque 100 Mio / 102 801 paquets a été analysé
  localement dans un conteneur limité à 2 Gio, en 17,71 s, avec environ 966 Mio
  de mémoire maximale. Ce cas représentatif ne garantit pas toutes les captures.
- Le plafond multi-PCAP reste 250 000 paquets par capture ; l'index initial d'une
  analyse simple peut ne contenir que 5 000 paquets. Les limitations remontées
  par les outils MCP doivent être prises en compte par le modèle.

Le déploiement a été réalisé sur Hobby sans passage à une offre payante.
Les quotas Vercel de calcul, Blob et Queues s'appliquent ; les services sont en
bêta. Surveiller la consommation dans Vercel avant d'augmenter le volume.
Les fichiers dont le transfert aboutit mais dont l'analyse n'est jamais
finalisée peuvent rester dans Blob et demander un nettoyage manuel.

## Configuration et redéploiement

Importer la **racine du dépôt**, conserver le preset **Services** et laisser
`vercel.json` déclarer les services. Ne pas importer seulement `mcp_gateway`
comme projet indépendant. Le projet existant est déjà relié à GitHub.

Variables de production :

| Variable | Configuration |
| --- | --- |
| `API_ACCESS_TOKEN` | Secret aléatoire d'au moins 32 caractères, déjà configuré |
| `BLOB_READ_WRITE_TOKEN` | Injecté par le stockage Blob privé lié au projet |
| `MCP_BACKEND_URL` | Injecté par la liaison privée du service `mcp` vers `app` |
| `MCP_PUBLIC_URL` | Facultatif : URL canonique finissant par `/mcp` ; sinon domaine de production Vercel |
| `MCP_OAUTH_ISSUER` | Issuer exact du fournisseur OAuth, à configurer |
| `MCP_OAUTH_AUDIENCE` | Audience de l'API MCP, à configurer |
| `MCP_OAUTH_JWKS_URL` | URL HTTPS des clés publiques JWT, à configurer |
| `MCP_ALLOWED_SUBJECTS` | Sujets OAuth `sub` autorisés, séparés par virgules, à configurer |

Les Dockerfiles configurent `PCAP_STORAGE=vercel`. Les credentials Queues sont
obtenus via l'identité Vercel du service/Daemon. Ne pas recopier un jeton OIDC
temporaire comme secret permanent. Aucun secret ne doit entrer dans un bundle
JavaScript public.

Un push sur `main` déclenche le déploiement GitHub. Les Daemons fonctionnent en
production ; une simple preview n'est pas un environnement complet de test
d'analyse. Pour une nouvelle installation, lier d'abord un Blob privé et les
secrets de production au projet.

## Terminer la connexion Claude / ChatGPT

Choisir un fournisseur OAuth/OIDC géré. Le serveur MCP valide des jetons ; il
ne fournit pas lui-même la page de connexion. Le fournisseur doit publier ses
métadonnées et son JWKS, gérer Authorization Code + PKCE S256 et les refresh
tokens, et émettre des access tokens JWT **RS256** avec `iss`, `aud`, `exp`,
`iat`, `sub` et le scope `pcap:read`.

Configurer l'audience de cette API (par exemple
`https://wireshark-mcp.vercel.app/mcp`), puis les quatre variables OAuth du tableau.
Autoriser le `sub` exact du propriétaire. Pour les clients statiques, créer des
clients OAuth distincts Claude et ChatGPT avec les callbacks exacts affichés
par chaque produit. Sinon utiliser un mécanisme d'enregistrement pris en charge
par le fournisseur et le client. Redéployer après les changements de variables.

Après configuration, une requête anonyme à `/mcp` doit renvoyer 401, avec les
métadonnées de ressource à
`/.well-known/oauth-protected-resource/mcp`. Ajouter alors l'URL
`https://wireshark-mcp.vercel.app/mcp` comme connecteur personnalisé Claude et
comme serveur MCP personnalisé ChatGPT, terminer OAuth et sélectionner le
connecteur dans la conversation. La disponibilité et les autorisations du
compte doivent être vérifiées dans chaque client.

Exemple : « Liste mes analyses, examine la plus récente et explique les
retransmissions en citant les sessions et paquets qui étayent tes conclusions. »

Les outils MCP lisent les résultats et les preuves ; ils ne permettent ni
suppression ni upload. Les éléments consultés sont transmis au fournisseur du
modèle et ne sont pas anonymisés. Les contenus du trafic sont des données non
fiables, y compris les éventuelles instructions qu'ils contiennent.

## Vérifications effectuées

- 51 tests application/cloud, 32 tests gateway, 2 tests connexion navigateur,
  3 tests upload/finalisation Node.
- Bundle navigateur construit, audit npm sans vulnérabilité détectée.
- Analyse Scapy et API testées dans l'image Python de production.
- Production : transfert direct Blob, finalisation Queues, exécution du Daemon,
  statut terminé, résumé MCP, détail de paquet et historique vérifiés avec une
  capture synthétique de 171 paquets ; analyse multi-PCAP de deux captures
  et lecture de ses résultats également vérifiées, puis suppression des tests.
- API sans clé : 401. MCP sans OAuth : 503. La connexion réelle aux comptes
  Claude et ChatGPT n'a pas encore été testée.

## Références officielles

- [Vercel Services](https://vercel.com/kb/guide/vercel-services)
- [Vercel Daemons](https://vercel.com/docs/daemons) et [limites](https://vercel.com/docs/daemons/limits)
- [Vercel Blob : transfert client](https://vercel.com/docs/vercel-blob/client-upload)
- [Vercel Queues : SDK Python](https://vercel.com/docs/queues/python-sdk)
- [OpenAI : ajouter un serveur MCP](https://developers.openai.com/api/docs/guides/custom-mcp-server)
- [OpenAI : authentification MCP](https://developers.openai.com/plugins/build/auth)
- [Claude : connecteurs distants](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp)
