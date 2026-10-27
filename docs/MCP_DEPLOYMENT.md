# Utiliser PCAP Analyzer depuis Claude et ChatGPT

> **Ancienne architecture hybride, conservée comme référence.** Le déploiement
> actuel utilise Vercel pour tous les composants : suivre
> [VERCEL_MANAGED.md](VERCEL_MANAGED.md). Les instructions de build Vercel
> ci-dessous décrivent l'ancienne configuration statique et ne correspondent
> plus au `vercel.json` actuel.

## Ce qui est fourni

L'interface existante peut être publiée sur Vercel. Le moteur Scapy/FastAPI,
Celery, Redis et le stockage restent sur un serveur Docker. Un nouveau service
MCP expose `/mcp` en Streamable HTTP, sans appeler de LLM ni nécessiter de clé API
OpenAI/Anthropic. Les conversations utilisent les modèles disponibles dans vos
abonnements et restent soumises à leurs limites. L'hébergement est à prévoir.

Cette version est **personnelle** : les sujets OAuth explicitement autorisés
partagent toutes les captures du serveur. Ce n'est pas une isolation par utilisateur.
Le connecteur n'est pas publié dans un annuaire public.

## Parcours utilisateur

1. Ouvrir l'interface et se connecter avec la clé d'accès du serveur.
2. Importer une capture et attendre son analyse. Lancer les analyses multi-PCAP
   depuis l'interface également.
3. Dans Claude/ChatGPT, sélectionner le connecteur et demander par exemple :
   « Liste mes captures, examine la plus récente et explique les retransmissions
   en citant les sessions et paquets qui étayent tes conclusions. »

Les outils fournis : `list_analyses`, `get_analysis_summary`, `query_analysis`,
`get_anomalies`, `get_packets`, `get_packet_details`, `get_tcp_session`, `get_diagnostic`.
`query_analysis` permet de naviguer dans les sections DNS/HTTP/SMB/LDAP/Kerberos/
RDP/SSH, les anomalies, l'enrichissement, la timeline, le graphe et les résultats
multi-PCAP. Utiliser `kind=multi`, `section=analysis` pour ces derniers.

Pour approfondir une section, utiliser un JSON Pointer : `section=tcp_analysis`,
`pointer=/sessions`, puis `/sessions/0`. `offset`, `limit`, `total` et
`next_offset` décrivent la pagination de l'objet ou de la liste sélectionnée.
Les limites signalées dans `limitations` doivent être prises en compte : le
modèle doit resserrer sa requête plutôt que considérer un résultat tronqué
comme exhaustif. Les diagnostics coûteux restent soumis à un délai de 90 s.

## 1. Préparer le serveur d'analyse

Prérequis : serveur Linux avec Docker/Compose, espace disque pour les captures,
RAM adaptée (Scapy garde les paquets en mémoire), domaine DNS pointant vers le
serveur et ports 80/443 accessibles. Commencer avec une petite capture avant de
dimensionner pour des fichiers de plusieurs Go.

Copier `deploy/.env.example` vers `deploy/.env` et renseigner les valeurs réelles.
Générer la clé du backend avec :

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
```

`API_ACCESS_TOKEN` protège les routes `/api/*` (sauf `/api/health`). Le connecteur
l'utilise entre conteneurs et le propriétaire la saisit dans l'interface. Elle
n'est jamais une variable Vercel ni une clé à fournir à Claude/ChatGPT. Le
navigateur la conserve dans `sessionStorage`, par origine API ; fermer la session
ou effacer ce stockage la retire. Toute personne possédant cette clé a accès à
l'API complète. Les réglages Ollama/MAC gardent leur protection admin existante.

`CORS_ORIGINS` est un tableau JSON contenant l'origine exacte du frontend.
Ajouter explicitement les origines de preview si nécessaire ; éviter `*`.
Les volumes de production sont distincts de ceux du Compose historique : migrer
les anciennes captures séparément si souhaité. Ne pas supprimer les volumes
avec `down -v` si leurs données doivent être conservées.

## 2. Configurer OAuth

Le service MCP est un **serveur de ressources** : il valide des jetons, mais ne
fournit pas lui-même un service de connexion ou de consentement. Configurer un
fournisseur OAuth/OIDC externe capable de :

- Publier les métadonnées OAuth/OIDC et un JWKS HTTPS.
- Gérer Authorization Code avec PKCE S256 et les refresh tokens.
- Émettre des access tokens JWT **RS256**, avec `iss`, `aud`, `exp`, `iat`, `sub`
  et un champ `scope` contenant `pcap:read`.
- Accepter les deux clients Claude et ChatGPT : enregistrement statique de clients
  distincts et callbacks exacts affichés par chaque client, ou enregistrement
  dynamique/identité publiée si le fournisseur le prend en charge.

Renseigner l'issuer exact, y compris son éventuel `/` final, le JWKS et l'audience.
L'audience recommandée est `https://VOTRE_DOMAINE/mcp` ; configurer les clients pour
qu'ils demandent bien un access token pour cette API (et non seulement un ID token).
Autoriser le scope `pcap:read` et les refresh tokens dans les clients OAuth.
Le renouvellement et le consentement sont gérés par ce fournisseur.

Mettre le `sub` exact de votre compte dans `MCP_ALLOWED_SUBJECTS`. Un jeton signé
valide d'un autre utilisateur est refusé. L'adresse email n'est pas un substitut
au sujet OAuth. Un fournisseur qui n'émet que des jetons opaques ou d'autres
algorithmes demande une adaptation du vérificateur avant utilisation.

Les métadonnées protégées sont publiées automatiquement à :
`https://VOTRE_DOMAINE/.well-known/oauth-protected-resource/mcp`.
Le serveur ne démarre pas sans configuration OAuth et liste de sujets complètes.

## 3. Démarrer les conteneurs

Depuis la racine du dépôt :

```bash
docker compose --env-file deploy/.env -f deploy/compose.yml config --quiet
docker compose --env-file deploy/.env -f deploy/compose.yml up -d --build
docker compose --env-file deploy/.env -f deploy/compose.yml logs --tail=100 mcp fastapi proxy
```

Seul Caddy publie des ports. Redis, FastAPI et MCP communiquent sur le réseau
Compose privé. Caddy gère TLS. Une requête anonyme à `/mcp` doit retourner 401 avec
un header `WWW-Authenticate` pointant vers les métadonnées de ressource.
`/api/history` doit aussi retourner 401 sans clé. `/api/health` reste public.

Le déploiement fourni laisse Ollama désactivé (aucun serveur local n'est lancé).
Les fonctions IA historiques de l'interface restent donc indisponibles tant
qu'un serveur Ollama n'est pas raccordé ; cela n'empêche pas le MCP de fonctionner.

## 4. Publier l'interface sur Vercel

Importer ce dépôt dans Vercel, avec la racine du dépôt comme Root Directory.
`vercel.json` génère l'interface statique dans `dist` avec Python 3.
Définir **uniquement** cette variable publique pour la connexion au moteur :

```text
PCAP_API_BASE_URL=https://VOTRE_DOMAINE
```

Le build copie les assets et rend le template existant. Aucun backend Python ni
worker n'est déployé dans les fonctions Vercel. Les uploads passent directement
du navigateur au backend HTTPS et ne traversent pas les fonctions Vercel.
Vérifier ensuite la connexion API et l'upload d'un petit PCAP depuis l'URL Vercel.
La clé ne doit jamais être ajoutée au code, au build ou aux variables publiques.

## 5. Connecter les clients

**Claude Max** : ajouter un connecteur personnalisé dans les réglages de
connecteurs, avec `https://VOTRE_DOMAINE/mcp`, puis terminer la connexion OAuth.
Si le fournisseur utilise un enregistrement statique, renseigner le client OAuth
Claude et son secret dans les réglages du connecteur prévus à cet effet.

**ChatGPT** : sur le web, utiliser l'ajout de serveur MCP personnalisé depuis
Plugins, si disponible sur le compte, avec la même URL. Configurer OAuth et
installer/sélectionner le connecteur dans la conversation. Les menus et
permissions dépendent des fonctions disponibles sur le compte. Pour un client
statique, utiliser les identifiants OAuth propres à ChatGPT.

Ne pas coller `API_ACCESS_TOKEN` dans ces conversations. La connexion OAuth
donne accès au MCP ; le secret backend reste dans l'application.

Références officielles :
- https://developers.openai.com/api/docs/guides/custom-mcp-server
- https://developers.openai.com/plugins/build/auth
- https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp
- https://py.sdk.modelcontextprotocol.io/v1/

## Limites et vérification

Les outils ne permettent ni suppression, ni upload, ni modification de réglages.
Certains diagnostics créent un cache de calcul. Les champs bruts et quelques
champs sensibles structurés sont omis, mais **ce n'est pas une anonymisation** :
IP, domaines et autres preuves peuvent contenir des informations confidentielles.
Les résultats consultés sont transmis au fournisseur du modèle. Les chaînes
issues du trafic peuvent contenir des instructions malveillantes ; le MCP indique
au modèle de les traiter comme des données non fiables.

L'index initial peut contenir seulement 5 000 paquets. Les alertes de sécurité
restent des heuristiques. Le MCP n'améliore pas la précision du moteur par lui-même.
Les réponses sont limitées à 60 000 caractères JSON, les listes imbriquées à 25
éléments et les longues chaînes à 1 500 caractères, avec signalement explicite.

Tests du connecteur dans un environnement séparé :

```bash
python3 -m venv /tmp/pcap-mcp-test
/tmp/pcap-mcp-test/bin/pip install -r mcp_gateway/requirements.txt pytest pytest-asyncio
/tmp/pcap-mcp-test/bin/python -m pytest gateway_tests -q
```

Les tests ne prouvent pas la connexion avec vos comptes : il faut ensuite
vérifier OAuth et les outils depuis chacun des deux clients sur le domaine réel.
