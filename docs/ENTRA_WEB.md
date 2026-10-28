# Nomios PcapAnalyzer — accès web Entra et activité MCP

## État

Interface Nomios intégrée en conservant les modules historiques et leurs exports.
Authentification nouvelle activée uniquement par `WEB_AUTH_ENABLED=true`. Sans ce
paramètre, l'accès par clé API existant continue de fonctionner ; le panneau
Assistants explique que le suivi n'est pas encore activé.

## Stockage partagé provisionné le 27 octobre 2026

La ressource Neon `nomios-identity` (plan gratuit `free_v3`) est reliée au projet
Vercel `wireshark-mcp`, environnement Production. `DATABASE_URL` est injectée par
l’intégration. Les tables `web_sessions`, `identity_policy`, `identity_audit` et
`mcp_activity` sont initialisées. Une écriture/lecture/suppression de session
chiffrée a été vérifiée sur cette base, sans importer de PCAP.

`WEB_SESSION_ENCRYPTION_KEY` et `CRON_SECRET` sont configurés comme secrets Vercel.
La politique initiale est réservée à l’administrateur, sans groupe autorisé.
La connexion web n’est pas activée tant que le client Entra Web, son secret et
les autres variables ne sont pas configurés et testés. Les secrets ne sont pas
versionnés dans le dépôt.

## Inscription Entra dédiée au site

Créer **Nomios PcapAnalyzer Web**, comptes de ce tenant uniquement :
`4b0a3328-264b-4f04-a6e9-66b104b58487`.

- Plateforme Web, URI de redirection exacte :
  `https://wireshark-mcp.vercel.app/auth/callback`.
- Autorisation Microsoft Graph **déléguée** `User.Read` ; aucun accès applicatif
  global au répertoire n'est nécessaire. Respecter la stratégie de consentement
  du tenant.
- Créer un secret client et le saisir dans les variables serveur Vercel,
  jamais dans le chat, le dépôt ou le JavaScript.
- Le flux MSAL gère code, PKCE, state et nonce ; la signature du jeton ID,
  issuer, audience, tenant, nonce et expiration sont contrôlés côté serveur.

## Base et variables de production

Connecter un PostgreSQL géré via Vercel Marketplace (par exemple Neon), puis
vérifier le coût et les conditions avant création. `DATABASE_URL` doit être une
URL PostgreSQL utilisant TLS (`sslmode=require` ou validation plus stricte),
avec un compte dédié à cette application. Les tables sont créées au démarrage.

```dotenv
WEB_AUTH_ENABLED=true
WEB_ENTRA_TENANT_ID=4b0a3328-264b-4f04-a6e9-66b104b58487
WEB_ADMIN_OID=65c6def3-d34c-414d-9d6e-a9266fa76264
WEB_ENTRA_CLIENT_ID=<ID de Nomios PcapAnalyzer Web>
WEB_ENTRA_CLIENT_SECRET=<secret serveur>
WEB_PUBLIC_ORIGIN=https://wireshark-mcp.vercel.app
DATABASE_URL=<connexion PostgreSQL privée>
WEB_SESSION_ENCRYPTION_KEY=<clé Fernet générée une fois et conservée>
MCP_ACTIVITY_ENABLED=true
CRON_SECRET=<secret de maintenance aléatoire distinct, au moins 32 caractères>
```

Les variables doivent être disponibles aux services concernés. `API_ACCESS_TOKEN`
reste requis pour les appels internes ; ne pas le supprimer. Le binding
`UPLOADS_BACKEND_URL` est configuré dans `vercel.json` et permet au service Node
l'introspection de session avant l'émission d'un jeton Blob.

Ne pas activer `WEB_AUTH_ENABLED` tant que toutes les variables ne sont pas
présentes. La configuration partielle doit faire échouer le démarrage. Une
prévisualisation nécessite son propre callback exact, son origin et une base
séparée, sans connecter ses utilisateurs aux données de production.

## Administration et sessions

Se connecter avec le compte propriétaire initial, ouvrir **Administration**, et
saisir l'**Object ID** d'un groupe de sécurité Entra. Aucun groupe ne signifie
administrateur uniquement. L'enregistrement valide la forme de l'identifiant ;
il ne prouve pas que le groupe existe. Graph vérifie l'appartenance effective
à la connexion, puis au plus tard toutes les cinq minutes. Un changement de
configuration force un nouveau contrôle dès la prochaine requête.

Les membres partagent les captures et analyses de l'espace existant. Seul le
propriétaire modifie le groupe. Les droits MCP restent limités au compte déjà
autorisé ; ce groupe web ne les élargit pas.

Sessions de huit heures, cookies Secure/HttpOnly/SameSite=Lax, cache MSAL chiffré
au repos, contrôles CSRF/Origin pour les mutations. Une erreur de renouvellement
ou un refus de groupe invalide la session. Déconnexion locale immédiate ; la
session Microsoft globale du navigateur n'est pas détruite.

## Mesure des appels MCP

Un événement = un `tools/call` authentifié ayant atteint le gestionnaire. Les
outils inconnus et paramètres invalides y sont comptés en erreur. Les noms
inconnus non conformes sont remplacés par `unknown_tool`. Aucun argument,
prompt, contenu de réponse, donnée PCAP ou jeton ne figure dans les événements.

La collecte n'est pas rétroactive. Les compteurs donnent aujourd'hui UTC et les
30 derniers jours ; un réessai du client est un nouvel appel. « Activité récente »
= dernier appel reçu il y a moins de quinze minutes, sans garantie de connexion
permanente. Le panneau se rafraîchit toutes les trente secondes quand visible.

Le contrôle de santé réservé au serveur vérifie activation et communication
MCP → backend → stockage. En cas d'indisponibilité, les anciens compteurs restent
consultables avec un avertissement ; une panne temporaire peut perdre un
événement, car la télémétrie ne doit pas interrompre l'investigation.

Purge quotidienne Vercel Cron à 03:00 UTC, authentifiée par `CRON_SECRET`, et purge
également à l'ingestion/consultation : événements et journal d'administration
30 jours, sessions et caches expirés supprimés. La purge quotidienne implique
un délai maximal d'environ 24 heures après expiration.

## Validation avant activation

1. Tests Python et Node, moteur PostgreSQL réel, contrôle visuel des modules.
2. Connexion propriétaire ; vérifier refus d'un compte hors tenant et hors groupe.
3. Tester un membre du groupe, lecture des captures, import direct et exports.
4. Modifier le groupe et vérifier l'invalidation ; tester déconnexion et expiration.
5. Depuis Claude, lancer un outil puis constater client/outil/résultat dans le panneau.
6. Vérifier la collecte désactivée et indisponible, puis la purge cron.

La validation par jetons synthétiques ne remplace pas le parcours Microsoft réel.
