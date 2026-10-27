# Authentification MCP avec Microsoft Entra ID

Le MCP reste hébergé à `https://wireshark-mcp.vercel.app/mcp`. Entra gère la
connexion et le consentement utilisateur ; aucun hébergement Azure n'est requis.
Ce guide décrit une configuration personnelle, dans un tenant unique, pour
Claude et ChatGPT avec des clients OAuth enregistrés explicitement.

## État de l'intégration

Le code sait valider les jetons délégués Entra v2 et les permissions exposées
ci-dessous. Les tests incluent l'accès MCP HTTP et le refus des autres tenants,
audiences et utilisateurs. La création des inscriptions, le consentement et la
connexion depuis les deux clients doivent être validés dans le tenant réel.

## 1. Enregistrer l'API MCP

Dans Entra > Inscriptions d'applications, créer `Wireshark MCP API` :

- Type de comptes : **ce répertoire uniquement**.
- Aucune URI de redirection pour cette inscription d'API.
- Dans le manifeste, positionner `api.requestedAccessTokenVersion` à `2`.
- Ensuite, sous Exposer une API, définir l'URI d'ID d'application exacte :
  `https://wireshark-mcp.vercel.app/mcp`.
- Ajouter une permission déléguée `pcap:read` pour la lecture des analyses.
  Le scope demandé par les clients sera
  `https://wireshark-mcp.vercel.app/mcp/pcap:read`.

L'ordre version v2 puis URI HTTPS est nécessaire selon la documentation MCP
Microsoft. Si une stratégie du tenant refuse cette URI, résoudre cette
restriction avant de continuer ; ne pas remplacer silencieusement l'URI par
`api://...` tout en annonçant l'URL Vercel comme ressource MCP.

Conserver l'**ID d'application (client)** de cette API : c'est l'audience attendue
des jetons v2. L'ID d'objet de l'inscription et l'ID de tenant ne le remplacent pas.

## 2. Préparer les clients OAuth

Créer deux inscriptions distinctes dans le même tenant :

- `Wireshark MCP - Claude`.
- `Wireshark MCP - ChatGPT`.

Configurer des clients Web utilisant Authorization Code + PKCE et les URI de
redirection **exactes affichées par chaque client** lors de l'ajout du MCP.
Les callbacks peuvent dépendre de la connexion créée ; ne pas les deviner.
Ne pas utiliser d'URI générique ni de caractère joker.

Dans Autorisations API, ajouter la permission **déléguée** `pcap:read` de l'API
MCP. Les scopes OIDC `openid`, `profile` et `offline_access` concernent la
connexion et son renouvellement. Aucune permission Microsoft Graph de lecture
du répertoire, des messages ou des fichiers n'est nécessaire à l'analyse PCAP.

Si les clients utilisent des secrets, créer un secret séparé par client et
conserver sa **valeur** dans un gestionnaire de secrets. Le secret va dans les
réglages OAuth du client concerné ; il n'est pas utilisé comme jeton backend
Vercel. Prévoir son renouvellement avant expiration.

Le consentement Microsoft et l'affectation des utilisateurs dépendent des
stratégies du tenant. La passerelle limite en plus les accès aux seuls `oid`
présents dans `MCP_ALLOWED_SUBJECTS`, même si un autre utilisateur du tenant
obtient un jeton signé pour cette API. Les jetons d'application sans utilisateur
(`roles` sans `scp`) ne sont pas acceptés par cette intégration personnelle.

## 3. Variables Vercel de production

```dotenv
MCP_OAUTH_PROVIDER=entra
MCP_ENTRA_TENANT_ID=TENANT_ID
MCP_PUBLIC_URL=https://wireshark-mcp.vercel.app/mcp
MCP_OAUTH_ISSUER=https://login.microsoftonline.com/TENANT_ID/v2.0
MCP_OAUTH_JWKS_URL=https://login.microsoftonline.com/TENANT_ID/discovery/v2.0/keys
MCP_OAUTH_AUDIENCE=API_APPLICATION_CLIENT_ID
MCP_ALLOWED_SUBJECTS=OWNER_USER_OBJECT_ID
```

Remplacer les trois identifiants par les valeurs réelles. L'audience doit être
l'ID client de l'**API**, et les sujets autorisés doivent être les ID d'objet
des **utilisateurs**, pas leur email ni leur `sub` propre à un client.

La passerelle valide la signature RS256, l'expiration, l'issuer tenant v2,
l'audience UUID, `tid`, `ver=2.0`, l'utilisateur `oid` et le scope délégué
`scp=pcap:read`. Elle annonce le scope qualifié dans les métadonnées MCP.
Une configuration incomplète garde `/mcp` fermé avec 503.

## 4. Connecter et vérifier

Après configuration et redéploiement :

1. Vérifier qu'un appel anonyme à `/mcp` retourne 401 et annonce les métadonnées
   à `/.well-known/oauth-protected-resource/mcp`.
2. Dans Claude, ajouter un connecteur Web personnalisé avec l'URL du MCP et
   choisir le client OAuth enregistré pour Claude.
3. Dans ChatGPT, ajouter un serveur MCP personnalisé avec la même URL et les
   paramètres du client OAuth enregistré pour ChatGPT.
4. Terminer la connexion Microsoft et le consentement dans chacun des clients.
5. Tester `list_analyses`, puis le résumé d'une capture connue ; vérifier aussi
   que les autres utilisateurs et les jetons destinés à Graph sont refusés.

Les tests synthétiques ne prouvent pas qu'un client réel a terminé OAuth.
L'accès depuis les deux comptes reste à confirmer par ces essais.

## Sources officielles

- [Microsoft : protéger un serveur MCP avec Entra](https://learn.microsoft.com/en-us/entra/agent-id/secure-mcp-server-with-entra-id)
- [Microsoft : claims des jetons d'accès](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference)
- [OpenAI : authentification MCP](https://developers.openai.com/plugins/build/auth)
- [Claude : connecteurs MCP distants](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp)
