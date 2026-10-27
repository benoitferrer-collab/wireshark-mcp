# Connexion Entra et activité MCP — proposition

## Résultat demandé

Ajouter une connexion Microsoft Entra ID à l'application Vercel dans le tenant existant `4b0a3328-264b-4f04-a6e9-66b104b58487`. L'accès web dépend d'un groupe dont l'administrateur renseigne l'Object ID dans l'application. Le menu Assistants IA présente l'activité réelle des clients MCP et leurs appels d'outils.

La nouvelle interface Nomios reste pour le moment une maquette séparée. Ces fonctions doivent pouvoir alimenter cette interface lors de son intégration, sans remplacer ni réduire les modules d'analyse existants.

## Accès web

- Nouvelle inscription cliente « Nomios PcapAnalyzer Web », limitée au tenant, distincte des clients Claude et ChatGPT. Parcours serveur authorization code avec PKCE, state et nonce, validation de signature/issuer/audience/expiration/tenant. Callback HTTPS fixe `/auth/callback` sur le domaine de production.
- Session serveur avec cookie opaque HttpOnly, Secure, SameSite=Lax ; pas de clé API partagée ni de jeton Microsoft accessible au JavaScript. Protection CSRF pour toutes les mutations par cookie, contrôle Origin pour les routes concernées, déconnexion et expiration.
- Vérification de l'appartenance au groupe via Microsoft Graph `/me/checkMemberGroups`, avec permission déléguée User.Read et jeton conservé côté serveur. Inclure les appartenances transitives prises en charge par Graph. Refuser l'accès si la vérification échoue ; ne jamais autoriser par défaut en cas d'erreur.
- Recontrôler l'appartenance au plus tard toutes les cinq minutes pour les sessions actives ; expirer la session si le renouvellement échoue. Un changement du groupe invalide immédiatement les autorisations mises en cache par une version de configuration.
- L'administrateur initial est le compte déjà autorisé, Object ID `65c6def3-d34c-414d-9d6e-a9266fa76264`, fixé dans la configuration serveur. Il peut accéder à l'administration même avant la définition du groupe. Aucun autre membre du groupe ne devient administrateur.
- Écran Administration : tenant en lecture seule, Object ID du groupe de sécurité, état de configuration, sauvegarde protégée, journal des modifications sans secrets. Le groupe vide signifie accès réservé à l'administrateur ; UUID malformé refusé. Enregistrer l'identifiant ne signifie pas que le groupe a été vérifié dans l'annuaire : la vérification d'appartenance à la connexion est l'autorité.
- Les membres autorisés partagent l'espace d'analyses existant (captures, résultats, imports et exports). Cette version ne crée pas de séparation des captures entre utilisateurs ; cette conséquence doit être explicitement approuvée.
- Conserver l'authentification serveur par Bearer pour les appels internes MCP et les workers. Adapter le service Node d'upload direct au contrôle des sessions ; ne pas laisser un chemin d'upload contourner la nouvelle autorisation.
- L'accès MCP demeure limité au compte actuellement autorisé et à pcap:read ; le groupe web ne modifie pas implicitement les droits MCP.

## Assistants IA et activité MCP

- Montrer endpoint MCP, nom du client identifié par son client ID vérifié (Claude connu, ChatGPT uniquement après configuration), dernier appel authentifié reçu, dernière réussite et état « jamais utilisé », « activité récente » ou « aucune activité récente ». Une activité récente ne prouve pas qu'une session distante reste ouverte. Fenêtre initiale : 15 minutes.
- Définir une requête comptabilisée comme un appel MCP `tools/call` authentifié accepté par le serveur, y compris les appels échoués après authentification. Les initialisations, tools/list et notifications ne gonflent pas ce compteur. Les refus d'authentification ne sont pas attribués à un assistant.
- Compteurs par client : aujourd'hui UTC, 30 jours glissants, réussites, erreurs ; préciser le fuseau et le début de collecte. Le passé ne peut pas être reconstitué sans données existantes. Les réessais du client sont de nouveaux appels, explicitement comptés.
- Historique récent : horodatage, outil, résultat, durée. Ne stocker ni prompts, ni réponses d'analyse, ni contenu PCAP, ni jetons. Montrer les métriques agrégées aux membres autorisés, la configuration sensible à l'administrateur uniquement.
- Instrumentation à la frontière réelle d'exécution des outils, après validation du jeton, y compris paramètres invalides ; identité du client issue de l'authentification, jamais d'un en-tête libre. Tester la couverture des appels et des erreurs.
- Actualisation du panneau toutes les 30 secondes quand visible, avec bouton Actualiser. Une défaillance de collecte est affichée comme indisponible, jamais comme zéro appel ni comme déconnexion certaine. Une erreur de télémétrie ne bloque pas l'analyse MCP.

## Persistance et exploitation — choix proposés

- Utiliser un magasin transactionnel compatible Vercel pour les sessions, la configuration du groupe et les événements/agrégats MCP (Postgres géré). Pas de compteur en mémoire ni de read-modify-write d'un objet Blob partagé : les instances concurrentes perdraient des incréments. Le fournisseur disponible et son éventuel coût seront vérifiés avant provisionnement.
- Événements conservés 30 jours, suppression planifiée, limite/pagination de l'historique, index sur temps/client. Contrainte d'identifiant événement évitant de dupliquer une écriture rejouée en interne.
- Secrets web, clé de session et URL de base conservés dans les variables serveur Vercel ; aucune valeur secrète dans le dépôt ou les journaux.
- Déploiement seulement après tests locaux et aperçu vérifié. La création de credentials et l'élargissement d'accès Entra suivent les confirmations requises à l'action ; aucune nouvelle autorisation annuaire n'est déjà accordée par ce document.

## Validation attendue

Tests : utilisateur hors tenant rejeté, hors groupe rejeté, membre accepté, administrateur initial accepté, groupe absent fermé, erreurs Graph fermées, session expirée/revoquée, state/nonce/PKCE/CSRF, upload et endpoints protégés. Tests MCP : identité client, succès/erreur, appels concurrents et réessais, zéro fuite de contenu ou secrets, panne de télémétrie sans panne d'analyse. Vérification UI ordinateur/mobile et parcours de connexion sur aperçu puis production après configuration Entra.

## Points à approuver

1. Les membres du groupe partagent les analyses existantes ; administration réservée au propriétaire actuel.
2. La métrique porte sur les appels d'outils réellement observés, avec un historique à partir de l'activation, pas sur les messages envoyés dans Claude.
3. Un stockage transactionnel géré est nécessaire ; aucun abonnement payant n'est créé sans accord.
