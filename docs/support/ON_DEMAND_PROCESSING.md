# Traitement PCAP et TLS à la demande

Les services privés `worker` et `tlsworker` remplacent le daemon permanent. Chacun reçoit un topic Vercel Queues via un déclencheur `queue/v2beta`, avec une livraison simultanée par topic et trois tentatives. Ils n'ont aucune réécriture publique et ne sont jamais montés dans l'API web/MCP. Le SDK officiel accepte les CloudEvents, maintient le bail pendant le traitement et acquitte uniquement après réussite. Le groupe de consommation attribué par Vercel est conservé sans modification.

Hobby impose 300 secondes par invocation. L'analyse PCAP est interrompue après 250 secondes et le déchiffrement après 240 secondes, pour laisser du temps au stockage et à l'acquittement. Les processus enfants et leur répertoire temporaire appartiennent au parent et sont nettoyés même en cas de délai. Une très grosse analyse peut échouer après trois tentatives : cette architecture n'offre pas un temps d'exécution illimité. Une offre ou un moteur adapté aux traitements longs reste nécessaire si ces limites sont régulièrement atteintes.

Le daemon historique est retiré de `vercel.json`. Il n'y a donc plus de réservation permanente de 2 Go pour cette tâche. Les invocations, CPU, mémoire des Functions, opérations Queues et Blob restent soumises aux quotas de l'offre ; aucune gratuité illimitée n'est promise.

Les statuts distinguent les étapes TLS et le numéro de tentative. Une attente dépassant 90 secondes est signalée comme retardée : l'application ne prétend pas lire les quotas Vercel. Les logs Vercel restent nécessaires pour identifier une limite de plateforme précise. Une interruption réseau du navigateur relance uniquement la lecture du statut, jamais l'envoi des secrets.

## Compatibilité TLS

Le bouton « Vérifier la compatibilité TLS » inspecte sans secret les ServerHello, dans les 100 000 premières trames (20 secondes maximum). Il retourne uniquement des versions, suites sélectionnées et références de trames, avec 25 sessions affichées au maximum. Les sessions absentes du périmètre restent indéterminées. Une petite liste conservatrice classe les échanges RSA et éphémères usuels ; une suite inconnue reste inconnue.

Un échange RSA observé ne prouve ni la correspondance de la clé, ni la complétude de la capture. TLS 1.3 et les échanges (EC)DHE nécessitent des secrets de session. Les secrets sont toujours chiffrés pendant l'attente, supprimés après traitement et expirent selon la politique existante de 24 heures. Le rapport contient les métadonnées applicatives autorisées, jamais les corps, cookies ou secrets.

## Exploitation

Vérifier dans le déploiement que les deux Functions privées ont leurs triggers v2, une durée de 300 secondes et les topics attendus. Consulter les logs `Queue processing` / `Queue completed`, puis le statut durable du travail. Le code de polling historique reste disponible pour un retour explicite à une architecture daemon ; ne pas activer simultanément les deux chemins en production.

Après une panne prolongée, les anciens messages peuvent avoir expiré (rétention 24h). Une réimportation des secrets peut être nécessaire. Les traitements déjà terminés ou supprimés sont ignorés à la réception d'un doublon ; aucun effacement des captures existantes n'est requis pour migrer.
