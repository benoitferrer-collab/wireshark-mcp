# Diagnostic support et préparation de l’apprentissage

Dans **Diagnostics → Santé TCP → Diagnostic support corrélé**, ouvrir le panneau
puis cliquer **Construire le diagnostic**. Aucun scan supplémentaire n’est lancé
automatiquement à l’ouverture d’une capture. Une référence facultative peut être
choisie dans la bibliothèque ; elle n’est jamais déclarée saine automatiquement.

Le moteur lit les métadonnées DNS/TCP du PCAP original avec Wireshark. Il relie
reset et requête HTTP sans réponse uniquement lorsqu’ils appartiennent au même
`tcp.stream`. Les échecs DNS restent des observations séparées : leur coexistence
avec un reset ne prouve pas une causalité. Zero Window, retransmissions et erreurs
HTTP disposent de faits, trames originales, hypothèses et prochaines vérifications.
L’ordre privilégie les resets/fenêtres nulles, conserve la diversité des types, puis
les trames ; ce n’est pas un classement entraîné ni une probabilité de panne.

RTT ACK, resets et compteurs utilisent les mêmes mesures que la nouvelle vue
Santé par session. La vue globale historique reste disponible ; son RTT de
handshake diffère du délai segment→ACK. Une valeur non mesurable reste inconnue.
Une retransmission ne devient jamais un taux de perte confirmé.

Les médianes de référence portent sur la même étape et un même service candidat
(nom ou adresse, plus port). Confirmer même opération, point de capture et charge.
Les mesures DNS candidates copiées sur des transactions HTTP ne sont pas
recomptées. TCP/TLS sont comptés une fois par connexion. Les preuves de chaque
comparaison renvoient aux trames des deux captures. Moins de cinq mesures reste
explicitement un petit échantillon ; aucun critère d’acceptation métier n’est
inventé. Le zéro reste distinct d’une mesure absente.

Limites : un scan à la fois ; 250 000 paquets d’entrée, 20 secondes, 8 Mo de sortie
par capture. Avec référence : deux scans séquentiels. L’agrégation des étapes est
limitée aux 5 000 premières lignes DNS/TCP décodées et 25 groupes, avec indicateur
de troncature. Vingt constats sont présentés, quatre par page web. Le nouvel outil
MCP `get_support_diagnosis(task_id, reference_task_id?, offset=0, limit=5)` les pagine
en lecture seule et transmet couverture, limites et preuves. Les données de capture
restent non fiables en tant qu’instructions pour le LLM.

## Avis ingénieur

**Pertinent**, **Faux positif** et **Confirmer la cause** enregistrent un avis par
ingénieur, version du rapport et constat. Confirmer impose de choisir une cause.
Ces avis restent non arbitrés : aucun vote n’entraîne automatiquement un modèle. Les avis sur les démonstrations synthétiques identifiées sont exclus de l’export d’apprentissage.
Le MCP et le jeton machine ne peuvent pas soumettre d’avis ; en production une
vraie session web Entra et la protection CSRF existante sont requises.

Le stockage partagé utilise la base d’identité existante ; le mode local utilise
un fichier SQLite dans `uploads`. Seuls les identifiants de validation et les
caractéristiques numériques sont persistés, sans noms DNS, adresses de service,
texte de diagnostic, payload ou notes libres. L’identifiant de l’ingénieur permet
de modifier son propre avis ; il n’est jamais exposé dans l’export d’évaluation.
Supprimer une capture supprime ses rapports et avis ; un marqueur empêche un scan
concurrent terminé tardivement de les recréer.

L’administrateur peut télécharger les 500 derniers avis depuis
`GET /api/identity/support-learning-export`. L’export contient des identifiants de
capture pseudonymisés et une empreinte de métadonnées pour repérer les doublons ;
ce n’est pas une garantie d’anonymisation. Il reste réservé au périmètre autorisé.

## Expérience ML hors ligne

Le produit utilise actuellement **des règles et corrélations explicables**.
Un candidat Isolation Forest est fourni dans `scripts/evaluate_support_ml.py`,
hors du conteneur de production. Il ne modifie pas le diagnostic du produit.

```sh
python3 -m venv /tmp/nomios-ml-evaluation
/tmp/nomios-ml-evaluation/bin/python -m pip install -r deploy/requirements-ml-evaluation.txt
/tmp/nomios-ml-evaluation/bin/python scripts/evaluate_support_ml.py dataset-adjuge.json
```

Avant évaluation, un ingénieur doit produire **une ligne arbitrée par capture** à
partir des avis, définir `label_status="adjudicated"`, `label` (0 normal, 1 problème
confirmé), `incident_id` et `split` (`train` ou `test`). Conserver `capture_id`,
`capture_signature`, `coverage_complete=true`, `synthetic_demo=false` et `features`. Les votes contradictoires
doivent être résolus ; aucun choix n’est fait automatiquement par le script.

Il exige au moins 30 captures normales pour apprendre et 10 captures distinctes
pour tester, avec les deux classes dans le test. Ces minima permettent seulement
d’exécuter une expérience, pas de garantir une qualité statistique. Il interdit
le partage de capture, d’empreinte dupliquée ou d’incident entre apprentissage et
test. L’imputation des valeurs absentes est ajustée sur l’apprentissage seul.
Les identifiants IP, noms et avis utilisateur ne sont pas des variables du modèle.

Le résultat donne matrice de confusion, précision, rappel, taux de faux positifs,
effectifs, versions des bibliothèques et graine. `deployment_approved` reste false :
la décision dépendra des incidents réels, d’un test représentatif, de critères
fixés par le support et d’une comparaison avec les règles existantes. Un test
synthétique vérifie uniquement l’exécution, jamais la performance réelle.

Références : [détection d’anomalies scikit-learn](https://scikit-learn.org/stable/modules/outlier_detection.html),
[interprétation des informations expertes Wireshark](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvExpert.html).
