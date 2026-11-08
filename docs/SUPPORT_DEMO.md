# Présenter Nomios PcapAnalyzer au support

## Parcours conseillé : 8 à 10 minutes

1. **Le problème métier (1 min).** Partir d’un incident concret : application lente, connexion coupée ou problème DNS. L’outil rapproche les constats réseau de l’expérience utilisateur ; il ne transforme pas un indicateur en cause certaine.
2. **La bibliothèque (1 min).** Montrer les captures de l’espace partagé, la recherche par nom/identifiant, le filtre de risque, le tri et la pagination. Les compteurs somment les métadonnées d’analyse ; deux captures du même trafic restent deux analyses.
3. **Le contexte (1 min).** Ouvrir une capture, cliquer « Préparer avec l’assistant ». Saisir le symptôme et le point de capture. Le contexte reste en mémoire dans l’onglet et se retrouve en revenant à cette capture, jusqu’au rechargement.
4. **Le diagnostic (2 min).** Choisir la famille d’incident, ouvrir le diagnostic adapté. Explorer les flux puis un paquet pour relier l’hypothèse à la preuve. Les scores heuristiques aident à prioriser ; ils ne prouvent pas la responsabilité d’un équipement.
5. **Le copilote (2 min).** Copier la consigne MCP dans Claude avec le connecteur Nomios activé. L’identifiant exact et le contexte sont inclus. Le nouvel outil `guide_investigation` apporte des observations, une question ciblée et la prochaine vérification. L’assistant doit citer les paquets et préciser les données manquantes.
6. **La transmission (1 min).** Demander une synthèse pour le ticket : faits, portée/limites de la capture, hypothèses, vérifications et prochaine action. Montrer les exports existants.
7. **Le contrôle des accès (1 min).** Centre de sécurité, Azure/Entra, activité réelle des outils MCP. Les compteurs décrivent des appels reçus, pas une garantie de session connectée.

## Avant la présentation

- Se connecter au site de production avec son compte autorisé, et ouvrir une capture de démonstration non sensible.
- Vérifier le connecteur Claude/LiteLLM, rafraîchir sa liste d’outils si `guide_investigation` n’apparaît pas.
- Préparer le même PCAP en local et les exports utiles pour une démonstration de secours. Le mode local sans authentification est distinct de la production.
- Tester une question complète avec ce PCAP avant la réunion. Les données du PCAP et les résultats exposés au LLM restent soumis aux politiques du fournisseur et du proxy.
- Le bouton de copie ne lance aucun appel IA. Le contexte n’est ni sauvegardé en base ni envoyé automatiquement à un fournisseur.
- Le déchiffrement TLS dépend de la disponibilité effective du worker et des secrets compatibles. Cette évolution ne valide pas les anciens travaux TLS restés en attente.

## Vérifications de cette évolution

Tests de course entre chargements, nouvel upload et navigation ; réponses serveur en erreur ; paquets tardifs ; historique supérieur à 50 captures ; filtrage et métadonnées manquantes. Vérification visuelle de la bibliothèque, du formulaire et des liens de diagnostic sur PCAP synthétique, ainsi que du rendu mobile.
