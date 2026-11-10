# Nomios Engineering Console

La refonte conserve les quinze modules et leurs identifiants, les tables,
les exports, l’authentification et les résultats TLS. Elle modifie uniquement
la présentation et ajoute des accès de navigation.

- Thème sombre par défaut pour une nouvelle session ; le choix clair/sombre
  existant reste respecté. Le mode clair partage la même hiérarchie visuelle.
- Une navigation permanente, avec Protocoles, Diagnostics et Collaboration
  repliables. Le conteneur HTML englobe désormais correctement les quinze vues.
- Palette d’accès rapide : clic dans la barre supérieure ou Cmd+K / Ctrl+K.
  Recherche insensible aux accents ; flèches, Entrée et Échap au clavier.
  Les commandes utilisent les boutons existants et respectent leurs contrôles.
- Import et thème directement accessibles depuis la barre supérieure.
- Menu mobile escamotable ; ses éléments deviennent inertes quand il est fermé.
- Couleurs, surfaces et typographie cohérentes pour les tables, graphiques,
  filtres, diagnostics et résultats de déchiffrement. Réduction des animations
  quand le système demande prefers-reduced-motion.

Implémentation : engineering.css et engineering-ui.js ; versions de fichiers
ajoutées au rendu FastAPI et au générateur statique pour éviter un cache obsolète.
Les graphiques existants utilisent une palette bleu, menthe et violet.
Aucune connexion, métrique ou activité réseau n’est simulée dans le produit.

Vérification : suite Python existante, tests Node de navigation/pagination/
transfert et recherche, puis parcours navigateur sur une capture synthétique
nommée DEMO_investigation-reseau.pcap, aux adresses de documentation RFC 5737.
Ce fichier de démonstration reste local et n’est pas déployé.
