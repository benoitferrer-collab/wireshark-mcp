# Parcours de support Nomios

Bibliothèque proposée pour le travail de support ; elle doit être adaptée au
contrat, aux responsabilités et aux procédures approuvées de chaque client.
Ce contenu n’est pas une procédure officielle validée par Nomios.

## Utilisation

Dans **Collaboration → IR Playbook**, ouvrir une capture, choisir un parcours ou
**Suggérer à partir de la capture**, puis **Préparer les checklists**.
Les quatorze parcours couvrent qualification, latence, pertes/retransmissions,
DNS, TLS, firewall, VPN, C2, exfiltration, mouvements latéraux,
authentifications en échec, ransomware, scan et saturation.

Chaque parcours contient qualification, collecte des preuves, propositions à
valider, puis contrôle et transmission au support. Les cases cochées suivent
l’avancement déclaré par l’ingénieur ; elles ne prouvent pas que des contrôles
ont été exécutés. Elles sont mémorisées uniquement dans le navigateur, séparées
par identifiant de capture, parcours et version. Elles ne sont pas partagées
entre collègues et ne constituent pas une piste d’audit.

## Suggestions et limites

- Sans signal exploitable : qualification générique, jamais C2 par défaut.
- NXDOMAIN observés : parcours DNS, sans déclaration de domaine malveillant.
- Retransmissions TCP : parcours pertes, sans localisation ni taux de perte déduit.
- RTT moyen d’au moins 100 ms : parcours latence proposé comme repère de tri,
  pas comme seuil de panne ; la référence client reste nécessaire.
- Indicateurs de flux, mouvement latéral ou types explicites du détecteur :
  suggestion d’investigation, jamais incident confirmé automatiquement.
- Les diagnostics de flux déjà enregistrés en stockage dérivé sont aussi pris en compte, sans lancer de nouvelle analyse.
- Les modules calculés à la demande et non présents dans le résultat enregistré
  ne sont pas inventés : choisir alors le parcours manuellement.

La sélection manuelle reste disponible même sans indicateur. Le PCAP peut être
partiel, asymétrique, chiffré ou présenter des artefacts. Corréler les observations
avec les journaux et le contexte du client. Les changements, confinements et
mitigations restent soumis à validation, impact et retour arrière ; aucun
playbook n’exécute de commande ni d’appel LLM.

## Références de structure

Les checklists sont rédigées pour cette application, avec une organisation de
qualification, réponse et rétablissement cohérente avec :

- [NIST SP 800-61r3, avril 2025](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [CISA, Incident and Vulnerability Response Playbooks](https://www.cisa.gov/sites/default/files/publications/Cybersecurity_Incident_Vulnerability_Response_Playbooks_508C.pdf)

Ces références ne valident ni l’implémentation ni les procédures d’un client.
