# Captures d'exemple — chaîne à 3 points

Trois captures d'un **même trafic** observé à trois endroits successifs du réseau.
Elles servent à tester l'analyse multi-PCAP (bande passante, appariement paquet,
goulot d'étranglement) avec des défauts connus à l'avance.

```
Postes clients ── [1] SW_LAN ── [2] FW_DMZ ── [3] RTR_WAN ── Internet
```

| Fichier | Équipement | Position | Paquets |
|---|---|---|---|
| `1_SW_LAN.pcap` | SW_LAN | 1 | 1334 |
| `2_FW_DMZ.pcap` | FW_DMZ | 2 | 1334 |
| `3_RTR_WAN.pcap` | RTR_WAN | 3 | 1209 |

## Comment les utiliser

1. Ouvrir l'application, cliquer sur **« Ouvrir le mode Multi-PCAP »**.
2. Importer les trois fichiers.
3. Renseigner pour chacun le nom d'équipement et la position indiqués dans le tableau
   ci-dessus (l'ordre compte : c'est lui qui définit la chaîne).
4. Lancer **« Lancer corrélation multi-PCAP »**.

Les fichiers s'analysent aussi individuellement, via l'upload classique.

## Ce que l'application doit trouver

### Goulot d'étranglement

| Segment | Ce qui a été injecté | Ce que l'app doit afficher |
|---|---|---|
| SW_LAN → FW_DMZ | file d'attente jusqu'à 45 ms, **aucune perte** | signature **SHAPING**, ~42 ms de délai ajouté p95 |
| FW_DMZ → RTR_WAN | **11 % de pertes**, délai stable | signature **POLICING**, ~9,4 % de pertes — **goulot principal** |

C'est la distinction utile sur le terrain : un *shaper* met en file d'attente (la latence
gonfle, rien ne se perd), un *policer* jette (ça se perd, sans file d'attente).

### Horloges désynchronisées

Les trois sondes ont volontairement des horloges décalées (0 s, +2,5 s, −1,25 s).
L'application doit afficher le bandeau **« Horloges non synchronisées »** et annoncer
des délais **relatifs** — c'est le comportement correct : sans synchronisation, seule la
*variation* de délai est mesurable, pas sa valeur absolue.

### Pourquoi les flux ne vont pas plus vite

Le trafic contient volontairement des flux de natures différentes :

- **Limité par le récepteur** — deux flux annoncent une fenêtre nulle à répétition
  (le poste ne consomme pas assez vite).
- **Limité par le réseau** — deux flux subissent des retransmissions massives.
- **Limité par l'application** — un flux marque des pauses alors que la fenêtre reste ouverte.
- Flux HTTPS sains, HTTP en clair, partage SMB et résolutions DNS pour la variété protocolaire.

## Régénérer les captures

```bash
python3 samples/generate_chain_samples.py
```

Le script est déterministe (graine fixe) : il reproduit exactement les mêmes fichiers.
Les paramètres de pertes, de latence et de décalage d'horloge sont en tête de script,
faciles à modifier pour fabriquer d'autres scénarios.

> Trafic entièrement synthétique : adresses de documentation (RFC 5737), aucune donnée réelle.
