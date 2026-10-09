# Sha'ah v2 — ce qui a changé

## Nouvelles fonctions

**Design bleu roi, sans icônes.** Toutes les icônes et émojis ont été retirés des quatre écrans (RH, tablette, Scan, accueil). Les statuts, boutons et onglets sont des pilules ; les chiffres clés sont des cases pleines.

**Heures supplémentaires.** Au pointage de départ, si l'employé part après son heure prévue, le départ est enregistré normalement et les minutes au-delà sont comptées en heures supplémentaires. Elles apparaissent sur la tablette, dans l'app Scan, le tableau de bord, la liste des pointages, le bilan annuel et l'export CSV.

**Module Congés.** Le RH indique l'employé, le type, le premier jour et la date de retour. Pendant le congé, l'employé est inactif : il disparaît de la tablette et n'est jamais marqué absent. Le jour de son retour, il redevient actif tout seul. Le RH peut aussi mettre fin au congé plus tôt (« Retour anticipé aujourd'hui ») ou le supprimer. Deux congés qui se chevauchent sont refusés.

**Absence automatique.** Chaque jour à l'heure de clôture (20:00 par défaut, réglable dans Paramètres), tout employé actif qui n'a fait aucun pointage un jour travaillé est marqué absent (« Automatique »). Les jours travaillés et les jours fériés se règlent dans Paramètres. Si le serveur a été arrêté, les jours manqués sont rattrapés au redémarrage. Si le RH saisit ensuite un pointage manuel ou un congé couvrant ce jour, l'absence automatique est retirée.

**Validation des justificatifs par le RH.** L'employé envoie son justificatif (motif + photo facultative) depuis l'app Scan de son téléphone. Le retard ou l'absence passe en « En attente » mais reste comptabilisé. Dans l'onglet Justificatifs, le RH accepte (plus comptabilisé) ou refuse (reste comptabilisé), avec un commentaire que l'employé voit. Une décision peut être annulée.

## Failles corrigées

1. **Perte de pointages.** L'espace RH renvoyait toute la base au serveur toutes les quelques secondes : un pointage fait sur la tablette entre deux synchronisations pouvait être effacé. Chaque action passe maintenant par sa propre requête ; le RH ne peut plus écraser la base.
2. **Injection de code (XSS).** Les noms et motifs étaient insérés tels quels dans la page RH : n'importe qui à la tablette pouvait taper un motif contenant du code qui s'exécutait chez le RH. Tout est maintenant échappé, et une politique de sécurité du contenu (CSP) est ajoutée.
3. **Justification au nom d'un collègue.** Depuis la tablette, n'importe qui pouvait voir et justifier les retards de n'importe quel employé, et c'était validé d'office. La justification se fait désormais sur le téléphone de l'employé, avec signature, et doit être validée par le RH.
4. **Code de jumelage réutilisable.** Le même code servait à lier le téléphone ET à signer les pointages, et pouvait lier plusieurs téléphones. Désormais, le code ne sert qu'une fois ; le téléphone reçoit une clé secrète à lui seul. Le code n'est plus stocké en clair.
5. **Blocage collectif à l'heure d'arrivée.** Derrière l'hébergeur, tous les employés partagent la même adresse vue par le serveur : la limite de 30 scans en 5 minutes bloquait tout le monde à 8 h. Seuls les échecs sont maintenant comptés, et l'adresse réelle est lue derrière le proxy.
6. **Mauvaise date et heure.** Le serveur mélangeait la date en heure universelle et l'heure locale de la machine. Tout est maintenant calculé dans le fuseau de l'entreprise (variable `TIMEZONE`, Africa/Abidjan par défaut).
7. **Fausse horloge sur la tablette.** L'écran affichait « heure du serveur » mais montrait l'heure de la tablette. Elle est maintenant synchronisée sur le serveur.
8. **Liste d'employés codée en dur.** 33 noms étaient créés automatiquement dans chaque nouvelle entreprise cliente. Supprimé.
9. **Code tablette attaquable par force brute.** Aucune limite d'essais : ajoutée.
10. **Sauvegardes perdues en ligne.** Les sauvegardes étaient écrites hors du disque persistant. Elles sont maintenant à côté de `data.json` (60 derniers jours conservés).
11. **Fichier de données corrompu = données effacées.** Un `data.json` illisible était remplacé par une base vide. Le serveur s'arrête maintenant et conserve le fichier pour restauration.
12. **Changement de mot de passe sans effet sur les autres sessions.** Les autres appareils connectés sont maintenant déconnectés.
13. **Requêtes intersites (CSRF).** Cookie de session en `SameSite=Strict` et requêtes de modification obligatoirement en JSON.
14. **Limite d'envoi de 60 Mo.** Ramenée à 64 Ko (3 Mo pour l'envoi d'une photo de justificatif).
15. **Compteur de retards faux.** Les arrivées à l'heure étaient comptées comme des retards dans les compteurs.
16. **Export CSV.** Accents illisibles dans Excel, guillemets non échappés, cellules pouvant contenir des formules : corrigé (séparateur point-virgule pour Excel en français).
17. **Lien Admin sur la tablette** retiré.
18. **Plusieurs QR actifs pour un même employé** : un seul à la fois.

## Reprise des données de la v1

Au premier démarrage, `data.json` est converti automatiquement :
- les téléphones déjà jumelés continuent de fonctionner ;
- les retards justifiés par le RH restent acceptés ; ceux justifiés par l'employé à la tablette passent « En attente » pour validation ;
- aucune absence automatique n'est créée pour le passé.

Faites une copie de `data.json` avant la mise à jour par précaution.

## Limite connue

Un employé peut encore prêter son téléphone à un collègue présent sur place. Aucun système sans biométrie ne l'empêche totalement ; le QR de 25 secondes rend en revanche le pointage à distance très difficile.
