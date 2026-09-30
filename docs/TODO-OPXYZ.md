# À faire de ton côté — actions système

Établi le 2026-08-29 à partir de l'audit de `/srv/docker` et des vérifications root.
clixz v2 ne touche à rien de tout ceci : ce sont des gestes sur la machine,
hors du dépôt.

Coche au fur et à mesure. Ordre = priorité décroissante.

---

## A. Fermer l'exposition Internet  — ✅ en grande partie fait

État constaté à l'audit : 24 hôtes, 20 activés, `access_list_id = 0` partout.
État au 2026-08-29 après ton passage : 15 hôtes, 7 activés, 9 supprimés.

- [x] ~~Désactiver `esp.coxyz.fr`~~ (esphome privileged + host net, sur Internet)
- [x] ~~Désactiver `mcp.coxyz.fr`~~ (Internet → token → démon root)
- [x] ~~Supprimer les cibles mortes~~ `sftp`, `portainer`, `adguard`, `zircon`,
      `server`, les doublons `ha.local`, le wildcard `*.coxyz.fr`→`web`
- [ ] Supprimer `komodo.coxyz.fr`, `proxy.coxyz.fr`, `pihole.coxyz.fr`
      → **étape 3c**, après avoir prouvé l'accès par le tailnet
- [ ] Supprimer `code.coxyz.fr` et `grafana.coxyz.fr` (conteneurs inexistants ;
      désactivés ne suffit pas — ils redeviennent vivants si un conteneur de ce
      nom réapparaît)
- [ ] Décider du sort de `aixyz.api.coxyz.fr` → 192.168.1.6 (désactivé pour
      l'instant ; c'est une autre machine du LAN)
- [ ] Réactiver `coxyz.fr` et `boxyz.api.coxyz.fr` si tu veux retrouver ton
      dashboard public (désactivés pour l'instant)

Reste activé : `atuin`, `cloud`, `vault`, `ha`, plus les 3 consoles à retirer.

## B. Accès admin par le tailnet — en cours

- [x] ~~Installer Tailscale sur l'hôte~~ — `100.113.235.49`, interface montée
- [ ] Installer le client sur ton laptop et ton téléphone (même compte)
- [ ] **Activer l'approbation manuelle des appareils** (`Settings → Device
      approval`). Sans elle, un compte Tailscale compromis = accès immédiat au
      réseau admin. Avec elle, l'appareil de l'attaquant reste en attente.
- [ ] MFA sur le compte d'identité (Google/GitHub), pas seulement sur Tailscale
- [ ] Décider pour Tailscale SSH (`RunSSH: true` actuellement) : le garder, ou
      `sudo tailscale set --ssh=false`. Il court-circuite ton `sshd` durci
      (port 4242, `AllowUsers opxyz`, clé uniquement) — deux portes au lieu d'une.
- [ ] **Étape 3a** — vérifier `http://100.113.235.49:9120` depuis la 4G
- [ ] **Étape 3b** — publier l'admin NPM : ajouter `"100.113.235.49:81:81"` aux
      ports de `/srv/docker/network/npm/compose.yaml` (l. 21-23), redéployer,
      vérifier `http://100.113.235.49:81` depuis la 4G
- [ ] **Étape 3d** — restreindre Komodo : `"100.113.235.49:9120:9120"` dans
      `/srv/docker/infra/komodo/compose.yaml` (l. 66), redéployer
- [ ] Optionnel — subnet router : `sudo tailscale up
      --advertise-routes=172.19.0.0/16,172.20.0.0/16,192.168.1.0/24` puis
      approuver les routes. Donne accès à n'importe quel conteneur et au LAN
      (donc pihole) sans publier un seul port.

## C. Fermer l'exposition LAN

Constaté : **`ufw` inactive** et **`DOCKER-USER` vide**. Aucun filtrage réseau.
Tout port publié sur `0.0.0.0` est joignable par n'importe quel appareil du LAN.
`ufw enable` ne suffirait pas : Docker insère ses règles en amont de ufw. Le bon
geste est le binding dans le compose.

- [ ] `komodo-core` : `9120` → `127.0.0.1:9120`
- [ ] `esphome` : `6052` (network_mode host — nécessite de revoir le mode réseau)
- [ ] `mosquitto` : `1883` → binding restreint, ou activer TLS
- [ ] `docker swarm leave --force` (0 service déployé, ferme 2377/7946/4789)

## D. Sauvegardes — le risque le plus probable de l'audit

Aucun outil installé (`restic`, `borg`, `rclone`, `duplicity` absents), aucun timer.
Bitwarden et 11 Go de Nextcloud n'ont **aucune** copie. Le seul dump existant est
celui de Komodo, sur le même disque que ce qu'il sauvegarde.

- [ ] Choisir un support externe (NAS, disque USB rotatif, stockage objet distant)
- [ ] `restic` + timer systemd sur : `apps/bitwarden/data`,
      `apps/nextcloud/data/files`, `automation/home-assistant/config`,
      les 12 `.env`, `/etc/clixz`, `/srv/docs`
- [ ] Tester une restauration (une sauvegarde non testée n'est pas une sauvegarde)

## E. Supervision

- [ ] Redémarrer `prometheus` et `node-exporter` (exited depuis 26 h, exit 2)
- [ ] Réparer `mosquitto` (unhealthy)
- [ ] **Retirer le montage `/`→`/rootfs` de `node-exporter`** : en root il lit les
      12 `.env` et `/etc/shadow`, ce qui annule la protection des secrets
- [ ] Mettre une alerte sur l'absence de métriques (une supervision qui ne s'alerte
      pas de sa propre panne ne couvre rien)

## F. Durcissement des conteneurs

- [ ] `nextcloud`, `nextcloud-db`, `nextcloud-redis` : root, sans `cap_drop`, sans
      `no-new-privileges`. Le service le plus exposé et le moins protégé.
- [ ] `pihole` : root, aucun `security_opt`, `SYS_TIME`
- [ ] **`homeassistant` : retirer `privileged`** — priorité haute puisqu'il reste
      publié sur Internet. Il a déjà `/dev`, `NET_ADMIN`, `NET_RAW`, une IP macvlan
      et `/run/dbus`. Tester : Bluetooth, clés USB Zigbee/Z-Wave, découverte réseau.
- [ ] `esphome` : mettre à jour l'image (figée à décembre 2024)
- [ ] `komodo-periphery` : retirer `/proc` rw, restreindre le montage `/srv/docker` rw

## G. Comptes système

- [ ] Retirer opxyz des groupes de service (il est dans `docker`, donc root sans mot
      de passe : ces appartenances n'ouvrent rien de neuf) :
      `sudo gpasswd -d opxyz svc_apps svc_automation svc_infra svc_monitoring svc_network`
      (une commande par groupe)
- [ ] `sudo gpasswd -d opxyz boxyz_dev`
- [ ] Supprimer le compte `boxyz_dev` et le groupe `boxyz_komodo` **une fois clixz v2
      déployé** (plus aucune ACL ne les utilise)
- [ ] Supprimer le compte `svc_mcprun`… non : il reste, `clixz-mcpd` tourne dessus.

## H. Déploiement de clixz v2 (quand la branche sera prête)

- [ ] Relire la branche `v2-refonte`
- [ ] Installer la nouvelle `/etc/clixz/config.yaml` (format changé — `clixz config --migrate`)
- [ ] `sudo systemctl disable --now clixz-admind.socket clixz-admind.service clixz-runnerd`
- [ ] Installer et activer `clixz-mcpd.service`
- [ ] Supprimer `/etc/clixz/elevated.yaml` (sans objet sans génération de compose)
- [ ] Reconstruire et redéployer l'image `mcp-coxyz`
      (le code dans `/opt/images/mcp-coxyz/app/` est **déjà adapté** : socket
      `clixz-mcpd`, `service_apply` supprimé, `service_exposed` ajouté — il ne
      reste qu'à builder)
- [ ] `sudo clixz check` puis `sudo clixz fix`

## I. Rangement

- [ ] Déplacer `/home/opxyz/komodo-docker-config` (credentials de registry de
      komodo-periphery) vers `/srv/docker/infra/komodo-periphery/config/docker/`
- [x] ~~`/srv/docs/config/compose.yaml` en 0775~~ — passé en 0644, et son contenu
      remplacé par la sortie réelle de `clixz new`
- [ ] Épingler les 9 images en `:latest` sur une version
- [ ] `birdnet-pi` : le compose pointe vers un dossier inexistant, le service n'a
      jamais démarré → réparer ou archiver
- [ ] `/srv/docker/network/npm/data/{app,letsencrypt}` en `root:root` : seuls chemins
      de service hors du modèle `svc_*` → régulariser ou documenter comme exception
- [ ] Réexaminer les deux `exclude:` sur `infra/komodo*/config`
- [ ] `/srv/docker/.archive` (0700) croît sans surveillance → purge ou rotation
- [x] ~~Corriger `hardening-boxyz.md`~~ — fait, avec les deux autres dérives
      trouvées au passage (chemin de Lynis `/srv/lynis` inexistant, et
      « n'expose que NPM en 80/443 » qui était faux). Tout `/srv/docs` a été
      réécrit ; **ce n'est pas versionné**, `/srv/docs` n'est pas un dépôt git.
- [ ] Envisager de mettre `/srv/docs` sous git — trois affirmations avaient
      dérivé sans que rien ne le signale
- [x] ~~`rm -rf /opt/repos/clixz/build`~~ — fait
