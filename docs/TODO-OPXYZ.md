# À faire de ton côté — actions système

Établi le 2026-08-29 à partir de l'audit de `/srv/docker`, **remis à jour le
2026-09-30** d'après l'état constaté sur la machine. clixz ne fait rien de tout
ceci à ta place : ce sont des gestes sur l'hôte, hors du dépôt.

Ordre = priorité décroissante. Ce qui est fait est listé à la fin.

---

## A. Sauvegardes — le risque le plus probable de l'audit

Aucun outil installé (`restic`, `borg` absents), aucun timer. Bitwarden et
Nextcloud n'ont **aucune** copie hors de la machine.

- [ ] Choisir un support externe (NAS, disque USB rotatif, stockage objet distant)
- [ ] `restic` + timer systemd sur : `apps/bitwarden/data`,
      `apps/nextcloud/data/files`, `automation/home-assistant/config`, les `.env`,
      `/etc/clixz`, `/srv/docs`
- [ ] Tester une restauration (une sauvegarde non testée n'est pas une sauvegarde)

## B. Mémoire du Pi

Le 2026-09-30, une charge supplémentaire (des conteneurs de test lancés à côté
de la production) a saturé les 4 Go et fait planter la machine — DNS du LAN
compris, puisque Pi-hole tourne dessus.

- [ ] Poser des `mem_limit` sur les services qui n'en ont pas (nextcloud et ses
      deux bases, homeassistant, pihole, la pile komodo, npm, bitwarden)
- [ ] Ne rien lancer de lourd sur cet hôte sans marge mesurée (`free -h`)

## C. Durcissement des conteneurs

Ce que `clixz check` montre encore, hors images non épinglées. Chaque point
demande un essai sur le service réel, un à la fois, avec l'ancien compose prêt à
être remis — une liste de `cap_add` incomplète empêche le conteneur de démarrer.

- [ ] **`homeassistant` : retirer `privileged`.** Il reste publié sur Internet.
      Il a déjà `/dev`, `NET_ADMIN`, `NET_RAW`, une IP macvlan et `/run/dbus`.
      À vérifier après coup : Bluetooth, clés USB Zigbee/Z-Wave, découverte réseau.
- [ ] `nextcloud`, `nextcloud-db`, `nextcloud-redis` : `cap_drop: ALL` +
      `no-new-privileges`. Listes à essayer : nextcloud `CHOWN DAC_OVERRIDE FOWNER
      SETGID SETUID NET_BIND_SERVICE` ; postgres `CHOWN DAC_OVERRIDE FOWNER SETGID
      SETUID` ; redis `CHOWN SETGID SETUID`.
- [ ] `komodo-postgres`, `komodo-ferretdb` : `cap_drop: ALL` (mêmes capacités
      que postgres pour le premier)
- [ ] `pihole` : `cap_drop: ALL` en gardant ses capacités réseau, et
      `no-new-privileges` — à essayer hors des heures où le LAN a besoin du DNS
- [ ] `esphome` : image figée à décembre 2024, à mettre à jour
- [ ] `komodo-periphery` : évaluer `/proc` en lecture seule

## D. Exposition

`clixz exposed` fait foi. État au 2026-09-30 : 14 hôtes dans le reverse proxy,
9 activés. `komodo`, `proxy` et `pihole` sont derrière la liste d'accès
`tailscale-only`.

- [ ] `mcp.coxyz.fr` et `playwright.coxyz.fr` sont publiés sans `url:` dans leur
      `service.yaml` : les déclarer, ou les retirer du proxy
- [ ] `code.coxyz.fr` et `grafana.coxyz.fr` sont déclarés dans un `service.yaml`
      mais absents du proxy : retirer l'`url:` tant que ces services ne tournent pas
- [ ] Supprimer les hôtes désactivés devenus inutiles (`esp`, `aixyz.api`,
      `*.coxyz.fr`) : désactivé ne suffit pas, l'entrée redevient vivante le jour
      où on la réactive par mégarde
- [ ] `mosquitto` : `1883` est publié sur toutes les interfaces, en clair
      (accepté dans `ignore.yaml`) — envisager TLS
- [ ] `docker swarm leave --force` : Swarm est toujours actif, 0 service, et
      ouvre 2377/7946/4789

## E. Supervision

`prometheus`, `node-exporter` et `grafana` ne tournent plus du tout : il n'y a
aucune supervision, et c'est ainsi que le plantage du 2026-09-30 n'a été vu que
par ses effets.

- [ ] Redéployer `monitoring/prometheus` (le compose ne monte plus `/`) et
      `monitoring/grafana`
- [ ] Mettre une alerte sur l'absence de métriques et sur la mémoire disponible

## F. Comptes système

Plus aucune ACL n'utilise ces comptes depuis clixz 2.0.

- [ ] Retirer `opxyz` des groupes de service (il est dans `docker`, donc root
      sans mot de passe : ces appartenances n'ouvrent rien de neuf) —
      `sudo gpasswd -d opxyz <groupe>` pour `svc_apps`, `svc_automation`,
      `svc_infra`, `svc_monitoring`, `svc_network`, `boxyz_dev`
- [ ] `/opt/images` et `/opt/repos` appartiennent à `boxyz_dev` : changer leur
      propriétaire **avant** de supprimer ce compte
- [ ] Supprimer le compte `boxyz_dev` et le groupe `boxyz_komodo`, puis la ligne
      `group_add: "1005"` des compose `komodo` et `komodo-periphery`

## G. Accès admin par le tailnet

- [ ] Activer l'approbation manuelle des appareils (`Settings → Device approval`)
- [ ] MFA sur le compte d'identité, pas seulement sur Tailscale
- [ ] Décider pour Tailscale SSH : il court-circuite le `sshd` durci (port 4242,
      clé uniquement) — deux portes au lieu d'une

## H. Rangement

- [ ] Épingler les images en `:latest` ou sans tag (`clixz check` les liste)
- [ ] `birdnet` : le service n'a jamais démarré → le déployer ou `sudo clixz rm`
- [ ] `/home/opxyz/komodo-docker-config` (identifiants de registry de Periphery)
      → `/srv/docker/infra/komodo-periphery/config/docker/`
- [ ] `/srv/docker/network/npm/data/{app,letsencrypt}` en `root:root` : seuls
      chemins de service hors du modèle `svc_*` → régulariser ou documenter
- [ ] `/srv/docker/.archive` (0700) croît sans surveillance → purge ou rotation
- [ ] Mettre `/srv/docs` sous git : ces documents ont déjà dérivé plusieurs fois
      sans que rien ne le signale
- [ ] Les tags git `v0.2.0` à `v1.2.1` pointent sur l'historique d'avant la
      réécriture du 2026-09-30 → les déplacer ou les supprimer

---

## Fait

- clixz 2.x déployé : `clixz-admind` et `clixz-runnerd` retirés, `clixz-mcpd`
  actif, config migrée, ACL de la v1 effacées par `clixz fix`, image `mcp-coxyz`
  reconstruite, `elevated.yaml` supprimé
- `manifest.json` et `npm-hosts.json` dans `/etc/clixz`, rafraîchis par
  `clixz-snapshot.timer`
- Komodo Periphery et Core : `cap_add: [DAC_OVERRIDE]` à la place de l'ACL
  `boxyz_komodo` (voir le rectificatif dans `REFONTE.md` §3)
- Consoles `komodo`, `proxy`, `pihole` derrière Tailscale + liste d'accès NPM ;
  admin NPM sur `127.0.0.1:8181` ; port 9120 de Komodo plus publié sur l'hôte
- Hôtes morts du proxy supprimés (`sftp`, `portainer`, `adguard`, `zircon`,
  `server`, doublons `ha.local`)
- Tailscale installé sur l'hôte
- `/srv/docs` réécrit et tenu à jour avec clixz 2.2
