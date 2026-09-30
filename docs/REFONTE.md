# Refonte clixz + architecture services — plan

État: proposition. Basé sur l'audit lecture-seule de /srv/docker du 2026-08-29
(17 services, 19 conteneurs, 5 catégories) et sur la relecture des 6126 lignes de clixz.

## 0. Principe directeur

clixz est un outil **pour l'humain** : inventorier, vérifier, créer, décrire.
Ce n'est ni un générateur de compose, ni un moteur de politique de sécurité.

Constat de l'audit qui justifie tout le reste :
- ~70 % de l'effort du système porte sur les permissions du système de fichiers ;
- ~90 % du risque réel est dans 3 conteneurs privilégiés et dans ce que NPM publie
  sur Internet.
Le système n'est pas trop complexe pour un homelab : il est complexe au mauvais endroit.

## 1. clixz v2 — ce qui disparaît

| Élément | Lignes | Raison |
|---|---|---|
| `spec.py` (spec.json → compose généré) | 874 | Modèle fermé déjà rouvert 2× (Exceptions, elevated.yaml). Inexprimable = ingérable. |
| `/etc/clixz/elevated.yaml` | — | Sans génération de compose, plus rien à autoriser. |
| Toute la machinerie ACL POSIX | ~400 (dans policy.py) | Voir §3 : plus aucune ACL nécessaire. |
| `dev.py` (`clixz dev add/remove/list`) | 217 | code-server n'est pas déployé. Principal `boxyz_dev` supprimé. |
| `update.py` (patch JSON sur spec) | 214 | Sans spec.json, sans objet. |
| Fusion `admind.py` + `runnerd.py` | ~300 économisées | Un seul daemon (voir §4). |
| `build/lib/coxyz/` | — | Artefact local pré-renommage, non versionné. À supprimer du disque. |

Cible : **~2500 lignes** au lieu de 6126.

## 2. clixz v2 — surface de commandes (10 au lieu de 18)

Lecture
  clixz ls [-C <cat>]            inventaire : service, image, ports, état, santé
  clixz show <service>           fiche : compose résumé, métadonnées, chemins, perms, conteneur
  clixz check [<service>]        audit permissions + lint compose. exit 1 sur erreur.

Écriture
  clixz new <cat>/<svc>          arbo + compose.yaml pré-rempli + .env + service.yaml
  clixz fix [<service>]          corrige owner/mode (ex-`apply`)
  clixz rm <service>             archive dans /srv/docker/.archive

Métadonnées
  clixz meta <service>           valide / scaffolde le service.yaml
  clixz manifest                 agrège les service.yaml publics → manifest.json

Divers
  clixz image add|rm|ls <name>   contextes de build sous /opt/images
  clixz config                   affiche / édite /etc/clixz/config.yaml

Supprimées : `apply` (renommé `fix`), `create` (renommé `new`), `list` (renommé `ls`),
`archive`/`archived` (fusionnés dans `rm` + `ls --archived`), `dev *`, `update`,
`meta scaffold`/`meta validate` (fusionnés), `show-config`/`edit` (fusionnés).

## 3. Modèle de fichiers et de permissions — simplification

### Arborescence par service (inchangée)

    /srv/docker/<cat>/<svc>/
    ├── compose.yaml     source de vérité, écrit à la main
    ├── .env             secrets
    ├── service.yaml     métadonnées (dashboard, MCP, doc)
    ├── config/          entrées, écrit par l'humain, monté :ro
    └── data/            état, écrit par le conteneur

### Règles : 7 → 3, et **zéro ACL POSIX**

    rules:
      dir:  { mode: "750" }                                # catégorie, service, config, data
      file: { mode: "640" }                                # compose.yaml, service.yaml, autres
      env:  { mode: "640", owner: "root:docker" }          # secrets

Trois suppressions qui ne coûtent aucune sécurité :

1. **ACL `boxyz_komodo` supprimée.** komodo-periphery tourne en uid 0 avec le
   socket Docker : il lit et écrit déjà tout, l'ACL est décorative.
2. **ACL `boxyz_dev` supprimée.** Elle sert code-server, absent.
3. **ACL `docker:r` sur `.env` remplacée par `root:docker 640`.** Effet identique,
   mécanisme ordinaire.

Conséquence : plus de `setfacl`, plus de masque ACL, plus d'`#effective:`, plus de
la section « ACL handling » du README, plus de `getfacl` dans l'audit. C'est la
simplification la plus rentable du plan.

### Comptes système `svc_*` : GARDÉS

Ils sont la seule chose qui empêche un des 9 conteneurs non-root d'une catégorie de
lire les données d'une autre. Vérifié réel par l'audit (catégories 0750, `other::---`,
aucun `svc_*` membre d'un autre).

Mais : **retirer opxyz des 5 groupes `svc_*`**. Il est dans `docker`, donc root sans
mot de passe : ces appartenances n'ouvrent rien de neuf et font croire à un
cloisonnement qui, pour lui, n'existe pas.

    sudo gpasswd -d opxyz svc_apps
    sudo gpasswd -d opxyz svc_automation
    sudo gpasswd -d opxyz svc_infra
    sudo gpasswd -d opxyz svc_monitoring
    sudo gpasswd -d opxyz svc_network
    sudo gpasswd -d opxyz boxyz_dev

## 4. Le compose : template + lint, plus de génération

`clixz new` écrit un compose.yaml **complet et modifiable**, pas un fichier
« do not hand-edit » :

    services:
      <svc>:
        image: TODO
        container_name: <svc>
        restart: unless-stopped
        user: "<uid>:<gid>"            # compte de la catégorie
        security_opt: [no-new-privileges:true]
        cap_drop: [ALL]
        networks: [boxyz_network]
        env_file: [.env]
        volumes:
          - ./config:/config:ro
          - ./data:/data
        logging:
          driver: json-file
          options: { max-size: 10m, max-file: "3" }
    networks:
      boxyz_network: { external: true }

`clixz check` lit le compose et **avertit** (jamais bloque) sur :
- absence de `cap_drop: ALL` / `no-new-privileges` / `restart`
- `privileged: true`, `network_mode: host`, montage de `docker.sock`, montage de `/`
- port publié sur `0.0.0.0` (suggère `127.0.0.1:`)
- image en `:latest`
- `env_file` pointant hors du service
- absence de `logging` (rotation)
- absence de healthcheck

Différence de fond avec l'ancien système : un avertissement se lit et se décide ;
une impossibilité d'expression se contourne hors du système.

## 5. Le pont MCP

**Décision : un seul daemon `clixz-mcpd`, non privilégié. `clixz-admind` disparaît.**

Compte `svc_mcprun`, aucune capability, durcissement systemd conservé (il est bon).
`ReadOnlyPaths=/srv/docker /etc/clixz`. Le daemon n'écrit jamais, nulle part.

- Lecture (`ls`, `show`, `check`, `manifest`) : exécutée directement, allowlist de
  sous-commandes, arguments regex-validés, `shell=False`.
- Écriture (`new`, `fix`, `rm`) : le daemon renvoie un **plan** — diff des fichiers,
  liste des chemins touchés, commande exacte à taper. Rien n'est écrit.
- L'humain exécute : `sudo clixz fix <service>`, `sudo clixz new <cat>/<svc>`.

Ce qui disparaît avec admind : l'unité root avec `CAP_DAC_OVERRIDE`, le socket
`root:svc_mcprun`, le contrôle `SO_PEERCRED`, le protocole de relais, le store de
plans avec TTL, le binding par SHA-256 sur 3 tentatives, `PROTECTED`/`PROTECTED_CATEGORIES`.
La boucle d'approbation ne disparaît pas : elle passe par le clavier.

## 6. Architecture des services — plan par phases

Catégories et arborescence **inchangées** (apps, automation, infra, monitoring, network).

### Phase 0 — sécurité réelle, avant tout travail sur clixz

Ces points valent plus que toute la refonte de l'outil.

1. **Sortir les consoles d'administration d'Internet.** 4 des 9 URL publiées sont
   des consoles : `komodo` (pilote le conteneur qui a docker.sock — qui prend cette
   UI prend l'hôte), `proxy` (NPM lui-même), `pihole` (DNS+DHCP du LAN), `grafana`.
   Plus `ha` (privileged). La règle interne `network-ports.md` §2 l'interdit déjà.
   **Décision : NPM ne publie plus que `vault`, `cloud`, `atuin` et `ha`.**
   `komodo`, `proxy`, `pihole`, `grafana` et `code` passent derrière WireGuard/Tailscale.
   `ha` reste exposé sur décision explicite — ce qui rend le retrait de `privileged`
   (phase 3) prioritaire et non plus optionnel : c'est le seul conteneur root-hôte
   qui restera joignable depuis Internet.
2. **Supprimer l'entrée NPM `code.coxyz.fr`** : elle pointe vers un conteneur inexistant.
3. **Sauvegardes hors machine.** Bitwarden et 11 Go de Nextcloud n'en ont aucune.
   restic vers un support externe sur `bitwarden/data`, `nextcloud/data/files`,
   `home-assistant/config`, les 12 `.env`, `/etc/clixz`, `/srv/docs`.
   Risque plus probable que tous les autres.
4. **Durcir nextcloud ×3 et pihole** : ils tournent en root, sans `cap_drop`, sans
   `no-new-privileges`. Nextcloud est le service le plus exposé et le moins protégé.
5. **Remettre la supervision en marche et l'alerter** : prometheus et node-exporter
   sont exited depuis 25 h, mosquitto unhealthy, personne ne l'a vu.
   Retirer le montage `/` de node-exporter (en root, il lit les 12 `.env` et
   `/etc/shadow` — il annule la protection des secrets).
6. **`docker swarm leave --force`** : 0 service déployé, ouvre 2377/7946/4789.
7. **Vérifications root — résultats du 2026-08-29 :**
   - SSH : `port 4242`, `permitrootlogin no`, `passwordauthentication no`,
     `allowusers opxyz`. **Conforme.** Clé uniquement. Seul écart : `hardening-boxyz.md`
     annonce un drop-in `99-hardening.conf` inexistant et un port 9285 — la doc est
     fausse, pas la configuration.
   - Firewall : **`ufw` inactive** et **`DOCKER-USER` vide** (`-N DOCKER-USER`, zéro
     règle). **Aucun filtrage réseau sur l'hôte.**
   - NPM : **24 hôtes, 20 activés, `access_list_id = 0` partout** (aucune liste
     d'accès, aucune authentification devant quoi que ce soit). Le manifeste
     `service.yaml` en déclare 9 : **le catalogue ne décrit pas la réalité**.
     Croisé avec `docker ps`, 14 hôtes activés pointent vers une cible vivante :

     | Hôte | Cible | Remarque |
     |---|---|---|
     | `esp.coxyz.fr` | 192.168.1.3:6052 | **esphome — privileged + network_mode host + AppArmor off, sur Internet** |
     | `mcp.coxyz.fr` | mcp:8000 | **le MCP est public** — le token Bearer est la 1re ligne, pas la 2e |
     | `komodo.coxyz.fr` | komodo-core:9120 | console d'orchestration = root hôte |
     | `proxy.coxyz.fr` | nginx-proxy-manager:81 | admin du proxy lui-même |
     | `pihole.coxyz.fr` | pihole:80 | admin DNS + DHCP du LAN |
     | `ha.coxyz.fr`, `ha.local` ×2 | homeassistant:8123 | privileged ; 2 doublons `ha.local` |
     | `vault`, `cloud`, `atuin`, `coxyz.fr`, `boxyz.api` | bitwarden, nextcloud, atuin, nginx, api | légitimes |
     | `server.coxyz.fr`, `aixyz.api.coxyz.fr` | **192.168.1.6** | une **autre machine** du LAN, exposée via ce proxy |

     6 hôtes activés pointent vers un conteneur inexistant : `*.coxyz.fr`→`web`,
     `sftp`→`sftp:22`, `portainer`→`portainer:9000`, `adguard`, `zircon-proxy`,
     `grafana`. Inoffensifs aujourd'hui (502), mais **activés** : le jour où un
     conteneur nommé `portainer` ou `adguard` apparaît, il est public sans décision.
     Le wildcard `*.coxyz.fr` réserve en plus tout sous-domaine non listé.

8. **Rebinder les ports publiés — conséquence du point 7.** Sans firewall, tout port
   publié sur `0.0.0.0` est joignable par n'importe quel appareil du LAN, sans TLS et
   sans passer par NPM : `9120` (console Komodo = contrôle du daemon Docker = root),
   `6052` (esphome, privileged), `1883` (MQTT en clair), `2377/7946/4789` (Swarm), plus
   `192.168.1.4:80/443` (admin pihole) et `192.168.1.5:8123` (HA) via macvlan.

   **Retirer un hôte de NPM ne ferme donc pas le service.** Les deux gestes vont
   ensemble : sortir du reverse proxy *et* rebinder en `127.0.0.1:` (ou sur l'interface
   Tailscale) dans le compose.

   `ufw enable` ne suffirait pas : Docker insère ses règles en amont de ufw. Le binding
   dans le compose est plus simple et plus fiable qu'une règle `DOCKER-USER`. C'est
   exactement ce que le lint de `clixz check` v2 doit signaler.
8. **Archiver ou réparer `birdnet-pi`** : compose pointe vers un dossier inexistant.

### Phase 1 — clixz v2 (§1 à §5)

Ordre : supprimer spec.py et elevated.yaml → simplifier policy.py (retrait ACL) →
nouvelle surface de commandes → fusion des daemons → mise à jour du MCP → docs.

### Phase 2 — régularisation des zones hors modèle

- `/srv/docker/network/npm/data/{app,letsencrypt}` en `root:root` : seuls chemins de
  service hors du modèle `svc_*`. Régulariser ou documenter comme exception assumée.
- Les deux `exclude:` sur `infra/komodo*/config` : deux trous déclarés dans l'audit.
- `/srv/docker/.archive` en 0700, hors du champ de `clixz check`, croît sans surveillance.
- Nettoyer les dérives de nommage `coxyz` → `clixz` (en-tête de config.yaml,
  `Documentation=/opt/repos/clixz-cli/` dans les units, docs).

### Phase 3 — durcissement des 3 conteneurs root-hôte

- **`homeassistant` : retirer `privileged` — priorité haute**, puisqu'il reste publié
  sur Internet (décision §6 phase 0.1). Il a déjà `/dev`, `NET_ADMIN`, `NET_RAW`, une
  IP macvlan et `/run/dbus` : `privileged` est probablement superflu. À tester service
  par service (Bluetooth, Z-Wave/Zigbee USB, découverte réseau).
- `esphome` : image figée à décembre 2024. Mettre à jour, et évaluer si
  `network_mode: host` reste nécessaire (mDNS).
- `komodo-periphery` : docker.sock est structurel. Au minimum, retirer `/proc` rw et
  restreindre le montage `/srv/docker` rw.

## 7. Documentation

1078 lignes de règles dans `/srv/docs` dont 553 pour `hardening-boxyz.md`, avec au
moins deux divergences constatées avec le réel (port SSH, drop-in absent). Une doc
qui a dérivé du réel est pire qu'une doc absente : elle est crue.

→ **Fait le 2026-08-29.** `/srv/docs` réécrit :

- `conventions/permissions-acl.md` → **`permissions.md`** : trois règles, plus
  d'ACL, et §6 explique pourquoi les trois bénéficiaires n'en avaient pas besoin.
- `conventions/instruction-compose.md` → **`compose.md`** : le compose est écrit
  à la main, §6 explique pourquoi la génération a été abandonnée, §5 liste ce que
  le lint signale et à quel niveau.
- `conventions/network-ports.md` : ajoute l'absence de filtrage réseau et
  pourquoi `ufw enable` n'y changerait rien, et `clixz exposed`.
- `conventions/infra-overview.md` : `clixz` et non `coxyz`, plus de principals,
  plus de renvoi à un `service-inventory.md` inexistant — l'inventaire se lit
  avec les commandes.
- `hardening/hardening-boxyz.md` : trois affirmations fausses corrigées avec la
  date (drop-in SSH inexistant, chemin de Lynis, « n'expose que NPM en 80/443 »),
  plus un §12 qui consigne l'audit.
- `config/compose.yaml` : remplacé par la sortie réelle de `clixz new`, donc les
  deux ne peuvent plus diverger. Passé de 0775 à 0644.

Références mortes supprimées : `service-inventory.md` et `compose-conventions.md`
n'ont jamais existé et étaient cités 38 fois.

⚠️ `/srv/docs` n'est pas un dépôt git : ces modifications ne sont pas versionnées
ni annulables par un `git checkout`.

## 8. Nommage

**Décision : trois noms distincts et assumés** — `coxyz` (domaine public), `boxyz`
(l'hôte et son réseau docker), `clixz` (l'outil). On corrige seulement les résidus
du renommage, qui n'ont aucun impact technique mais coûtent du temps à chaque lecture :

- en-tête de `/etc/clixz/config.yaml` : dit encore `# coxyz CLI configuration` / `/etc/coxyz/config.yaml`
- `Documentation=file:/opt/repos/clixz/deploy/README.md` dans les units — vérifier la cible
- occurrences de `coxyz check` / `coxyz` dans `/srv/docs`
- `build/lib/coxyz/` sur le disque (non versionné, artefact pré-renommage) : à supprimer

## 9. Décisions prises (2026-08-29)

| Question | Décision |
|---|---|
| spec.json → compose généré | **Supprimé.** compose.yaml écrit à la main, template + lint non bloquant. |
| runnerd + admind | **Fusionnés en un `clixz-mcpd` non privilégié.** admind supprimé. |
| plan → apply | **Conservé, simplifié.** Le MCP produit le plan, l'humain exécute au clavier. |
| Comptes `svc_*` | **Gardés** (protègent 9 conteneurs non-root), **retirés d'opxyz**. |
| ACL POSIX | **Supprimées entièrement.** `.env` passe en `root:docker 640`. |
| Exposition Internet | `vault`, `cloud`, `atuin`, `ha`. Le reste derrière VPN. |
| Nommage | Trois noms distincts ; corriger les résidus seulement. |

## 10. Reste à décider plus tard

- Cible et support des sauvegardes (NAS, disque USB rotatif, objet distant).
- WireGuard ou Tailscale pour l'accès admin.
- Sort de `birdnet-pi` : réparer ou archiver.
- `/srv/docker/network/npm/data` en root:root : régulariser ou documenter comme exception.
- Épinglage des 9 images en `:latest`.


---

## 11. État de la refonte (branche `v2-refonte`)

Fait :

- `spec.py` (874 l.), `dev.py`, `update.py`, `admind.py`, `runnerd.py`, `compat.py`
  supprimés ; `/etc/clixz/elevated.yaml` sans objet.
- Moteur ACL retiré de `policy.py` ; il ne reste que la *détection* des entrées
  laissées par v1, que `clixz fix` efface avec `setfacl -b`.
- `compose.py` : gabarit durci + lint non bloquant.
- `npm.py` + `clixz exposed` : croisement base NPM ↔ `service.yaml`.
- `mcpd.py` : un seul démon, non privilégié, incapable d'écrire.
- `cli.py` réécrit : 11 commandes, `--json` partout, `--plan` sur les verbes mutants.
- `deploy/clixz-mcpd.service`, `default_config.yaml`, README, 98 tests.
- `/opt/images/mcp-coxyz/app/` adapté (hors dépôt) : `service_apply` supprimé,
  `service_exposed` ajouté, socket `clixz-mcpd`.

6 126 → 2 850 lignes, 18 → 11 commandes.

Deux bugs réels trouvés par les tests pendant l'écriture :

1. `_lint_volumes` ratait le montage `/` — `"/".rstrip("/")` vaut `""`, donc la
   comparaison `== "/"` échouait. C'est exactement le montage de `node-exporter`
   que l'audit avait relevé à la main.
2. L'ordre des correctifs plaçait `chmod` avant `setfacl -b`. Sur un chemin
   portant une ACL étendue, `chmod` écrit le *masque* et non les bits de groupe :
   `chmod 640` puis `setfacl -b` ne laisse pas 640. v1 contournait le piège en
   ne faisant jamais de `chmod` sur un chemin ACL ; v2 retire les ACL d'abord.

Reste à faire côté humain : `docs/TODO-OPXYZ.md`.
