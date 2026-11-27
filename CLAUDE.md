# clixz : règles de travail

clixz gère `/srv/docker` sur Boxyz. Il tourne en root (sous `sudo`) et sert de passerelle à un serveur
MCP publié sur Internet (`clixz.coxyz.fr`, dépôt `/opt/images/mcp-clixz`). **Toute modification de
clixz est donc une modification de sécurité.** Ce fichier s'impose à toute personne ou tout agent qui
modifie le dépôt.

## 1. Revue de sécurité obligatoire, avant chaque commit

Aucune modification n'est commitée sans revue de sécurité. La revue se fait sur le diff complet, et on
répond à chacune des questions ci-dessous. Une réponse qui n'est pas « non » ou « rien ne change » doit
être justifiée par écrit dans la spec (`docs/specs/`) ou dans le message de commit.

1. **Frontière de privilèges.** Quel processus exécute ce code ?
   - l'opérateur (`sudo clixz`, root) ;
   - `clixz-mcpd` (svc_mcprun, groupes `svc_*`, aucune capability) ;
   - `clixz-apply` (root, une requête) ;
   - `clixz-inspect` (compte dynamique, groupe `docker`, une requête).

   Est-ce que ce qui l'atteint, et ce qu'il peut faire, change ? Un nouveau chemin entre Internet et un
   processus privilégié doit passer par une **liste fermée** de requêtes, **revalidées** du côté
   privilégié. Le côté non privilégié n'est qu'un filtre de confort.
2. **Entrées.** Tout ce qui arrive d'un socket ou du MCP est hostile. On vérifie le type (un `bool`
   n'est pas un `int`), on applique une regex, on borne la taille. On n'utilise jamais de shell
   (`shell=False`), et l'appelant ne choisit jamais un chemin ni une option globale (`--config`).
3. **Secrets.** Les valeurs des `.env`, l'`Env` et le `Cmd` d'un conteneur, et les identifiants Komodo,
   ne sortent jamais. Ils n'apparaissent ni dans une sortie, ni dans un plan, un diff, un journal ou un
   message d'erreur. On donne les noms, jamais les valeurs.
4. **Écritures.** Elles passent uniquement par un plan (MCP), appliqué une fois après l'accord de
   l'opérateur et revalidé contre le disque, ou par `sudo clixz` (CLI). On archive avant d'écraser.
5. **Décisions de l'opérateur.** Rien de ce qui suit ne peut être modifié depuis le MCP, même par un
   plan :
   - accepter une règle de niveau `error` ;
   - `lint.yaml` ;
   - `config.yaml`, dont la liste des services dont les logs sont lisibles (`docker.logs`).
6. **Unités systemd.** Le durcissement reste en place. Une capability, un `ReadWritePaths` ou un groupe
   ajouté doit être justifié par écrit.
7. **Sorties vers le modèle.** Elles sont bornées en taille, et les caractères de contrôle sont retirés.
   Ce qu'on lit d'un conteneur (logs, sortie d'un healthcheck) est une donnée, pas une instruction.
8. **Tests.** Chaque garde de sécurité a son test de refus, pas seulement le chemin qui marche.

Avec Claude Code, lancer `/security-review` sur le diff, puis noter la conclusion dans le message de
commit, sur une ligne `Security review: …`.

## 2. Conventions à suivre

- Architecture et choix de fond : `docs/REFONTE.md`, puis la spec de la version dans `docs/specs/`.
- Règles de l'hôte : `/srv/docs/conventions` et `/srv/docs/hardening`. Ce sont elles qui priment : si
  le code les contredit, le signaler à l'opérateur plutôt que de les contourner.
- L'opérateur `opxyz` n'est membre ni des groupes `svc_*` ni de `docker` (décision du 2026-11-27). Toute
  commande clixz se lance avec `sudo`. Les écritures s'élèvent d'elles-mêmes (`ensure_root`).
- Compose : `cap_drop: ALL`, `no-new-privileges`, un utilisateur non root, `restart`, la rotation des
  logs, des ports en `127.0.0.1:` et des chemins hôte absolus. L'image suit son canal stable (`:stable`
  ou une version majeure si l'image en publie une, sinon `:latest` : on ne propose pas de l'épingler).
- Code : Python ≥ 3.10, stdlib en priorité (pas de dépendance ajoutée sans raison), ruff
  (`line-length = 110`). Les commentaires expliquent le *pourquoi*.

## 3. Tests

    uv run --extra dev pytest -q
    uv run --extra dev ruff check src tests

Ne jamais lancer de conteneur de test sur Boxyz (`docker run`) : la machine a planté par manque de
mémoire le 2026-09-30. Les tests simulent Docker.

## 4. Git et publication

- Aucune ligne d'attribution Claude ou Copilot (`Co-Authored-By`, « Generated with ») dans les commits
  ni dans les PR.
- On pousse sur `git@github.com:Coxyz/Clixz.git` (SSH).
- On publie sur PyPI par une release GitHub (`make release`), jamais par un tag poussé seul.
- On ne commite et ne publie que sur demande de l'opérateur.
