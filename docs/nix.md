# Nix

This repo uses Nix flakes.

## Install Nix (Determinate Systems, non-interactive)

```bash
sudo curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix \
  | sh -s -- install --no-confirm

. /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
```

## Why `--accept-flake-config`?

This repo sets `nixConfig.extra-substituters`.
Nix will prompt unless you pass `--accept-flake-config` or set:

```conf
accept-flake-config = true
```

Add that to `~/.config/nix/nix.conf` or `/etc/nix/nix.conf`.

## Common commands

```bash
nix build --accept-flake-config
nix run --accept-flake-config .#bench
nix develop --accept-flake-config
```
