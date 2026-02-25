# Releases

## Download prebuilt binaries

Use the Quickstart snippet in `README.md` (downloads from `releases/latest`).

## Cut a release (maintainers)

Releases are created by pushing a `v*` git tag. GitHub Actions builds binaries via Nix and uploads
tarballs + sha256 sums.

```bash
git tag v0.1.0
git push origin v0.1.0
```

(Optional) watch the workflow:

```bash
gh run list --workflow release --limit 5
```
