# Snapshots

Each subdirectory is a dated snapshot of the canonical nyalai.com pages at the moment of a Doctrine version bump.

## Directory naming convention

`YYYY-MM-DD_vX.Y.Z/` where `YYYY-MM-DD` is the UTC date of the snapshot and `vX.Y.Z` is the Doctrine version sealed on that date.

## Snapshot contents

Each snapshot directory contains :

- `doctrine.html` : nyalai.com/doctrine at the moment of snapshot
- `verdicts.html` : nyalai.com/verdicts index page
- `verdicts/vf-001.html` : individual verdict-form pages
- `doctrine/governance.html` : governance page
- `methodology/relational-blinding.html` : methodology pages (as they become live)
- `methodology.html` : methodology index
- `glossary.html` : glossary
- `assets/` : rendered CSS, JS, images, fonts inlined from the source pages
- `MANIFEST.json` : integrity record with SHA256 hash of every file, plus self-hash of the manifest

## Verifying snapshot integrity

To independently verify any snapshot :

```bash
cd YYYY-MM-DD_vX.Y.Z/
# Fetch the MANIFEST
cat MANIFEST.json
# Recompute SHA256 of each listed file and compare to the hash in MANIFEST.json
find . -type f ! -name MANIFEST.json -exec sha256sum {} \;
# Recompute the manifest self-hash (last line of MANIFEST.json declares it)
```

Any mismatch is grounds for §11.4 contestation of the archive integrity per the Refusal Doctrine.

## Snapshot list

The first snapshot will be added on the next Doctrine version bump. This placeholder file will be superseded by an `INDEX.md` listing all snapshots by date when the archive is populated.
