# nyalai-archive

Primary tier of the Nyalai two-tier archival stack.

Serves dated snapshots of the canonical pages at [nyalai.com](https://nyalai.com), reachable at [archive.nyalai.com](https://archive.nyalai.com) under Nyalai DNS control. Zero third-party chrome, zero analytics, zero external fonts.

## What this repository contains

- `src/` : Astro static site source (index page listing snapshots, layout matching nyalai.com design tokens)
- `public/snapshots/` : dated directories, one per version bump, containing wget mirrors of nyalai.com canonical URLs with `MANIFEST.json` integrity records
- `scripts/` : local hook AI-9 pre-push protection copied from the Nyalai portfolio infrastructure repository ; must be installed as a git pre-push hook before first commit
- `.github/workflows/` : Cloudflare Pages build verification workflow
- `README.md` : this file
- `LICENSE` : Creative Commons Zero v1.0 Universal (CC0-1.0), matching the license of the archived content

## Doctrine anchor

The Refusal Doctrine v0.3.4 archival mechanism obligation (b) commits Nyalai to a two-tier version-bump preservation stack. This repository implements the primary tier under Nyalai DNS control. A secondary tier of off-domain preservation mechanisms is documented internally at `nyalai_infrastructure/` in the portfolio repository, for post-Nyalai durability.

## Local development

```bash
npm install
npm run dev
# Astro dev server at http://localhost:4321
```

## Deployment

Cloudflare Pages project `nyalai-archive-site` connected to `main` branch. Every push to `main` triggers a build and deploy to archive.nyalai.com. Branch protection requires pull-request review before merge to `main`.

## Snapshot cadence

Snapshots are added by running the mirror script (source at `Badounofficial/portfolio-shared` under `scripts/archive_nyalai_mirror.sh`) on each :

- Doctrine version bump
- New verdict-form publication
- Governance page update
- Weekly cadence regardless of changes (preservation baseline)

Each snapshot is committed as a discrete pull request titled `snapshot: YYYY-MM-DD version` for audit trail readability.

## Security discipline

Before the first commit and before every push :

1. The local pre-push hook `scripts/git-pre-push-nyalai.sh` scans staged content for eight forbidden pattern categories (secrets, PII, credentials, third-party content markers, em dashes, AI signature patterns). Push is blocked on any critical hit.
2. Branch protection on `main` requires : one pull request review, hook check pass, no direct push to `main`, no force push.
3. The `.gitignore` excludes secrets, credentials, environment files, and OS artifacts belt-and-suspenders.

## License

All content in this repository is released under Creative Commons Zero v1.0 Universal (CC0-1.0). See `LICENSE`.

## Related

- [nyalai.com](https://nyalai.com) : live canonical pages
- [Refusal Doctrine](https://nyalai.com/doctrine) : archival mechanism source (§12.9)
- [Badounofficial/portfolio-shared](https://github.com/Badounofficial/portfolio-shared) : private/public portfolio infrastructure repository containing the mirror script and infrastructure documentation

## Contact

Governance and archival questions : `contact@nyalai.com` with subject line `archive question`.
