# Stage 6 — Dynamic README and subscription catalog

Stage 6 generates `README.md` directly from the published `output/` tree.

The README includes:

- the complete subscription;
- subscriptions grouped by protocol;
- subscriptions grouped by transport and security;
- subscriptions grouped by inferred location;
- a live configuration count for every generated subscription;
- aggregate update statistics from `output/status.json`;
- Anonymous Keys branding, Telegram community link and donation details.

The GitHub Actions workflow runs `scripts/generate_readme.py` after output generation and commits the README together with changed subscription files.

Generate it locally with:

```bash
python3 scripts/generate_readme.py --output-dir output --readme README.md
```

All source URLs remain private in GitHub Actions secrets. The README contains only public generated subscription links.
