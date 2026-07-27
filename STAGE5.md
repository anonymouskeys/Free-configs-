# Stage 5 — Automated updates

The workflow `.github/workflows/update-configs.yml` runs:

- manually through `workflow_dispatch`;
- automatically every four hours;
- with one active update at a time.

Private source URLs are read only from repository secrets named
`SOURCE_SUB_01` through `SOURCE_SUB_20`.

The updater never writes URLs to logs or generated files. Sources are shown
only as numeric identifiers:

```text
Source 01  ✅ 1843 configs
Source 02  ❌ timeout
Source 03  ✅ 922 configs
```

A failed source is skipped. Existing output remains untouched only when all
configured sources fail. Successful runs generate:

- `output/all.txt` — normalized, deduplicated and branded subscription;
- `output/status.json` — numeric source statuses and aggregate counts.

The workflow commits only `output/`, and only when its contents changed.

## Local validation

The updater expects secrets in environment variables. For a harmless local
test, point one variable at a temporary local HTTP server or run only tests:

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile scripts/update_hub.py
```

Do not place private source URLs in tracked files, shell history, issue text or
workflow YAML.
