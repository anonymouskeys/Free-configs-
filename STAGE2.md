# Stage 2 — Subscription parser

`subscription_parser.py` is an offline parser. It does not download sources and
does not print or store source URLs.

Supported schemes:

- `vless://`
- `vmess://`
- `trojan://`
- `ss://`
- `hysteria://`
- `hysteria2://`
- `hy2://`

Supported input containers:

- plain text;
- standard Base64;
- URL-safe Base64;
- one nested Base64 layer.

## Local checks

```bash
python3 -m unittest discover -s tests -v
python3 scripts/subscription_parser.py subscription.txt
cat subscription.txt | python3 scripts/subscription_parser.py --format jsonl
```

Exit codes:

- `0` — at least one configuration parsed;
- `1` — input/read error;
- `2` — `--strict` was used and invalid entries were found;
- `3` — no valid configurations were found.

Invalid links are isolated in `issues`; they do not stop parsing of other
entries. Semantic deduplication, renaming, transport grouping and country
classification belong to later stages.
