# Stage 3 — Normalization, branding and deduplication

Stage 3 consumes the parser from Stage 2 and produces stable, branded links.

It performs:

- semantic deduplication that ignores the original profile name;
- deterministic query ordering and host normalization;
- canonical VMess JSON/Base64 output;
- canonical Shadowsocks SIP002 output;
- replacement of every profile name with the Dragon Config Hub brand;
- stable SHA-256 fingerprints for later grouping and statistics.

The current naming format is:

```text
🌍 Unknown | Reality | @anonymouskeys
```

Country detection is intentionally deferred to Stage 4. Stage 4 will pass a
country code/name and produce names such as:

```text
🇩🇪 Germany | Reality | @anonymouskeys
```

## Usage

```bash
python3 scripts/normalize_configs.py subscription.txt --format links
cat subscription.txt | python3 scripts/normalize_configs.py --format json
```

## Exit codes

- `0` — at least one normalized configuration;
- `1` — input or normalization failure;
- `3` — no valid configurations.

Malformed entries remain isolated by the Stage 2 parser. One invalid link does
not abort processing of valid links.
