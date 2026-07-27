# Stage 4 — Classified output generator

The generator creates a complete public subscription tree on every successful
run:

```text
output/
├── all.txt
├── protocol/
│   ├── vless.txt
│   ├── vmess.txt
│   ├── trojan.txt
│   ├── ss.txt
│   ├── hysteria.txt
│   └── hysteria2.txt
├── transport/
│   ├── tcp.txt
│   ├── grpc.txt
│   ├── ws.txt
│   ├── xhttp.txt
│   ├── httpupgrade.txt
│   ├── reality.txt
│   ├── reality-vision.txt
│   └── unknown.txt
├── countries/
│   ├── de.txt
│   ├── us.txt
│   └── unknown.txt
└── status.json
```

Only categories that contain at least one configuration are created.
`protocol/hysteria.txt` combines Hysteria 1 and Hysteria 2; the separate
`hysteria2.txt` file is also retained.

Country detection is offline. It reads flags, ISO country codes and country
names from the original configuration label. It performs no DNS or GeoIP
requests. Profiles without reliable metadata are named and stored as Unknown.

The output directory is replaced atomically after generation, so obsolete
category files cannot survive a later update.

## Local validation

```bash
python3 -m unittest discover -s tests -v
python3 scripts/generate_outputs.py subscription.txt --output-dir output-test
```
