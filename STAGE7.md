# Stage 7 — Reliable automated README publishing

The workflow already generated the dynamic `README.md`. Stage 7 hardens the
publication step so every scheduled run publishes `output/` and `README.md`
together.

## Behaviour

- runs at minute 17 every four hours and can still be started manually;
- verifies that `README.md`, `output/all.txt`, and `output/status.json` exist;
- stages both `output/` and `README.md` before checking for changes;
- skips empty commits;
- commits generated subscriptions and README counters together;
- retries a push once after `git pull --rebase` when the remote branch changed
  while the workflow was running.

The source subscription URLs remain available only through GitHub Secrets.
