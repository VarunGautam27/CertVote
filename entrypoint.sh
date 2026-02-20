#!/bin/sh
set -e

# Generate config.json dynamically for Docker DB connection
if [ -f /app/config.json ]; then
  echo "config.json exists. Updating DB settings for Docker..."
else
  echo "config.json not found. Creating minimal config.json..."
  echo '{}' > /app/config.json
fi

python3 - <<'PY'
import json, os

path = "/app/config.json"
with open(path, "r", encoding="utf-8") as f:
    try:
        cfg = json.load(f)
    except Exception:
        cfg = {}

cfg.setdefault("db", {})
cfg["db"]["host"] = os.environ.get("DB_HOST", "mysql")
cfg["db"]["port"] = int(os.environ.get("DB_PORT", "3306"))
cfg["db"]["user"] = os.environ.get("DB_USER", "certvote_user")
cfg["db"]["password"] = os.environ.get("DB_PASSWORD", "certvote_pass")
cfg["db"]["database"] = os.environ.get("DB_NAME", "itclub_vote")

with open(path, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2)

print("✅ Wrote Docker DB config into config.json:", cfg["db"])
PY

echo "Starting CertVote..."
exec python3 /app/app.py
