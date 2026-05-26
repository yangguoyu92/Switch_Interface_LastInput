# Catalyst Center Last Input Audit

This folder contains the Catalyst Center version only.

The script queries Cisco Catalyst Center interface inventory and reports interfaces whose `lastIncomingPacketTime` is older than a threshold.

## Files

- `catalyst_center_last_input_audit.py`: main script
- `requirements.txt`: Python dependency

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python3 catalyst_center_last_input_audit.py \
  --base-url https://dnac.example.com \
  --username myuser \
  --password mypassword \
  --months 3 \
  --output catalyst_center_last_input_report.csv
```

You can also use environment variables:

```bash
export CATC_USERNAME=myuser
export CATC_PASSWORD=mypassword
```

## Useful options

- `--include-never`: include interfaces with no `lastIncomingPacketTime`
- `--site-filter core`: only include devices whose hostname contains `core`
- `--insecure`: skip TLS certificate validation
- `--requests-per-minute 20`: cap request rate to stay under Catalyst Center API limits
- `--max-retries 5`: retry `429` and transient server errors with backoff

## Notes

- The month calculation uses `30 days * months`, so 3 months means 90 days.
- `--base-url` should be the Catalyst Center server root such as `https://10.1.1.1`. The script now also tolerates `.../dna` and `.../dna/home` and normalizes them automatically.
- This script uses Catalyst Center's `lastIncomingPacketTime` field.
- That is close to the IOS CLI `Last input` concept, but it is not the exact literal `show interfaces` text field.
- The script includes client-side rate limiting and retry handling for `429 Too Many Requests` and common `5xx` responses.
- If your Catalyst Center uses a self-signed certificate, add `--insecure`.
