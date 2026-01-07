
# Runbook — threat-feed-lab

## Purpose
Generate a curated CSV from a public threat-intel feed so it can be used in Excel/Power BI and shared across a team.

## Prerequisites
- Python 3.10+ installed
- Internet access

## Run steps
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python .\threat_feed_etl.py
