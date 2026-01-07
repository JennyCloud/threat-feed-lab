# threat-feed-lab

A small, practical lab that downloads a public threat-intel feed, cleans/normalizes the data, and outputs a curated CSV for analysis in Excel/Power BI.

## What this demonstrates
- Basic ETL (extract → transform → load) using Python
- Repeatable local workflow and clear documentation
- Data quality checks (fail fast when input/output is unexpected)

## Output
The script writes:
- `output/threat_feed_curated.csv` (curated dataset for Excel/Power BI)

## How to run (local)
1. Create a Python virtual environment (optional but recommended)
2. Install dependencies
3. Run the script

Example (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python .\threat_feed_etl.py
