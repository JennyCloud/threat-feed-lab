import csv
import json
import zipfile
from pathlib import Path
from datetime import datetime, timezone

import requests

# Public threat-intel feed (recent dataset)
URLHAUS_RECENT_JSON_ZIP = "https://urlhaus.abuse.ch/downloads/json_recent/"

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

OUTPUT_CSV = OUTPUT_DIR / "threat_feed_curated.csv"


def download_zip(url: str) -> bytes:
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    return r.content


def extract_json_from_response(content: bytes) -> list[dict]:
    """
    Some endpoints return a zip containing JSON; sometimes you may receive plain JSON
    or an HTML error page. This function tries:
      1) ZIP -> JSON
      2) Plain JSON
    If neither works, it prints a short preview to help troubleshooting.
    """
    # 1) Try ZIP first
    from io import BytesIO

    try:
        with zipfile.ZipFile(BytesIO(content), "r") as zf:
            json_names = [n for n in zf.namelist() if n.lower().endswith(".json")]
            if not json_names:
                raise RuntimeError("Zip downloaded but contains no .json file.")
            with zf.open(json_names[0], "r") as f:
                payload = json.loads(f.read().decode("utf-8", errors="replace"))
            return _normalize_payload(payload)
    except zipfile.BadZipFile:
        pass  # Not a zip — fall through to plain JSON parsing

    # 2) Try plain JSON
    try:
        payload = json.loads(content.decode("utf-8", errors="replace"))
        return _normalize_payload(payload)
    except Exception:
        preview = content[:300].decode("utf-8", errors="replace")
        raise RuntimeError(
            "Feed response was neither a ZIP nor valid JSON. "
            "First 300 chars of response:\n" + preview
        )


def _normalize_payload(payload) -> list[dict]:
    """
    Normalize different feed shapes into a list[dict].

    Supported shapes:
    1) {"urls": [ {...}, {...} ]}
    2) [ {...}, {...} ]
    3) {"<id>": [ {...} ], "<id2>": [ {...}, {...} ]}  <-- flatten values
    """
    # 1) dict with 'urls'
    if isinstance(payload, dict) and isinstance(payload.get("urls"), list):
        return payload["urls"]

    # 2) already a list
    if isinstance(payload, list):
        return payload

    # 3) dict-of-lists (keyed by ID) -> flatten
    if isinstance(payload, dict):
        out: list[dict] = []
        for _, v in payload.items():
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        out.append(item)
        if out:
            return out

    raise RuntimeError("Unexpected JSON structure from feed.")



def write_curated_csv(rows: list[dict]) -> int:
    """
    Writes a curated CSV for dashboards.
    Returns number of data rows written.
    """
    fieldnames = [
        "date_added",
        "url_status",
        "threat",
        "host",
        "tags",
        "reporter",
        "url",
    ]

    count = 0
    with OUTPUT_CSV.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()

        for d in rows:
            if not isinstance(d, dict):
                continue

            url = str(d.get("url", "")).strip()
            if not url:
                continue

            tags = d.get("tags") or []
            if isinstance(tags, list):
                tags = ",".join([str(t).strip() for t in tags if str(t).strip()])
            else:
                tags = str(tags).strip()

            w.writerow(
                {
                    "date_added": str(d.get("date_added", "")).strip(),
                    "url_status": str(d.get("url_status", "")).strip(),
                    "threat": str(d.get("threat", "")).strip(),
                    "host": str(d.get("host", "")).strip(),
                    "tags": tags,
                    "reporter": str(d.get("reporter", "")).strip(),
                    "url": url,
                }
            )
            count += 1

    return count


def main() -> int:
    print("[threat-feed-lab] Downloading feed...")
    zip_bytes = download_zip(URLHAUS_RECENT_JSON_ZIP)

    print("[threat-feed-lab] Parsing JSON from zip...")
    rows = extract_json_from_response(zip_bytes)

    print("[threat-feed-lab] Writing curated CSV...")
    n = write_curated_csv(rows)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[threat-feed-lab] OK ({ts}) rows_written={n} output={OUTPUT_CSV}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
