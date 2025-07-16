import json
import os
import requests
import re

MITRE_DB_PATH = os.path.join(os.path.dirname(__file__), "mitre_db.json")

def clean_text(text):
    """Normalize text to lowercase alphanumeric only."""
    return re.sub(r'[^\w\s]', '', str(text)).lower()

def load_mitre_db():
    """Load the local MITRE mapping database."""
    if not os.path.exists(MITRE_DB_PATH):
        return {}
    with open(MITRE_DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def save_mitre_db(data):
    """Persist updated MITRE mapping database."""
    with open(MITRE_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def fetch_mitre_technique(technique_id):
    """Fetch MITRE technique metadata dynamically from MITRE ATT&CK API (or fallback)."""
    url = f"https://attack.mitre.org/techniques/{technique_id}/"
    try:
        # For now, just return the structured link. You could enrich this with real-time scraping if needed.
        return {
            "technique_id": technique_id,
            "name": f"Technique {technique_id}",
            "url": url
        }
    except Exception:
        return {
            "technique_id": technique_id,
            "name": "Unknown",
            "url": url
        }

def match_findings_to_tactics(scan_type, results):
    """Match scan findings against MITRE mapping."""
    mitre_db = load_mitre_db()
    recommendations = []

    for item in results:
        description = ""
        if isinstance(item, dict):
            description = json.dumps(item)
        elif isinstance(item, str):
            description = item
        else:
            continue

        for mapped_issue, mitre_data in mitre_db.get(scan_type, {}).items():
            if clean_text(mapped_issue) in clean_text(description):
                if mitre_data not in recommendations:
                    recommendations.append(mitre_data)

    return recommendations

def enrich_mitre_db(scan_type, keyword, technique_id):
    """Update local DB with new mapping if not exists."""
    mitre_db = load_mitre_db()
    if scan_type not in mitre_db:
        mitre_db[scan_type] = {}

    if keyword not in mitre_db[scan_type]:
        mitre_data = fetch_mitre_technique(technique_id)
        mitre_db[scan_type][keyword] = mitre_data
        save_mitre_db(mitre_db)