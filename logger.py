import os
import json

def save_log(scan_type, account_name, results, avg_risk, scanned_count=0, failed_count=0, provider: str = "aws", account_id: str = "default", mitre_recommendations=None):
    """Save scan results to logs/<provider>/<account_id>/logs.json without overwriting other scans."""

    base_dir = os.path.join("logs", provider, account_id)
    os.makedirs(base_dir, exist_ok=True)

    log_file_path = os.path.join(base_dir, "logs.json")

    # Load existing log file or initialize new
    if os.path.exists(log_file_path):
        with open(log_file_path, "r", encoding="utf-8") as f:
            try:
                log_data = json.load(f)
            except json.JSONDecodeError:
                log_data = {}
    else:
        log_data = {}

    # Save new scan data under its scan type (ec2, iam, etc.)
    if "account_name" not in log_data:
        log_data["account_name"] = account_name
        
    log_data[scan_type] = {
        "results": results,
        "avg_risk": avg_risk,
        "scanned_count": scanned_count,
        "failed_count": failed_count,
        "mitre_recommendations": mitre_recommendations or []
    }
    
    # Save back to file
    with open(log_file_path, "w", encoding="utf-8") as f:
        json.dump(log_data, f, indent=4)

    print(f"📝 {scan_type.upper()} scan results saved for account {account_id} to {log_file_path}")
