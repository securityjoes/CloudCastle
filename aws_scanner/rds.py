import boto3
import typer
from datetime import datetime, timezone
from threatintel.mitre import match_findings_to_tactics

def scan_rds(session, account_id):
    """Scan AWS RDS instances for security posture"""
    rds_client = session.client("rds")

    try:
        dbs = rds_client.describe_db_instances()["DBInstances"]
        if not dbs:
            typer.echo("✅ No RDS instances found.")
            return [], 0, 0, 0, 0

        typer.echo(f"✅ Found {len(dbs)} RDS instances")
        rds_results = []
        total_risk = 0
        scanned_count = 0
        failed_count = 0

        for db in dbs:
            try:
                db_name = db.get("DBInstanceIdentifier", "N/A")
                engine = db.get("Engine", "N/A")
                engine_version = db.get("EngineVersion", "N/A")
                is_public = db.get("PubliclyAccessible", False)

                # Metadata
                storage_encrypted = db.get("StorageEncrypted", False)
                backup_retention = db.get("BackupRetentionPeriod", 0)
                multi_az = db.get("MultiAZ", False)
                log_exports = db.get("EnabledCloudwatchLogsExports", [])
                iam_auth = db.get("IAMDatabaseAuthenticationEnabled", False)

                # Risk logic
                risk_score = 0
                issues = []

                if is_public:
                    risk_score += 30
                    issues.append("❌ Publicly Accessible")

                    if not storage_encrypted:
                        risk_score += 15
                        issues.append("❌ Storage Not Encrypted")

                    if backup_retention < 7:
                        risk_score += 10
                        issues.append(f"⚠️ Backup Retention < 7 days ({backup_retention})")

                    if not multi_az:
                        risk_score += 10
                        issues.append("⚠️ Not Multi-AZ")

                    if not iam_auth:
                        risk_score += 10
                        issues.append("⚠️ IAM Authentication Disabled")

                    if not log_exports:
                        risk_score += 10
                        issues.append("⚠️ No Log Exports Enabled")

                # Determine visibility label
                visibility = "❌ Public" if is_public else "🔒 Private"
                backup_status = f"{backup_retention} days"
                log_export_status = ", ".join(log_exports) if log_exports else "⚠️ No Logs Exported"

                risk_score = min(risk_score, 100)
                risk_class = (
                    "risk-high" if risk_score >= 71 else
                    "risk-medium" if 31 <= risk_score <= 70 else
                    "risk-low"
                )

                rds_results.append({
                    "db_name": db_name,
                    "engine": engine,
                    "engine_version": engine_version,
                    "is_public": visibility,
                    "storage_encrypted": "✅ Encrypted" if storage_encrypted else "❌ Not Encrypted",
                    "backup_retention": backup_status,
                    "multi_az": "✅ Multi AZ" if multi_az else "⚠️ Single AZ",
                    "iam_auth": "✅ IAM Enabled" if iam_auth else "⚠️ IAM Disabled",
                    "log_exports": log_export_status,
                    "risk_score": risk_score,
                    "risk_class": risk_class
                })

                typer.echo(f"\n🔹 **{db_name}** ({engine} {engine_version})")
                typer.echo(f"   - Visibility: {visibility}")
                for issue in issues:
                    typer.echo(f"   - {issue}")
                typer.echo(f"   ➡️ **Risk Score: {risk_score}/100 ({risk_class})**")

                total_risk += risk_score
                scanned_count += 1

            except Exception as e:
                failed_count += 1
                typer.echo(f"❌ Error scanning RDS instance: {e}")

        avg_risk = round(total_risk / scanned_count) if scanned_count > 0 else 0
        typer.echo("✅ RDS Instances scan completed.")

        mitre_recommendations = match_findings_to_tactics("rds", rds_results)
        
        return rds_results, avg_risk, scanned_count, failed_count, mitre_recommendations

    except Exception as e:
        typer.echo(f"❌ Failed to retrieve RDS data: {e}")
        return [], 0, 0, 0, 0