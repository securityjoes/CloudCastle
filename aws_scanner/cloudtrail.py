import boto3
import typer
from threatintel.mitre import match_findings_to_tactics

def scan_cloudtrail(session, account_id):
    """Scan AWS CloudTrail for security gaps."""
    
    cloudtrail_client = session.client("cloudtrail")

    try:
        trails = cloudtrail_client.describe_trails()["trailList"]

        if not trails:
            typer.echo("✅ No CloudTrail trails found.")
            return [], 0, 0, 0, 0

        typer.echo(f"✅ Found {len(trails)} CloudTrail trails")
        cloudtrail_results = []
        total_risk = 0
        failed_count = 0
        scanned_count = 0
        failed_buckets = []

        for trail in trails:
            try:
                trail_name = trail["Name"]
                is_multi_region = trail.get("IsMultiRegionTrail", False)
                has_s3_logging = "S3BucketName" in trail
                log_validation_enabled = trail.get("LogFileValidationEnabled", False)
                cloudwatch_enabled = "CloudWatchLogsLogGroupArn" in trail
                kms_encryption = "KmsKeyId" in trail

                risk_score = 0

                if not is_multi_region:
                    risk_score += 40  # High risk if not multi-region
                if not has_s3_logging:
                    risk_score += 30  # Medium risk if not storing logs securely
                if not log_validation_enabled:
                    risk_score += 20  # Medium risk if log validation is disabled
                if not cloudwatch_enabled:
                    risk_score += 10  # Low risk if CloudWatch is missing
                if not kms_encryption:
                    risk_score += 10  # Low risk if logs aren't encrypted

                risk_class = "risk-high" if risk_score >= 71 else "risk-medium" if 31 <= risk_score <= 70 else "risk-low"

                cloudtrail_results.append({
                    "trail_name": trail_name,
                    "is_multi_region": "✅ Enabled" if is_multi_region else "❌ No Multi-region",
                    "has_s3_logging": "✅ Enabled" if has_s3_logging else "❌ No S3 Logging",
                    "log_validation": "✅ Enabled" if log_validation_enabled else "❌ No Log Validation",
                    "cloudwatch_logging": "✅ Enabled" if cloudwatch_enabled else "❌ No CloudWatch",
                    "kms_encryption": "✅ Enabled" if kms_encryption else "❌ No KMS Encryption",
                    "risk_score": risk_score,
                    "risk_class": risk_class
                })

                typer.echo(f"\n🔹 **CloudTrail:** {trail_name}")
                typer.echo(f"   - Multi-Region: { '✅ Enabled' if is_multi_region else '❌ No Multi-region' }")
                typer.echo(f"   - S3 Logging: { '✅ Enabled' if has_s3_logging else '❌ No S3 Logging' }")
                typer.echo(f"   - Log Validation: { '✅ Enabled' if log_validation_enabled else '❌ No Log Validation' }")
                typer.echo(f"   - CloudWatch Logging: { '✅ Enabled' if cloudwatch_enabled else '❌ No CloudWatch' }")
                typer.echo(f"   - KMS Encryption: { '✅ Enabled' if kms_encryption else '❌ No KMS Encryption' }")
                typer.echo(f"   ➡️ **Risk Score: {risk_score}/100 ({risk_class})**")

                total_risk += risk_score
                scanned_count +=1

            except Exception as e:
                failed_count += 1
                typer.echo(f"❌ Error retrieving CloudTrail data for {trail_name}: {e}")

        avg_risk = round(total_risk / scanned_count) if scanned_count > 0 else 0

        mitre_recommendations = match_findings_to_tactics("cloudtrail", cloudtrail_results)

        return cloudtrail_results, avg_risk, scanned_count, failed_count, mitre_recommendations

    except Exception as e:
        typer.echo(f"❌ Error scanning CloudTrail: {e}")
        return [], 0, 0, 0, 0
