import boto3
import typer
from botocore.exceptions import ClientError
from threatintel.mitre import match_findings_to_tactics

def scan_s3(session, account_id):
    """Scan S3 buckets for security risks."""
    s3 = session.client("s3")
    try:
        buckets = s3.list_buckets()["Buckets"]
    except Exception as e:
        typer.echo(f"❌ Error listing S3 buckets: {e}")
        return [], 0, 0, 0, 0

    if not buckets:
        typer.echo("✅ No S3 buckets found.")
        return [], 0, 0, 0, 0

    typer.echo(f"✅ Found {len(buckets)} S3 buckets.")
    results = []
    total_risk = 0
    scanned_count = 0
    failed_count = 0

    for bucket in buckets:
        bucket_name = bucket["Name"]
        risk_score = 0
        issues = []

        try:
            # Check for public ACL
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                grants = acl.get("Grants", [])
                public_acl = any(
                    g["Grantee"].get("URI", "") == "http://acs.amazonaws.com/groups/global/AllUsers"
                    for g in grants
                )
            except ClientError as e:
                if e.response["Error"]["Code"] == "AccessDenied":
                    typer.echo(f"⚠️ Skipping bucket {bucket_name}: AccessDenied")
                    continue
                raise

            # Public access block requires region-specific call
            try:
                location = s3.get_bucket_location(Bucket=bucket_name)["LocationConstraint"]
                region = location or "us-east-1"
                regional_s3 = session.client("s3", region_name=region)

                pab = regional_s3.get_bucket_public_access_block(Bucket=bucket_name)
                config = pab["PublicAccessBlockConfiguration"]
                if not all(config.values()):
                    issues.append("⚠️ Public Access Block Misconfigured")
                    risk_score += 30
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    issues.append("⚠️ No Public Access Block Configuration")
                    risk_score += 10
                else:
                    typer.echo(f"❌ Error checking access block for {bucket_name}: {e}")
                    failed_count += 1

            # Check bucket policy
            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                if '"Principal":"*"' in policy["Policy"]:
                    issues.append("⚠️ Open Bucket Policy")
                    risk_score += 30
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                    typer.echo(f"⚠️ Error checking bucket policy for {bucket_name}: {e}")
                    failed_count += 1

            # Logging check
            try:
                logging = s3.get_bucket_logging(Bucket=bucket_name)
                if not logging.get("LoggingEnabled"):
                    issues.append("⚠️ Logging Disabled")
                    risk_score += 10
            except Exception:
                issues.append("⚠️ Unable to verify logging")
                risk_score += 5

            # Public status and final score
            is_public = "🔥 Public" if public_acl else "🔒 Private"
            risk_score = min(risk_score, 100)
            risk_class = (
                "risk-high" if risk_score >= 71 else
                "risk-medium" if 31 <= risk_score <= 70 else
                "risk-low"
            )
            total_risk += risk_score
            scanned_count += 1

            typer.echo(f"\n🔹 {bucket_name}")
            typer.echo(f"   - Visibility: {is_public}")
            typer.echo(f"   - Issues: {', '.join(issues) if issues else '✅ No Issues'}")
            typer.echo(f"   ➡️ Risk Score: {risk_score}/100 ({risk_class})")

            results.append({
                "bucket_name": bucket_name,
                "is_public": is_public,
                "issues": ", ".join(issues) if issues else "✅ No Issues",
                "risk_score": risk_score,
                "risk_class": risk_class
            })

        except Exception as e:
            failed_count += 1
            typer.echo(f"❌ Error checking bucket {bucket_name}: {e}")

    avg_risk = round(total_risk / scanned_count) if scanned_count > 0 else 0
    typer.echo("✅ S3 bucket scan completed.")

    mitre_recommendations = match_findings_to_tactics("s3", results)
    return results, avg_risk, scanned_count, failed_count, mitre_recommendations