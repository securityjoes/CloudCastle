import typer
from auth import auth_aws
import botocore.exceptions
from datetime import datetime, timezone
from threatintel.mitre import match_findings_to_tactics

def check_iam_users(session, account_id):
    """Scan AWS IAM users and determine their status"""
    
    try:
        iam_client = session.client("iam")
        users = iam_client.list_users()["Users"]
    except Exception as e:
        typer.echo(f"❌ Error scanning AWS IAM: {e}")
        return [], 0, 0, 0

    user_data = []
    scanned_count = 0
    failed_count = 0
    total_risk = 0
    risk_score = 0
    
    typer.echo(f"✅ Found {len(users)} IAM users") 
    
    for user in users:
        try:
            username = user["UserName"]
            created_date = user.get("CreateDate", "N/A")
            mfa_status = ""
            old_key_warning = ""
            admin_status = ""
            has_password_login = False
            is_admin = False

            # Check if user is disabled
            access_keys = iam_client.list_access_keys(UserName=username)["AccessKeyMetadata"]
            attached_policies = iam_client.list_attached_user_policies(UserName=username)["AttachedPolicies"]
            groups = iam_client.list_groups_for_user(UserName=username)["Groups"]
            signing_certs = iam_client.list_signing_certificates(UserName=username)["Certificates"]

            has_active_keys = any(k["Status"] == "Active" for k in access_keys)
            try:
                iam_client.get_login_profile(UserName=username)
                has_password_login = True
            except botocore.exceptions.ClientError:
                pass
            in_group = bool(groups)
            has_cert_auth = bool(signing_certs)

            is_disabled = not has_active_keys and not has_password_login and not in_group and not has_cert_auth
            status_message = "❌ Disabled User" if is_disabled else "✅ Active User"

            # Only assign risk if user is active
            mfa_devices = iam_client.list_mfa_devices(UserName=username)["MFADevices"]
            mfa_status = "✅ MFA Enabled" if mfa_devices else "❌ No MFA"
            if not mfa_devices and not is_disabled:
                risk_score += 40

            # Access key age
            for key in access_keys:
                if key["Status"] == "Active":
                    age_days = (datetime.now(timezone.utc) - key["CreateDate"]).days
                    if age_days > 90 and not is_disabled:
                        risk_score += 10
                        old_key_warning = f"⚠️ Access Key {key['AccessKeyId']} is {age_days} days old"
                    else:
                        old_key_warning = f"✅ Access Key {key['AccessKeyId']} is {age_days} days old"

            # Admin policy check
            is_admin = any(p["PolicyName"] in ["AdministratorAccess", "PowerUserAccess"] for p in attached_policies)
            admin_status = "⚠️ Admin Access Enabled" if is_admin else "✅ No Admin Access"
            if is_admin and not is_disabled:
                risk_score += 50

            # Determine risk class
            risk_level = (
                "🟢 Low Risk" if risk_score <= 30 else
                "🟡 Medium Risk" if risk_score <= 60 else
                "🔴 High Risk"
            )
            risk_class = (
                "risk-low" if risk_score <= 30 else
                "risk-medium" if risk_score <= 60 else
                "risk-high"
            )

            typer.echo(f"\n🔹 **{username}** (Created: {created_date})")
            typer.echo(f"   - {mfa_status}")
            if old_key_warning:
                typer.echo(f"   - {old_key_warning}")
            if is_admin:
                typer.echo("   - ⚠️ User has AdministratorAccess permissions")
            typer.echo(f"   ➡️ **Risk Score: {risk_score}/100 ({risk_level})**")

            user_data.append({
                "username": username,
                "status": status_message,
                "mfa_status": mfa_status,
                "old_key_warning": old_key_warning,
                "admin_status": admin_status,
                "risk_score": risk_score,
                "risk_class": risk_class
            })
            scanned_count += 1

        except Exception as e:
            failed_count += 1
            typer.echo(f"❌ Error retrieving IAM user data for {username}: {e}")

    total_risk += risk_score
    avg_risk = round(total_risk / scanned_count) if scanned_count > 0 else 0
    typer.echo("✅ AWS Identities scan completed.")

    mitre_recommendations = match_findings_to_tactics("iam", user_data)

    return user_data, avg_risk, scanned_count, failed_count, mitre_recommendations