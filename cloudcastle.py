import sys
import os
import json
import typer
import subprocess
import auth
from datetime import datetime, timezone
from logger import save_log

sys.stdout.reconfigure(encoding="utf-8")

app = typer.Typer()

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "..", "utils", "cloudcastle_config.json")

@app.command()
def menu():
    from menu import show_menu
    show_menu()

def save_config(data):
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f)

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}

@app.command()
def auth_aws():
    """Authenticate with AWS using browser-based login"""
    typer.echo("🔗 Checking AWS SSO configuration...")
    
    if is_aws_authenticated():
        return ""

    else:
    
        config = load_config()

        # Ask for SSO Start URL if not already saved
        if "sso_start_url" not in config:
            typer.echo("💡 Find your AWS SSO Start URL in the AWS Console under IAM Identity Center.")
            typer.echo("   Example: https://your-company.awsapps.com/start")
            config["sso_start_url"] = typer.prompt("Enter your AWS SSO Start URL")
            save_config(config)

        sso_start_url = config["sso_start_url"]
        sso_region = "us-east-1" #default
        profile_name = "cloudcastle"

        try:
            # Configure AWS SSO
            subprocess.run(
                ["aws", "configure", "set", f"profile.{profile_name}.sso_start_url", sso_start_url],
                check=True
            )
            subprocess.run(
                ["aws", "configure", "set", f"profile.{profile_name}.sso_region", sso_region],
                check=True
            )
            typer.echo(f"✅ AWS SSO configured for {sso_start_url}!")

            # Start login
            typer.echo("🔗 Opening AWS authentication in your browser...")
            subprocess.run(["aws", "sso", "login", "--profile", profile_name], check=True)
            typer.echo("✅ AWS authentication created successfully!")

        except subprocess.CalledProcessError:
            typer.echo("❌ AWS authentication failed. Please try again.")

@app.command()
def scan_aws(account_id: str, account_name: str, session):
    """Scans all AWS Cloud Infra for a specific account."""

    from aws_scanner.iam import check_iam_users
    from aws_scanner.ec2 import check_ec2
    from aws_scanner.vpc import scan_vpc
    from aws_scanner.gateways import scan_gateways
    from aws_scanner.route53 import scan_route53
    from aws_scanner.cloudtrail import scan_cloudtrail
    from aws_scanner.s3 import scan_s3
    from aws_scanner.rds import scan_rds


    scan_map = { 
        "iam": check_iam_users,
        "ec2": check_ec2,
        "vpc": scan_vpc,
        "gateways": scan_gateways,
        "route53": scan_route53,
        "cloudtrail": scan_cloudtrail,
        "s3": scan_s3,
        "rds": scan_rds
    }

    for scan_type, scan_function in scan_map.items():
        try:
            typer.echo(f"- Running {scan_type.upper()} Security Scan...")
            results, avg_risk, scanned_count, failed_count, mitre_recommendations = scan_function(session, account_id)
            typer.echo(f"\n📊 **Average {scan_type.upper()} Risk Score: {avg_risk}/100**")
            typer.echo(f"- Scanned {scanned_count} out of {scanned_count + failed_count} {scan_type} resources.")
            save_log(
                account_name=account_name,
                account_id=account_id,
                scan_type=scan_type,
                results=results,
                avg_risk=avg_risk,
                scanned_count=scanned_count,
                failed_count=failed_count,
                mitre_recommendations=mitre_recommendations,
                provider="aws",
            )
        except Exception as e:
            typer.echo(f"❌ {scan_type.upper()} scan failed: {e}")


# Leave this here for now
@app.command()
def scan_azure():
    typer.echo("❌ Unsupported provider (for now!)")

@app.command()
def scan_gcp():
    typer.echo("❌ Unsupported provider (for now!)")
###

if __name__ == "__main__":
    if len(sys.argv) > 1:
        app()
    else: 
        menu()
