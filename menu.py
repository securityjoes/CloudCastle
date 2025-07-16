import sys
import typer
import time
import subprocess
from banner import display_banner
from auth.status import get_auth_status
from auth.auth_aws import list_aws_accounts
from cloudcastle import scan_aws
from export import export_to_html

from auth.auth_aws import list_aws_accounts
from cloudcastle import scan_aws

def select_aws_accounts():
    accounts = list_aws_accounts()
    print("\n📘 Select AWS Account(s) to scan:")
    
    for idx, acc in enumerate(accounts):
        print(f"{idx + 1}  {acc['name']} ({acc['id']}) {acc['status']}")

    print(f"{len(accounts)+1}. All Accessible Accounts")

    selected = input("Enter selection (comma-separated): ").split(",")

    if str(len(accounts) + 1) in selected:
        selected_accounts = [acc for acc in accounts if acc["status"] == "✅"]
    else:
        selected_accounts = [accounts[int(i)-1] for i in selected if i.strip().isdigit()]

    print(f"🔄 Starting scan for {len(selected_accounts)} accounts...\n")

    for acc in selected_accounts:
        account_id = acc["id"]
        account_name = acc["name"]
        session = acc["session"]

        if not session:
            print(f"❌ Skipping {account_id} (no session available)")
            continue

        try:
            print(f"\n🔍 Scanning {account_name} ({account_id})")
            scan_aws(account_id=account_id, account_name=account_name, session=session)

        except Exception as e:
            print(f"❌ Error scanning {account_id}: {e}")

def go_to_azure_menu():
    typer.echo("🧩 Sorry, Azure Security Posture Scan not yet implemented.")
def go_to_gcp_menu():
    typer.echo("🧩 Sorry, GCP Security Posture Scan not yet implemented.")

def show_menu():
    
    display_banner()

    typer.echo("\n📌 CloudCastle - Cloud Security Posture Tool")
    typer.echo("📌 by cloud hunters, for cloud hunters")
    typer.echo("📌 Meet us at: www.securityjoes.com\n\n")

    print("Connection Status:")
    get_auth_status() # prints auth status for each cloud provider

    while True:
        # MAIN MENU #
        
        typer.echo("")
        typer.echo("☁️ Select Cloud Provider:")
        typer.echo("1️ AWS")
        typer.echo("2️ Azure")
        typer.echo("3️ GCP")
        typer.echo("4 Export HTML")
        typer.echo("5 Exit CloudCastle 🏰")
        provider_choice = typer.prompt("Select an option (1-5)")

        if provider_choice == "1":
            select_aws_accounts()
        elif provider_choice == "2":
            go_to_azure_menu()
        elif provider_choice == "3":
            go_to_gcp_menu()
        elif provider_choice =="4":
            export_to_html()
            typer.echo("HTML report created from last scan.")
        elif provider_choice == "5":
            typer.echo("👋 Exiting CloudCastle.")
            typer.echo("🔗 Get in touch: response@securityjoes.com")
            sys.exit(0)