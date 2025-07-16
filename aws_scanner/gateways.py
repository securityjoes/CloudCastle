import boto3
import typer
from threatintel.mitre import match_findings_to_tactics

def scan_gateways(session, account_id):
    """Scan AWS Internet and NAT Gateways"""
    ec2_client = session.client("ec2")

    try:
        igws = ec2_client.describe_internet_gateways()["InternetGateways"]
        nat_gws = ec2_client.describe_nat_gateways()["NatGateways"]
        total_risk = 0
        scanned_count = 0
        failed_count = 0
        gateway_results = {"internet_gateways": [], "nat_gateways": []}

        if not igws and not nat_gws:
            typer.echo("✅ No Internet Gateways or NAT Gateways found.")
            return (gateway_results, 0, 0, 0, 0)

        # Scan Internet Gateways
        if igws:
            typer.echo(f"✅ Found {len(igws)} Internet Gateways")
            for igw in igws:
                try:
                                    
                    igw_name = next((tag['Value'] for tag in igw.get("Tags", []) if tag["Key"] == "Name"), "N/A")
                    attached_vpcs = [attachment["VpcId"] for attachment in igw["Attachments"] if attachment["State"] == "available"]
                    is_attached = bool(attached_vpcs)
                    risk_score = 20 if not is_attached else 0  # Unattached IGW = Medium Risk

                    total_risk += risk_score
                    
                    gateway_results["internet_gateways"].append({
                        "gateway_name": igw_name,
                        "type": "Internet Gateway",
                        "attached_vpcs": attached_vpcs or "❌ Not Attached",
                        "state": "N/A",
                        "risk_score": risk_score,
                        "risk_class": "risk-medium" if risk_score > 0 else "risk-low"
                    })
                    scanned_count += 1

                except Exception as e:
                    failed_count += 1
                    typer.echo(f"❌ Error retrieving Gateways data for {igw_name}: {e}")
        else:
            typer.echo("✅ No Internet Gateways found.")

        # Scan NAT Gateways
        if nat_gws:
            typer.echo(f"✅ Found {len(nat_gws)} NAT Gateways")
            for nat in nat_gws:
                try:
                    nat_name = next((tag['Value'] for tag in nat.get("Tags", []) if tag["Key"] == "Name"), "N/A")
                    public_ip = nat.get("PublicIp", "❌ No Public IP")
                    state = nat["State"]
                    risk_score = 30 if state == "available" and public_ip != "❌ No Public IP" else 0  # NAT Exposed = High Risk

                    total_risk += risk_score

                    gateway_results["nat_gateways"].append({
                        "gateway_name": nat_name,
                        "type": "NAT Gateway",
                        "public_ip": public_ip,
                        "state": state,
                        "risk_score": risk_score,
                        "risk_class": "risk-high" if risk_score > 30 else "risk-low"
                    })
                    scanned_count += 1
                except Exception as e:
                    failed_count +=1
                    typer.echo(f"❌ Error retrieving Gateways data for {nat_name}: {e}")   
        else:
            typer.echo("✅ No NAT Gateways found.")

        avg_risk = round(total_risk / scanned_count) if scanned_count > 0 else 0
        typer.echo("✅ Internet & NAT Gateways scan completed.")    
        
        results = gateway_results["internet_gateways"] + gateway_results["nat_gateways"]
        mitre_recommendations = match_findings_to_tactics("gateways", results)

        return (
            results,
            avg_risk,
            scanned_count,
            failed_count,
            mitre_recommendations
        )

    except Exception as e:
        typer.echo(f"❌ Error scanning gateways: {e}")
        return ([], 0, 0, 0, 0)
