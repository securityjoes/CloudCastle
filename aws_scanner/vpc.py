import typer
from threatintel.mitre import match_findings_to_tactics

def scan_vpc(session, account_id):
    """Scan AWS VPCs for exposure risks"""
    ec2_client = session.client("ec2")

    try:
        vpcs = ec2_client.describe_vpcs()["Vpcs"]
        total_risk = 0
        scanned_count = 0
        failed_count = 0

        if not vpcs:
            typer.echo("✅ No VPCs found.")
            return [], 0, 0, 0, 0

        typer.echo(f"✅ Found {len(vpcs)} VPCs")
        vpc_results = []

        for vpc in vpcs:
            try:
                vpc_id = vpc["VpcId"]
                cidr_block = vpc["CidrBlock"]
                is_default = vpc.get("IsDefault", False)
                risk_score = 0

                # Check if VPC is publicly routable
                is_public = cidr_block.startswith("0.")  # Rough check for public ranges
                if is_public:
                    risk_score += 40  # Public VPC = high risk


                total_risk += risk_score

                risk_class = "risk-high" if risk_score > 60 else "risk-medium" if risk_score > 30 else "risk-low"
                
                vpc_results.append({
                    "vpc_id": vpc_id,
                    "cidr_block": cidr_block,
                    "is_default": "✅ Default VPC" if is_default else "❌ Non-Default",
                    "is_public": "✅ Public" if is_public else "🔒 Private",
                    "risk_score": risk_score,
                    "risk_class": risk_class
                })

                typer.echo(f"\n🔹 **VPC ID:** {vpc_id}")
                typer.echo(f"   - CIDR Block: {cidr_block}")
                typer.echo(f"   - { '✅ Public' if is_public else '🔒 Private' }")
                typer.echo(f"   ➡️ **Risk Score: {risk_score}/100 ({risk_class})**")

                scanned_count += 1
                
            except Exception as e:
                failed_count += 1
                typer.echo(f"❌ Error retrieving VPC data for {vpc_id}: {e}")

        avg_risk = round(total_risk / scanned_count) if scanned_count > 0 else 0
        typer.echo("✅ VPC scan completed.")

        mitre_recommendations = match_findings_to_tactics("vpc", vpc_results)

        return vpc_results, avg_risk, scanned_count, failed_count

    except Exception as e:
        typer.echo(f"❌ Error scanning VPCs: {e}")
        return [], 0, 0, 0, 0