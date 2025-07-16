import boto3
import typer
from threatintel.mitre import match_findings_to_tactics

def check_ec2(session, account_id):
    """Scan EC2 instances for security risks with scoring"""
    ec2_client = session.client("ec2")

    try:
        instances = ec2_client.describe_instances()["Reservations"]
        if not instances:
            typer.echo("✅ No running EC2 instances found in region.")
            return [], 0, 0, 0, 0

        typer.echo(f"✅ Found {sum(len(res['Instances']) for res in instances)} EC2 instances")
        total_risk = 0
        ec2_results = []
        failed_count = 0
        scanned_count = 0

        for reservation in instances:
            for instance in reservation["Instances"]:
                try:
                    instance_name = next((tag['Value'] for tag in instance.get("Tags", []) if tag["Key"] == "Name"), "N/A")
                    instance_type = instance["InstanceType"]
                    public_ip = instance.get("PublicIpAddress", "⛔ No Public IP")
                    private_ip = instance.get("PrivateIpAddress", "Unknown")
                    security_groups = instance.get("SecurityGroups", [])
                    subnet_id = instance.get("SubnetId", "")
                    open_ports = []
                    risk_score = 0

                    # --- Public Exposure Check ---
                    is_public_ip = "PublicIpAddress" in instance

                    allows_inbound_all = False
                    for sg in security_groups:
                        sg_id = sg["GroupId"]
                        sg_details = ec2_client.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"]
                        for rule in sg_details[0].get("IpPermissions", []):
                            if "FromPort" in rule:
                                for ip_range in rule.get("IpRanges", []):
                                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                                        allows_inbound_all = True
                                        open_ports.append(rule["FromPort"])

                    # Subnet route table check
                    has_igw = False
                    route_tables = ec2_client.describe_route_tables(
                        Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
                    )["RouteTables"]
                    for rt in route_tables:
                        for route in rt.get("Routes", []):
                            if route.get("GatewayId", "").startswith("igw-"):
                                has_igw = True
                                break

                    is_fully_public = is_public_ip and allows_inbound_all and has_igw

                    if is_fully_public:
                        risk_score += 40
                        if open_ports:
                            risk_score += 30

                    open_ports_status = f"⚠️ Open Ports: {open_ports}" if open_ports else "✅ No Open Ports"
                    visibility = "🔥 Public" if is_fully_public else "✅ Private"

                    # --- IAM Role ---
                    has_iam_role = "✅ Has IAM Role" if "IamInstanceProfile" in instance else "❌ No IAM Role"
                    if "❌" in has_iam_role:
                        risk_score += 20

                    risk_score = min(risk_score, 100)
                    risk_class = (
                        "risk-high" if risk_score >= 71 else
                        "risk-medium" if 31 <= risk_score <= 70 else
                        "risk-low"
                    )
                    total_risk += risk_score

                    ec2_results.append({
                        "instance_name": instance_name,
                        "instance_type": instance_type,
                        "public_ip": public_ip,
                        "private_ip": private_ip,
                        "is_public": visibility,
                        "open_ports": open_ports_status,
                        "iam_role": has_iam_role,
                        "risk_score": risk_score,
                        "risk_class": risk_class
                    })

                    scanned_count += 1

                    typer.echo(f"\n🔹 **Instance Name:** {instance_name}")
                    typer.echo(f"   - Type: {instance_type}")
                    typer.echo(f"   - Public IP: {public_ip}")
                    typer.echo(f"   - Private IP: {private_ip}")
                    typer.echo(f"   - Visibility: {visibility}")
                    typer.echo(f"   - {open_ports_status}")
                    typer.echo(f"   - {has_iam_role}")
                    typer.echo(f"   ➡️ **Risk Score: {risk_score}/100 ({risk_class})**")

                except Exception as e:
                    failed_count += 1
                    typer.echo(f"❌ Error retrieving EC2 Instance data for {instance_name}: {e}")

        avg_risk = round(total_risk / scanned_count) if scanned_count > 0 else 0
        typer.echo("✅ EC2 Instances scan completed.")

        mitre_recommendations = match_findings_to_tactics("ec2", ec2_results)

        return ec2_results, avg_risk, scanned_count, failed_count, mitre_recommendations

    except Exception as e:
        typer.echo(f"❌ Error scanning EC2 instances: {e}")
        return [], 0, 0, 0, 0
