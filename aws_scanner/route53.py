import boto3
import typer
from threatintel.mitre import match_findings_to_tactics

def scan_route53(session, account_id):
    """Scan AWS Route 53 domains for misconfigurations"""
    route53_client = session.client("route53")

    try:
        total_risk = 0
        scanned_count = 0
        failed_count = 0
        response = route53_client.list_hosted_zones()
        domains = response.get("HostedZones", [])
        
        if not domains:
            typer.echo("✅ No Route 53 domains found.")
            return [], 0, 0, 0, 0

        typer.echo(f"✅ Found {len(domains)} Route 53 domains")
        route53_results = []

        for domain in domains:
            try:
                domain_name = domain["Name"]
                is_public = not domain["Config"]["PrivateZone"]
                risk_score = 80 if is_public else 0  

                total_risk += risk_score

                route53_results.append({
                    "domain": domain_name,
                    "is_public": "❌ Public" if is_public else "🔒 Private",
                    "risk_score": risk_score,
                    "risk_class": 'risk-high' if risk_score >= 71 else 'risk-medium' if 31 <= risk_score <= 70 else 'risk-low'
                })

                typer.echo(f"\n🔹 **Domain:** {domain_name}")
                typer.echo(f"   - {'❌ Public' if is_public else '🔒 Private'}")
                typer.echo(f"   ➡️ **Risk Score: {risk_score}/100 ({'risk-high' if risk_score >= 71 else 'risk-medium' if 31 <= risk_score <= 70 else 'risk-low'})**")
                
                scanned_count += 1

            except Exception as e:
                failed_count += 1
                typer.echo(f"❌ Error retrieving route53 data for {domain_name}: {e}")

        avg_risk = round(total_risk / scanned_count) if scanned_count > 0 else 0 

        mitre_recommendations = match_findings_to_tactics("route53", route53_results)
 
        return route53_results, avg_risk, scanned_count, failed_count, mitre_recommendations

    except Exception as e:
        typer.echo(f"❌ Error scanning Route 53: {e}")
        return [], 0, 0, 0, 0
