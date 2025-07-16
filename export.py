import json
import os
import jinja2
from datetime import datetime
from threatintel import mitre

REPORTS_DIR = "reports"

TEMPLATE_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>CloudCastle - Cloud Security Posture Report</title>
    <meta charset="UTF-8">
    <style>
        body { background-color: #1e1e2e; color: #c0c0c0; font-family: Arial, sans-serif; margin: 20px; }
        h1, h2, h3 { color: #ff9900; }
        .header { display: flex; align-items: center; justify-content: space-between; padding: 20px; background: #292929; position: sticky; top: 0; z-index: 1000; }
        .header img { height: 50px; }
        .risk-high { color: red; font-weight: bold; }
        .risk-medium { color: orange; font-weight: bold; }
        .risk-low { color: green; font-weight: bold; }
        #account-select {
            background: #2b2b3b; color: #fff; padding: 8px 12px; border: 1px solid #555; border-radius: 5px; font-size: 14px; margin-left: 10px;
        }
        label[for="account-select"] {
            font-weight: bold;
            color: #ffcc00;
        }
        .account-tabs { text-align: center; margin: 20px 0; }
        .account-btn { background: #444; color: white; padding: 10px 20px; border: none; margin: 5px; border-radius: 5px; cursor: pointer; }
        .account-btn.active { background-color: #ff9900; font-weight: bold; }
        .account-section { display: none; }
        .nav-links { text-align: center; margin-top: 10px; }
        .nav-links a { margin: 5px; padding: 8px 12px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold; }
        .risk-high-link { background-color: red; color: white; }
        .risk-medium-link { background-color: orange; color: white; }
        .risk-low-link { background-color: green; color: white; }
        .collapse { cursor: pointer; color: #00ccff; }
        .content { display: none; padding: 10px; background: #2d2d3a; border-left: 3px solid #00ccff; margin-bottom: 10px; }
        .content a { color: #ffcc00; }
        .dashboard-wrapper {
        display: flex;
        flex-wrap: wrap;
        justify-content: center;
        gap: 30px;
        margin: 20px 0;
        }

        .dashboard-card {
            background: #2d2d3a;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.5);
            max-width: 400px;
            width: 100%;
            overflow-x: auto;
            flex: 1 1 400px;
        }
        .dashboard-card table {
            width: 100%;
            table-layout: fixed;
            word-break: break-word;
        }
        .chart-container {
            width: 100%;
            max-width: 400px;
            height: 400px;
        }

        .chart-container canvas {
            width: 100% !important;
            height: 100% !important;
            aspect-ratio: 1 / 1 !important;
            display: block;
        }


        #top-risks-table th {
            box-sizing: border-box;
            padding: 8px;
            text-align: left;
            font-family: 'Courier New', monospace;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        table { width: 100%; border-collapse: collapse; background: #2b2b3b; margin-top: 10px; }
        th, td { border: 1px solid #444; padding: 8px; text-align: left; font-family: 'Courier New', monospace; }
        th { background: #333; color: #ffcc00; }
        td.risk_score {
            font-weight: bold;
        }
        #top-risks-table th:nth-child(1),
        #top-risks-table th:nth-child(3) {
            min-width: 120px;
        }

        td.risk_class::before {
            content: attr(data-icon);
            margin-right: 4px;
        }

        td.risk_class:contains('High') { color: red; }
        td.risk_class:contains('Medium') { color: orange; }
        td.risk_class:contains('Low') { color: green; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
<div class="header">
    <div style="display: flex; align-items: center; gap: 15px;">
        <img src="../images/main_logo_2023.png" alt="main logo">
        <h1>CloudCastle - Cloud Security Posture Report</h1>
        <div style="text-align:center; margin-top: 10px;">
        <label for="account-select" style="font-weight:bold;">Select Account:</label>
        <select id="account-select" onchange="switchAccount(this.value)">
            {% for account in account_sections %}
                <option value="{{ account.account_id }}" {% if loop.first %}selected{% endif %}>
                    {{ account.account_name }} ({{ account.account_id }})
                </option>
            {% endfor %}
        </select>
        </div>
    </div>
    <div class="cloud-tabs">
        <button class="account-btn active" onclick="switchCloud('aws')">AWS</button>
        <button class="account-btn" style="background: #555; cursor: not-allowed;" disabled>Azure</button>
        <button class="account-btn" style="background: #555; cursor: not-allowed;" disabled>GCP</button>
    </div>
    <img src="../images/cloudcastle_logo.png" alt="cloudcastle logo">
</div>

    <!-- AWS CLOUD WRAPPER -->
    <div id="cloud-aws" class="cloud-section" style="display: block;">
    <div class="dashboard-wrapper">

        <div class="dashboard-card">
            <h2 style="text-align:center;">🧭 AWS Account Risk Overview</h2>
            <div class="chart-container">
                <canvas id="aws-risk-chart"></canvas>
            </div>
        </div>

        <div class="dashboard-card">
            <h2 style="text-align:center;">📊 Risk by Resource Type</h2>
            <div class="chart-container">
                <canvas id="resource-risk-chart"></canvas>
            </div>
        </div>

        <div class="dashboard-card">
            <h2 style="text-align:center;">🔥 Top 10 Risks</h2>
            <div id="top-10-risks" style="width: 100%; max-width: 400px; overflow-x:auto;">
                <table id="top-risks-table" style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr>
                            <th style="background: #333; color: #ffcc00; padding: 8px;">Account</th>
                            <th style="background: #333; color: #ffcc00; padding: 8px;">Section</th>
                            <th style="background: #333; color: #ffcc00; padding: 8px;">Name</th>
                            <th style="background: #333; color: #ffcc00; padding: 8px;">Score</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>

    </div> <!-- end of dashboard-wrapper -->
</div> <!-- end of cloud-aws -->


    <!-- AZURE CLOUD WRAPPER -->
    <div id="cloud-azure" class="cloud-section" style="display: none;">
        <h2 style="text-align:center;">🧭 Azure Account Risk Overview</h2>
        <div id="azure-summary" style="text-align:center; margin: 20px;">
            <canvas id="azure-risk-chart" style="max-width: 400px; width: 100%; height: 300px;"></canvas>
            <p>🔒 Azure data not yet available.</p>
        </div>
        <!-- Missing resource chart -->
    </div>

    <!-- GCP CLOUD WRAPPER -->
    <div id="cloud-gcp" class="cloud-section" style="display: none;">
        <h2 style="text-align:center;">🧭 GCP Account Risk Overview</h2>
        <div id="gcp-summary" style="text-align:center; margin: 20px;">
            <canvas id="gcp-risk-chart" style="max-width: 400px; width: 100%; height: 300px;"></canvas>
            <p>🔒 GCP data not yet available.</p>
        </div>
        <!-- Missing resource chart -->
    </div>

{% for account in account_sections %}
<div id="account-{{ account.account_id }}" class="account-section">
    <h2>🧾 Report For Account: {{ account.account_name }}</h2>
    <h3>
        📊 Total Risk Score: 
        <span class="total-risk {% if account.total_avg_risk > 60 %}risk-high{% elif account.total_avg_risk > 30 %}risk-medium{% else %}risk-low{% endif %}"
              data-score="{{ account.total_avg_risk }}">
            {{ account.total_avg_risk }}/100
        </span>
    </h3>

    <div class="nav-links">
        {% for scan_key, risk in account.avg_risks.items() %}
            <a href="#{{ account.account_id }}-{{ scan_key }}-section"
               class="{% if risk > 60 %}risk-high-link{% elif risk > 30 %}risk-medium-link{% else %}risk-low-link{% endif %}">
                {{ scan_key | upper }} Risks
            </a>
        {% endfor %}
    </div>

    {% for scan_key, results in account.scan_results.items() %}
    <div id="{{ account.account_id }}-{{ scan_key }}-section">
        <h3>{{ scan_key | upper }} Risks (Avg: {{ account.avg_risks[scan_key] }}/100)</h3>
        <p>Scanned {{ account.scanned_counts[scan_key] }} of {{ account.scanned_counts[scan_key] + account.failed_counts[scan_key] }}</p>

        {% if account.mitre_notes[scan_key] %}
            <h4 class="collapse" onclick="toggle('mitre-{{ account.account_id }}-{{ scan_key }}')">⚠️ MITRE & ATT&CK Notes</h4>
            <div class="content" id="mitre-{{ account.account_id }}-{{ scan_key }}">
                {% for mitre in account.mitre_notes[scan_key] %}
                    <p><a href="{{ mitre.url }}" target="_blank">{{ mitre.technique_id }} - {{ mitre.name }}</a></p>
                {% endfor %}
            </div>
        {% endif %}

        {% if results %}
            <table data-enhance="true" id="{{ account.account_id }}-{{ scan_key }}-table">
                <thead>
                    <tr>
                        {% for col in results[0].keys() %}
                                <th>{{ col.replace('_', ' ').title() }}</th>
                        {% endfor %}
                    </tr>
                </thead>
                <tbody>
                    {% for row in results %}
                        <tr>
                        {% for key, value in row.items() %}
                            {% if key == 'risk_score' %}
                                <td class="risk_score">{{ value }}</td>
                            {% elif key == 'risk_class' %}
                                <td class="risk_class">{{ value }}</td>
                            {% else %}
                                <td>{{ value }}</td>
                            {% endif %}
                        {% endfor %}
                        </tr>
                    {% endfor %}
                </tbody>
            </table>
        {% else %}
            <p>⚠️ No {{ scan_key | upper }} scan data available.</p>
        {% endif %}
    </div>
    {% endfor %}
</div>
{% endfor %}

<!-- JS & DataTables -->
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css"/>
<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<script>
    function toggle(id) {
        var el = document.getElementById(id);
        el.style.display = el.style.display === "block" ? "none" : "block";
    }

    function switchCloud(cloudId) {
        document.querySelectorAll('.cloud-section').forEach(el => el.style.display = 'none');
        document.getElementById('cloud-' + cloudId).style.display = 'block';
    }

    function navigateToFinding(accountId, linkTarget) {
    
        event.preventDefault();
        switchAccount(accountId);

        setTimeout(() => {
            const el = document.querySelector(linkTarget);
            if (el) {
                el.scrollIntoView({ behavior: "smooth", block: "start" });
                el.classList.add("highlight-risk");
                setTimeout(() => {
                    el.classList.remove("highlight-risk");
                }, 2000); // Glow effect for 2s
            }
        }, 500); // ⏳ Give 500ms to allow DOM to update
    }

    function switchAccount(accountId) {
        document.querySelectorAll('.account-section').forEach(el => el.style.display = 'none');
        document.getElementById('account-' + accountId).style.display = 'block';
    }
    document.addEventListener("DOMContentLoaded", function() {
        document.querySelectorAll("table[data-enhance='true']").forEach(function(table) {
            new DataTable(table, {
                pageLength: 10,
                lengthChange: false,
                searching: true,
                order: []
            });
        });

        document.querySelectorAll('td.risk_class').forEach(td => {
            const txt = td.textContent.toLowerCase();
            if (txt.includes("high")) td.textContent = "🔴 High";
            else if (txt.includes("medium")) td.textContent = "🟡 Medium";
            else if (txt.includes("low")) td.textContent = "🟢 Low";
        });

        let high = 0, medium = 0, low = 0;

        document.querySelectorAll('.account-section').forEach(section => {
            const riskText = section.querySelector("span.total-risk")?.textContent || "";
            const match = riskText.match(/(\\d+)/); // extract numeric part
            if (!match) return;
            const score = parseInt(match[1]);
            if (score > 60) high++;
            else if (score > 30) medium++;
            else low++;
        });

        const awsRiskData = {
            labels: ["High", "Medium", "Low"],
            datasets: [{
                label: "Account Risk Levels",
                data: [high, medium, low],
                backgroundColor: ["#ff4c4c", "#ffb347", "#7bed9f"]
            }]
        };

        const awsConfig = {
            type: "pie",
            data: awsRiskData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: "bottom" },
                    title: {
                        display: true,
                        text: "AWS Risk Distribution"
                    }
                }
            }
        };

        new Chart(document.getElementById("aws-risk-chart"), awsConfig);

        let resourceTotals = {};

        document.querySelectorAll("table[id$='-table']").forEach(table => {
            const scanKey = table.id.split("-").slice(1, -1).join("-");

            let caseCount = table.querySelectorAll("td.risk_score").length;
            if (caseCount > 0) {
                resourceTotals[scanKey] = (resourceTotals[scanKey] || 0) + caseCount;
            }
        });

        function generateColor(index) {
            const hue = (index * 47) % 360; // Spread hues around the wheel
            return `hsl(${hue}, 70%, 60%)`;  // Pleasant saturation and brightness
        }

        const resourceRiskData = {
            labels: Object.keys(resourceTotals).map(k => k.toUpperCase()),
            datasets: [{
                label: "Resource Risk Scores",
                data: Object.values(resourceTotals),
                backgroundColor: Object.keys(resourceTotals).map((_, i) => generateColor(i))
            }]
        };

        const resourceConfig = {
            type: 'pie',
            data: resourceRiskData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom' },
                    title: {
                        display: true,
                        text: 'Risk Contribution by Resource Type'
                    }
                }
            }
        };

        if (Object.keys(resourceTotals).length > 0) {
            new Chart(document.getElementById("resource-risk-chart"), resourceConfig);
        }

        let topFindings = [];

        document.querySelectorAll("table[id$='-table']").forEach(table => {
            const tableIdParts = table.id.split("-");
            const accountId = tableIdParts[0];
            const scanKey = tableIdParts.slice(1, -1).join("-").toUpperCase();

            const accountSection = document.getElementById(`account-${accountId}`);
            const accountNameElement = accountSection?.querySelector("h2");
            const accountName = accountNameElement ? accountNameElement.textContent.replace("🧾 Report For Account: ", "").trim() : "Unknown Account";

            const linkTarget = `#account-${accountId}-${scanKey.toLowerCase()}-section`;

            table.querySelectorAll("tbody tr").forEach(row => {
                const cells = row.querySelectorAll("td");
                if (!cells.length) return;

                let riskScore = 0;
                let name = "";

                cells.forEach((cell, idx) => {
                    const headerEl = table.querySelectorAll("thead th")[idx];
                    if (!headerEl) return;

                    const header = headerEl.innerText.toLowerCase();
                    if (header.includes("risk score")) {
                        riskScore = parseInt(cell.innerText.trim());
                    }
                    if (!name && (header.includes("name") || header.includes("instance") || header.includes("bucket") || header.includes("username"))) {
                        name = cell.innerText.trim();
                    }
                });

                if (riskScore > 0 && name) {
                    topFindings.push({
                        accountId: accountId,
                        section: scanKey,
                        name: name,
                        score: riskScore,
                        link: linkTarget,
                        accountName: accountName
                    });
                }
            });
        });

        topFindings.sort((a, b) => b.score - a.score);

        const top10 = topFindings.slice(0, 10);

        // Inject into Top 10 Table
        const topRisksTableBody = document.querySelector("#top-risks-table tbody");
        topRisksTableBody.innerHTML = "";

        if (top10.length === 0) {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td colspan="4" style="text-align: center; padding: 10px; color: #999;">
                    Nothing to see here 🚀 Carry on soldier!
                </td>
            `;
            topRisksTableBody.appendChild(tr);
        } else {
            top10.forEach(finding => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td style="padding: 8px; border: 1px solid #444;">${finding.accountName}</td>
                    <td style="padding: 8px; border: 1px solid #444;">${finding.section}</td>
                    <td style="padding: 8px; border: 1px solid #444;">
                        <a href="#" onclick="navigateToFinding('${finding.accountId}', '${finding.link}', event)" style="color: #ffcc00; text-decoration: underline;">${finding.name}</a>
                    </td>
                    <td style="padding: 8px; border: 1px solid #444; font-weight: bold;">${finding.score}</td>
                `;
                topRisksTableBody.appendChild(tr);
            });
        }


    });
</script>
</body>
</html>
"""
import json
import os
from jinja2 import Environment, FileSystemLoader

def build_account_sections(provider="aws"):
    
    base_path = os.path.join("logs", provider)
    account_sections = {}

    if not os.path.exists(base_path):
        print(f"❌ No logs found in {base_path}")
        return {}

    for account_id in os.listdir(base_path):
        account_log_path = os.path.join(base_path, account_id, "logs.json")
        if os.path.exists(account_log_path):
            try:
                with open(account_log_path, "r", encoding="utf-8") as f:
                    log_data = json.load(f)
                    account_name = log_data.get("account_name", account_id)

                    account_sections[account_id] = {
                        "account_name": account_name,
                        "scan_data": log_data
                    }
            except Exception as e:
                print(f"❌ Error loading logs for {account_id}: {e}")
    return account_sections

def export_to_html():
    
    accounts_data = build_account_sections()
    account_sections = []
    all_account_ids = []

    try:
        for account_id, scans in accounts_data.items():
            
            account_name = scans.get("account_name", account_id)
            scan_data = scans.get("scan_data", {})
            scan_results = {}
            avg_risks = {}
            scanned_counts = {}
            failed_counts = {}
            mitre_notes = {}
            total_avg_scores = []

            for scan_key in ["iam", "ec2", "vpc", "gateways", "route53", "cloudtrail", "s3", "rds"]:
                scan_section = scan_data.get(scan_key, {})
                scan_results[scan_key] = scan_section.get("results", [])
                avg_risks[scan_key] = scan_section.get("avg_risk", 0)
                scanned_counts[scan_key] = scan_section.get("scanned_count", 0)
                failed_counts[scan_key] = scan_section.get("failed_count", 0)
                mitre_notes[scan_key] = scan_section.get("mitre_recommendations", [])
                if avg_risks[scan_key] > 0:
                    total_avg_scores.append(avg_risks[scan_key])

            total_avg_risk = round(sum(total_avg_scores) / len(total_avg_scores)) if total_avg_scores else 0

            try:
                for key, value in scan_results.items():
                    if key == "gateways":
                        if isinstance(scan_results[key], dict):
                            combined = []
                            for subtype in ["internet_gateways", "nat_gateways"]:
                                combined.extend(scan_results[key].get(subtype, []))
                            scan_results[key] = combined

                    else:
                        if not isinstance(value, list):
                            print(f"⚠️ Scan '{key}' results was not a list. Defaulting to empty.")
                            scan_results[key] = []
                            avg_risks[key] = 0
                            scanned_counts[key] = 0
                            failed_counts[key] = 0
                            mitre_notes[key] = []
                        elif value and not isinstance(value[0], dict):
                            raise ValueError(f"❌ Scan '{key}' first item is not a dict in account {account_id}: {type(value[0])}")
            except Exception as validation_err:
                print(f"[ERROR] Skipping account {account_id} due to malformed scan data: {validation_err}")
                continue

            account_sections.append({
                "account_name": account_name,
                "account_id": account_id,
                "scan_results": scan_results,
                "avg_risks": avg_risks,
                "scanned_counts": scanned_counts,
                "failed_counts": failed_counts,
                "mitre_notes": mitre_notes,
                "total_avg_risk": total_avg_risk
            })

    except Exception as e:
        print(f"❌Error in aws data: {e}")
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    report_filename = f"CloudCastle_Report_{timestamp}.html"
    report_path = os.path.join(REPORTS_DIR, report_filename)

    # Jinja template engine
    template = jinja2.Template(TEMPLATE_HTML)
    html_output = template.render(account_sections=account_sections)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_output)

    print(f"📄 Report generated: {report_path}")