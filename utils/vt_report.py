import requests
import time
import os
import datetime

def upload_file_to_virustotal(filepath, api_key):
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {'x-apikey': api_key}
    with open(filepath, 'rb') as f:
        files = {'file': (filepath, f)}
        response = requests.post(url, files=files, headers=headers)
    if response.status_code == 200:
        file_id = response.json()['data']['id']
        print("[*] File uploaded to VirusTotal. Scan ID:", file_id)
        return file_id
    else:
        print("[!] Error uploading file:", response.text)
        return None

def generate_html_report(file_path, stats, results, vt_url):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    malicious = stats.get('malicious', 0)
    undetected = stats.get('undetected', 0)
    suspicious = stats.get('suspicious', 0)
    harmless = stats.get('harmless', 0)
    total = sum(stats.values())
    fname = os.path.basename(file_path)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>AV Scan Report for {fname}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap');
        body {{
            font-family: 'Roboto', Arial, sans-serif;
            background: #f5fafd;
            margin: 0;
            padding: 0;
        }}
        .container {{
            max-width: 1050px;
            margin: 0 auto;
            padding: 24px 16px 50px 16px;
        }}
        .header {{
            margin-top: 40px;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
        }}
        h1 {{
            color: #e74c3c;
            font-size: 2em;
            margin: 0;
            line-height: 1.15;
        }}
        .info {{
            margin-bottom: 10px;
            color: #444;
        }}
        .summary-cards {{
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            margin: 22px 0 30px 0;
            justify-content: center;
        }}
        .card {{
            background: #fff;
            border-radius: 12px;
            box-shadow: 0 2px 12px rgba(60,60,60,0.07);
            padding: 18px 32px;
            text-align: center;
            min-width: 130px;
            flex: 1 1 150px;
            margin-bottom: 6px;
        }}
        .card-title {{
            font-size: 1em;
            color: #888;
        }}
        .card-value {{
            font-size: 2.1em;
            font-weight: bold;
            margin-top: 2px;
        }}
        .malicious {{ color: #e74c3c; }}
        .undetected, .harmless {{ color: #2ecc71; }}
        .suspicious {{ color: #f1c40f; }}
        #chart-wrap {{
            margin: 32px auto 16px auto;
            width: 100%;
            max-width: 370px;
            background: #fff;
            padding: 10px 10px 24px 10px;
            border-radius: 12px;
            box-shadow: 0 1px 8px rgba(0,0,0,0.07);
            display: flex;
            justify-content: center;
        }}
        h2 {{
            margin-top: 36px;
            color: #1d2636;
        }}
        .table-responsive {{
            overflow-x: auto;
            width: 100%;
            margin-bottom: 20px;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            min-width: 480px;
            margin-top: 10px;
            background: #fff;
            border-radius: 10px;
            box-shadow: 0 1px 6px rgba(80,80,80,0.04);
        }}
        th, td {{
            border: 1px solid #f2f2f2;
            padding: 10px 14px;
            text-align: left;
        }}
        th {{
            background: #f7cac9;
        }}
        tr:hover {{
            background: #f2f9fa;
        }}
        .vt-link {{
            margin: 30px 0 12px 0;
            font-size: 1.05em;
            word-break: break-all;
        }}
        .pdf-export-wrap {{
            margin: 30px 0 12px 0;
        }}
        /* Mobile Responsiveness */
        @media (max-width: 800px) {{
            .container {{
                padding: 10px 3vw 40px 3vw;
            }}
            .header {{
                flex-direction: column;
                align-items: flex-start;
            }}
            h1 {{
                font-size: 1.5em;
            }}
            .summary-cards {{
                flex-direction: column;
                gap: 10px;
            }}
            .card {{
                min-width: unset;
                width: 100%;
                box-sizing: border-box;
            }}
            #chart-wrap {{
                max-width: 98vw;
            }}
            table {{
                min-width: 420px;
                font-size: 0.95em;
            }}
        }}
        @media (max-width: 550px) {{
            h1 {{
                font-size: 1.08em;
            }}
            .card-value {{
                font-size: 1.5em;
            }}
            table {{
                min-width: 340px;
            }}
        }}
        /* Hide PDF export button and clean up for print */
        @media print {{
            button[onclick="window.print()"] {{
                display: none !important;
            }}
            .pdf-export-wrap {{
                display: none !important;
            }}
            .container {{
                box-shadow: none !important;
                background: #fff !important;
                padding: 0 !important;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>AV Scan Report for {fname}</h1>
        </div>
        <div class="info"><b>Report generated:</b> {now}</div>
        <div class="summary-cards">
            <div class="card"><div class="card-title">Total Engines</div><div class="card-value">{total}</div></div>
            <div class="card"><div class="card-title">Malicious</div><div class="card-value malicious">{malicious}</div></div>
            <div class="card"><div class="card-title">Undetected</div><div class="card-value undetected">{undetected}</div></div>
            <div class="card"><div class="card-title">Suspicious</div><div class="card-value suspicious">{suspicious}</div></div>
            <div class="card"><div class="card-title">Harmless</div><div class="card-value harmless">{harmless}</div></div>
        </div>
        <div id="chart-wrap">
            <canvas id="avStatsChart" width="320" height="200"></canvas>
        </div>
        <h2>Detailed AV Results</h2>
        <div class="table-responsive">
        <table>
            <tr><th>AV Engine</th><th>Category</th><th>Result</th></tr>
"""
    for engine, verdict in results.items():
        category = verdict.get('category', 'unknown')
        result = verdict.get('result', 'Clean' if category == 'undetected' else category.capitalize())
        color = "#e74c3c" if category == "malicious" else "#2ecc71" if category in ("undetected", "harmless") else "#f1c40f"
        html += f"<tr><td>{engine}</td><td style='color:{color}'>{category.capitalize()}</td><td>{result}</td></tr>\n"

    html += f"""    </table>
        </div>
        <div class="vt-link"><b>VirusTotal link:</b> <a href="{vt_url}" target="_blank">{vt_url}</a></div>
        <div class="pdf-export-wrap">
            <button onclick="window.print()" style="
                padding: 10px 26px;
                background: #e74c3c;
                color: #fff;
                border: none;
                border-radius: 7px;
                font-size: 1.08em;
                cursor: pointer;
                font-family: inherit;
                box-shadow: 0 1px 5px rgba(60,0,0,0.07);
                transition: background 0.18s;">
                Export as PDF
            </button>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
    const data = {{
        labels: ["Malicious", "Undetected", "Suspicious", "Harmless"],
        datasets: [{{
            data: [{malicious}, {undetected}, {suspicious}, {harmless}],
            backgroundColor: [
                "#e74c3c", "#2ecc71", "#f1c40f", "#3498db"
            ]
        }}]
    }};
    window.onload = function(){{
        var ctx = document.getElementById('avStatsChart').getContext('2d');
        window.avChart = new Chart(ctx, {{
            type: 'doughnut',
            data: data,
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        display: true,
                        position: 'bottom'
                    }}
                }},
                cutout: "60%"
            }}
        }});
    }};
    </script>
</body>
</html>"""

    report_dir = "output/reports"
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, f"{fname}.av_report.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] HTML report generated: {report_path}")
    return report_path

def get_vt_report(file_id, api_key, file_path=None):
    url = f'https://www.virustotal.com/api/v3/analyses/{file_id}'
    headers = {'x-apikey': api_key}
    vt_url = None
    max_attempts = 36   # 36 x 5s = 180s = 3 minutes (you can increase this)
    for i in range(max_attempts):
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            analysis = response.json()
            status = analysis['data']['attributes']['status']
            if status == 'completed':
                stats = analysis['data']['attributes']['stats']
                results = analysis['data']['attributes']['results']
                sha256 = analysis.get('meta', {}).get('file_info', {}).get('sha256', '')
                vt_url = f"https://www.virustotal.com/gui/file/{sha256}/detection" if sha256 else ""
                print(f"\n[*] AV Scan Complete: {stats.get('malicious',0)} / {sum(stats.values())} engines flagged as malicious.\n")
                if file_path:
                    generate_html_report(file_path, stats, results, vt_url)
                return stats
            else:
                print(f"[*] Scan in progress, waiting... ({i+1}/{max_attempts})")
                time.sleep(5)
        else:
            print("[!] Error fetching report:", response.text)
            break
    print("[!] Report not ready after waiting.")
    return None
