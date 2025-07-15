import os
import re
import ipaddress
import csv
from tabulate import tabulate
from datetime import datetime

try:
    import whois
    from ipwhois import IPWhois
except ImportError:
    print("Please install dependencies: pip install whois ipwhois tabulate")
    exit(1)

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_domain(domain):
    domain = domain.strip()
    if len(domain) > 255 or '.' not in domain:
        return False
    pattern = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
    )
    return bool(pattern.search(domain))

def _clean_datetime(val):
    if isinstance(val, list):
        val = val[0] if val else ""
    if isinstance(val, datetime):
        return val.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(val, str):
        return val
    return str(val) if val else ""

def _clean_list(val):
    if isinstance(val, list):
        return ", ".join(str(x) for x in val)
    return str(val) if val else ""

def _clean_emails(val):
    if isinstance(val, list):
        return ", ".join(str(e) for e in val)
    return str(val) if val else ""

def whois_domain(domain):
    try:
        w = whois.whois(domain)
        return {
            "Domain": domain,
            "Registry Domain ID": str(getattr(w, "domain_id", "")),
            "Registrar": str(w.registrar or ""),
            "Registrar IANA ID": str(getattr(w, "registrar_id", "")),
            "Registrar WHOIS Server": str(getattr(w, "whois_server", "")),
            "Registrar URL": str(getattr(w, "url", "")),
            "Registrar Abuse Email": str(getattr(w, "abuse_contact_email", "")),
            "Registrar Abuse Phone": str(getattr(w, "abuse_contact_phone", "")),
            "Creation Date": _clean_datetime(w.creation_date),
            "Updated Date": _clean_datetime(getattr(w, "updated_date", "")),
            "Expiry Date": _clean_datetime(w.expiration_date),
            "Status": _clean_list(getattr(w, "status", "")),
            "Name Servers": _clean_list(w.name_servers),
            "DNSSEC": str(getattr(w, "dnssec", "")),
            "Registrant Name": str(getattr(w, "name", "")),
            "Registrant Organization": str(w.org or ""),
            "Registrant Country": str(w.country or ""),
            "Registrant Address": _clean_list(getattr(w, "address", "")),
            "Registrant City": str(getattr(w, "city", "")),
            "Registrant State": str(getattr(w, "state", "")),
            "Registrant Zip": str(getattr(w, "zipcode", "")),
            "Registrant Email": _clean_emails(w.emails),
            "Registrant Phone": str(getattr(w, "phone", "")),
        }
    except Exception as e:
        return {"Domain": domain, "Error": str(e)}

def whois_ip(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        return {
            "IP": ip,
            "ASN": str(res.get("asn") or ""),
            "Organization": str(res.get("network", {}).get("name") or ""),
            "Country": str(res.get("network", {}).get("country") or ""),
            "CIDR": str(res.get("network", {}).get("cidr") or ""),
        }
    except Exception as e:
        return {"IP": ip, "Error": str(e)}

def generate_whois_html(domain_results, ip_results):
    import json
    domains_json = json.dumps(domain_results, ensure_ascii=False, indent=2)
    ips_json = json.dumps(ip_results, ensure_ascii=False, indent=2)

    style = """
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap');
        html,body { height: 100%; margin: 0; padding: 0; background: #f8fafc; }
        body { font-family: 'Roboto', Arial, sans-serif; color: #273245; }
        .whois-header {
            background: #24486c;
            color: #fff;
            padding: 28px 0 14px 0;
            font-size: 2.1em;
            font-weight: 800;
            letter-spacing: 1px;
            text-align: center;
            border-bottom: 3px solid #3866a6;
            box-shadow: 0 2px 24px 0 rgba(30,70,180,0.12);
        }
        .download-btn-bar {
            text-align: center;
            margin: 20px 0 0 0;
            padding-bottom: 12px;
        }
        .download-btn {
            background: #295ad2;
            color: #fff;
            border: none;
            border-radius: 6px;
            padding: 10px 23px;
            margin: 0 13px;
            font-size: 1.04em;
            font-weight: 700;
            cursor: pointer;
            transition: background 0.16s;
            box-shadow: 0 2px 7px 0 rgba(50,70,120,0.08);
            outline: none;
        }
        .download-btn:hover { background: #174ac6; }
        .whois-footer {
            margin-top: 24px;
            padding: 14px 0 22px 0;
            font-size: 1em;
            color: #5c7180;
            background: #e6ecfa;
            text-align: center;
            border-top: 2px solid #dde4ef;
        }
        .whois-outer-wrap {
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: flex-start;
            background: #f8fafc;
            margin: 0;
            padding: 0;
        }
        .whois-container {
            width: 100%;
            max-width: 900px;
            margin: 0 auto 36px auto;
            background: none;
        }
        .whois-section-title {
            color: #24486c;
            font-size: 1.25em;
            margin: 32px 0 18px 0;
            font-weight: 800;
            letter-spacing: 1px;
        }
        .whois-cards {
            display: flex;
            flex-direction: column;
            gap: 30px;
            margin-bottom: 48px;
        }
        .whois-card {
            border-radius: 18px;
            box-shadow: 0 2px 18px 0 rgba(40,90,200,0.09), 0 1.5px 6px rgba(0,0,0,0.03);
            background: #fff;
            padding: 28px 26px 18px 26px;
            margin: 0;
            min-width: 0;
            display: flex;
            flex-direction: column;
            gap: 0;
            transition: box-shadow 0.2s;
            border-left: 5px solid #24486c;
        }
        .whois-card:hover {
            box-shadow: 0 6px 32px 0 rgba(40,90,200,0.19), 0 1.5px 12px rgba(0,0,0,0.05);
        }
        .whois-fields {
            display: flex;
            flex-direction: column;
            gap: 2px;
        }
        .whois-field-row {
            display: flex;
            flex-direction: row;
            padding: 3.5px 0;
            border-bottom: 1px solid #f5f6fa;
        }
        .whois-label {
            width: 200px;
            min-width: 120px;
            font-weight: 700;
            color: #214274;
            padding-right: 18px;
        }
        .whois-value {
            color: #2a3442;
            word-break: break-all;
            flex: 1;
        }
        .whois-card-error {
            border-left: 5px solid #e74c3c !important;
            background: #fff3f3 !important;
        }
        .whois-error-label {
            color: #c0392b;
            font-weight: bold;
        }
        @media (max-width: 700px) {
            .whois-container { max-width: 99vw; }
            .whois-card { padding: 16px 7vw 8px 7vw; }
            .whois-label { width: 110px; padding-right: 7px; font-size: 0.99em;}
            .whois-value { font-size: 0.98em;}
            .whois-header { font-size: 1.15em; padding: 18px 0 9px 0;}
        }
        @media (max-width: 430px) {
            .whois-label { width: 72px; font-size: 0.93em;}
            .whois-value { font-size: 0.93em;}
            .whois-card { padding: 11px 2vw 5px 2vw;}
        }
    </style>
    """

    html_top = f'''
    {style}
    <div class="whois-outer-wrap">
        <div class="whois-header">WHOIS Lookup Results</div>
        <div class="download-btn-bar">
            <button class="download-btn" onclick="downloadCSV('domain')">Download Domain CSV</button>
            <button class="download-btn" onclick="downloadPDF('domain')">Download Domain PDF</button>
            <button class="download-btn" onclick="downloadCSV('ip')">Download IP CSV</button>
            <button class="download-btn" onclick="downloadPDF('ip')">Download IP PDF</button>
        </div>
        <div class="whois-container">
    '''

    html_domains = ""
    if domain_results:
        html_domains += '<div class="whois-section-title">Domain WHOIS Results</div>'
        html_domains += '<div class="whois-cards" id="domain-cards">'
        for r in domain_results:
            if "Error" in r:
                html_domains += '<div class="whois-card whois-card-error">'
                html_domains += f'<div class="whois-field-row"><span class="whois-label whois-error-label">Error</span><span class="whois-value">{r.get("Domain","")}: {r.get("Error","")}</span></div>'
                html_domains += '</div>'
                continue
            html_domains += '<div class="whois-card"><div class="whois-fields">'
            for k, v in r.items():
                html_domains += f'<div class="whois-field-row"><span class="whois-label">{k}</span><span class="whois-value">{v}</span></div>'
            html_domains += '</div></div>'
        html_domains += '</div>'

    html_ips = ""
    if ip_results:
        html_ips += '<div class="whois-section-title">IP WHOIS Results</div>'
        html_ips += '<div class="whois-cards" id="ip-cards">'
        for r in ip_results:
            if "Error" in r:
                html_ips += '<div class="whois-card whois-card-error">'
                html_ips += f'<div class="whois-field-row"><span class="whois-label whois-error-label">Error</span><span class="whois-value">{r.get("IP","")}: {r.get("Error","")}</span></div>'
                html_ips += '</div>'
                continue
            html_ips += '<div class="whois-card"><div class="whois-fields">'
            for k, v in r.items():
                html_ips += f'<div class="whois-field-row"><span class="whois-label">{k}</span><span class="whois-value">{v}</span></div>'
            html_ips += '</div></div>'
        html_ips += '</div>'

    html_js = f"""
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>
    <script>
    const domainData = {domains_json};
    const ipData = {ips_json};
    function convertToCSV(objArray) {{
        const array = typeof objArray !== 'object' ? JSON.parse(objArray) : objArray;
        if(array.length === 0) return '';
        let str = '';
        str += Object.keys(array[0]).join(',') + '\\r\\n';
        for (let i = 0; i < array.length; i++) {{
            let line = '';
            for (let idx in array[0]) {{
                let val = array[i][idx] !== undefined ? array[i][idx] : '';
                line += ('"' + String(val).replace(/"/g, '""') + '",');
            }}
            str += line.slice(0, -1) + '\\r\\n';
        }}
        return str;
    }}
    function downloadCSV(type) {{
        let data = type==='domain' ? domainData : ipData;
        if(!data.length) {{ alert('No data to export'); return; }}
        let csv = convertToCSV(data);
        let blob = new Blob([csv], {{type: 'text/csv'}});
        let url = URL.createObjectURL(blob);
        let a = document.createElement('a');
        a.href = url;
        a.download = type + '_whois_export.csv';
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }}
    function downloadPDF(type) {{
        let container = document.getElementById(type+'-cards');
        if(!container) {{ alert('No data to export'); return; }}
        let opt = {{
            margin:       0.28,
            filename:     type + '_whois_export.pdf',
            image:        {{ type: 'jpeg', quality: 0.96 }},
            html2canvas:  {{ scale: 1.35, useCORS: true }},
            jsPDF:        {{ unit: 'in', format: 'a4', orientation: 'landscape' }}
        }};
        html2pdf().from(container).set(opt).save();
    }}
    </script>
    """

    html_footer = (
        '</div>'
        '<div class="whois-footer">Generated by WHOIS Lookup Utility &copy; 2025</div>'
        '</div>'
        + html_js
    )

    return html_top + html_domains + html_ips + html_footer

def prompt_for_domains_or_ips():
    while True:
        user_input = input("Enter domains or IPs (comma separated):\n").strip()
        if not user_input:
            print("Please enter at least one domain or IP.\n")
            continue

        items = [item.strip() for item in user_input.split(",") if item.strip()]
        valid_domains, valid_ips, invalid_items = [], [], []

        for item in items:
            if is_valid_ip(item):
                valid_ips.append(item)
            elif is_valid_domain(item):
                valid_domains.append(item)
            else:
                invalid_items.append(item)

        if not valid_domains and not valid_ips:
            print("\033[91mNo valid domains or IPs detected. Please try again.\033[0m\n")
            continue
        if invalid_items:
            print("These items are invalid and will be skipped: " + ", ".join(invalid_items))
            print("Please re-enter with only valid domains or IPs.\n")
            continue
        break

    return valid_domains, valid_ips

if __name__ == "__main__":
    print("=== WHOIS Lookup Utility ===")
    valid_domains, valid_ips = prompt_for_domains_or_ips()

    domain_results = [whois_domain(d) for d in valid_domains]
    ip_results = [whois_ip(ip) for ip in valid_ips]

    # Terminal pretty print for convenience
    if domain_results:
        headers = list(domain_results[0].keys())
        table = []
        for r in domain_results:
            row = [r.get(h, "") for h in headers]
            table.append(row)
        print("\n[Domain WHOIS Results]")
        print(tabulate(table, headers=headers, tablefmt="fancy_grid"))

    if ip_results:
        headers = list(ip_results[0].keys())
        table = []
        for r in ip_results:
            row = [r.get(h, "") for h in headers]
            table.append(row)
        print("\n[IP WHOIS Results]")
        print(tabulate(table, headers=headers, tablefmt="fancy_grid"))

    # Ensure the output directory exists
    output_dir = "output/reports"
    os.makedirs(output_dir, exist_ok=True)

    outname = input("Enter filename to save WHOIS HTML report (default: whois_lookup.html): ").strip()
    if not outname:
        outname = "whois_lookup.html"
    if not outname.endswith(".html"):
        outname += ".html"
    output_file = os.path.join(output_dir, outname)

    html_snippet = generate_whois_html(domain_results, ip_results)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_snippet)
    print(f"\n[+] Styled HTML WHOIS report saved: {output_file}\nOpen it in your browser!")

