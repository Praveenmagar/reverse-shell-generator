import os
import re
import ipaddress
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

def _clean_emails(val):
    if isinstance(val, list):
        return ", ".join(str(e) for e in val)
    return str(val) if val else ""

def whois_domain(domain):
    try:
        w = whois.whois(domain)
        return {
            "domain": domain,
            "registrar": str(w.registrar or ""),
            "creation_date": _clean_datetime(w.creation_date),
            "expiration_date": _clean_datetime(w.expiration_date),
            "org": str(w.org or ""),
            "country": str(w.country or ""),
            "emails": _clean_emails(w.emails),
        }
    except Exception as e:
        return {"domain": domain, "error": str(e)}

def whois_ip(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        return {
            "ip": ip,
            "asn": str(res.get("asn") or ""),
            "org": str(res.get("network", {}).get("name") or ""),
            "country": str(res.get("network", {}).get("country") or ""),
            "cidr": str(res.get("network", {}).get("cidr") or ""),
        }
    except Exception as e:
        return {"ip": ip, "error": str(e)}

def generate_whois_html(domain_results, ip_results):
    style = """
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap');
        html,body { height: 100%; margin: 0; padding: 0; background: #f4f8fb;}
        body { font-family: 'Roboto', Arial, sans-serif; }
        .whois-outer-wrap {
            display: flex;
            flex-direction: column;
            align-items: center;
            min-height: 100vh;
            justify-content: flex-start;
            padding: 0;
            background: #f4f8fb;
        }
        .whois-container {
            width: 100%;
            max-width: 1080px;
            margin: 0 auto;
            margin-top: 36px;
            margin-bottom: 36px;
            background: none;
            box-shadow: none;
        }
        h2 {
            color: #2e53a2;
            font-size: 2.1em;
            text-align: center;
            margin: 32px 0 26px 0;
            font-weight: 900;
            letter-spacing: 1px;
        }
        .whois-table-wrap {
            width: 100%;
            display: flex;
            justify-content: center;
            margin: 0 auto 35px auto;
        }
        table {
            border-collapse: collapse;
            width: 98%;
            background: #fff;
            border-radius: 16px;
            box-shadow: 0 2px 24px 0 rgba(70,110,255,0.08), 0 1.5px 6px rgba(0,0,0,0.03);
            overflow: hidden;
            margin: 0 auto 15px auto;
        }
        th, td {
            padding: 12px 16px;
            text-align: left;
            border: none;
        }
        th {
            background: #e6ecfa;
            color: #24486c;
            font-weight: 700;
            font-size: 1.08em;
        }
        tr {
            border-bottom: 1.5px solid #f2f4fa;
        }
        tr:last-child {
            border-bottom: none;
        }
        td {
            color: #202d3c;
            font-size: 1.02em;
        }
        .whois-error-row td {
            color: #e74c3c;
            font-weight: bold;
            background: #f8eaea;
            font-size: 1em;
        }
        @media (max-width: 900px) {
            .whois-container { max-width: 99vw; }
            .whois-table-wrap { width: 99vw; }
            table { width: 100%; font-size: 0.97em;}
            th, td { padding: 9px 7px; }
        }
        @media (max-width: 600px) {
            h2 { font-size: 1.2em; }
            .whois-container { padding: 0 1vw; }
            .whois-table-wrap { width: 99vw; }
            th, td { padding: 6px 2vw; font-size: 0.93em;}
            table { font-size: 0.97em;}
        }
    </style>
    """

    html = style + '<div class="whois-outer-wrap"><div class="whois-container">\n'

    # --- Domains Table ---
    if domain_results:
        html += "<h2>WHOIS Results – Domains</h2>\n<div class='whois-table-wrap'><table><tr>"
        headers = ["Domain", "Registrar", "Organization", "Country", "Creation Date", "Expiry Date", "Email(s)"]
        for h in headers:
            html += f"<th>{h}</th>"
        html += "</tr>\n"
        for r in domain_results:
            if "error" in r:
                html += f"<tr class='whois-error-row'><td colspan='{len(headers)}'>{r['domain']}: {r['error']}</td></tr>"
            else:
                html += "<tr>" + "".join([
                    f"<td>{r.get('domain','')}</td>",
                    f"<td>{r.get('registrar','')}</td>",
                    f"<td>{r.get('org','')}</td>",
                    f"<td>{r.get('country','')}</td>",
                    f"<td>{r.get('creation_date','')}</td>",
                    f"<td>{r.get('expiration_date','')}</td>",
                    f"<td>{r.get('emails','')}</td>",
                ]) + "</tr>\n"
        html += "</table></div>"

    # --- IPs Table ---
    if ip_results:
        html += "<h2>WHOIS Results – IPs</h2>\n<div class='whois-table-wrap'><table><tr>"
        headers = ["IP", "ASN", "Organization", "Country", "CIDR"]
        for h in headers:
            html += f"<th>{h}</th>"
        html += "</tr>\n"
        for r in ip_results:
            if "error" in r:
                html += f"<tr class='whois-error-row'><td colspan='{len(headers)}'>{r['ip']}: {r['error']}</td></tr>"
            else:
                html += "<tr>" + "".join([
                    f"<td>{r.get('ip','')}</td>",
                    f"<td>{r.get('asn','')}</td>",
                    f"<td>{r.get('org','')}</td>",
                    f"<td>{r.get('country','')}</td>",
                    f"<td>{r.get('cidr','')}</td>",
                ]) + "</tr>\n"
        html += "</table></div>"

    html += '</div></div>'
    return html

def prompt_for_domains_or_ips():
    """
    Prompt the user for domains or IPs and ensure only valid inputs are accepted.
    Returns: (valid_domains, valid_ips)
    """
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
            print("No valid domains or IPs detected. Please try again.\n")
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
        table = []
        for r in domain_results:
            if "error" in r:
                table.append([r['domain'], "ERROR: "+r['error'], "", "", "", "", ""])
            else:
                table.append([
                    r.get('domain',''), r.get('registrar',''), r.get('org',''), r.get('country',''),
                    r.get('creation_date',''), r.get('expiration_date',''), r.get('emails','')
                ])
        print("\n[Domain WHOIS Results]")
        print(tabulate(table, headers=["Domain", "Registrar", "Org", "Country", "Creation", "Expiry", "Email"], tablefmt="fancy_grid"))

    if ip_results:
        table = []
        for r in ip_results:
            if "error" in r:
                table.append([r['ip'], "ERROR: "+r['error'], "", "", ""])
            else:
                table.append([
                    r.get('ip',''), r.get('asn',''), r.get('org',''), r.get('country',''), r.get('cidr','')
                ])
        print("\n[IP WHOIS Results]")
        print(tabulate(table, headers=["IP", "ASN", "Org", "Country", "CIDR"], tablefmt="fancy_grid"))

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
