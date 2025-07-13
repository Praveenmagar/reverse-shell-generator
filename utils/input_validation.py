import socket

def is_valid_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except socket.error:
        return False

def is_valid_hostname(hostname):
    if len(hostname) > 255 or not hostname:
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.")
    return all(c in allowed for c in hostname)

def is_valid_port(port_str):
    if not port_str.isdigit():
        return False
    port = int(port_str)
    return 1 <= port <= 65535

def get_lhost():
    while True:
        lhost = input("Enter attacker IP (LHOST): ").strip()
        if lhost and (is_valid_ip(lhost) or is_valid_hostname(lhost)):
            return lhost  # FIXED: Don't cast to int!
        print("[!] Invalid IP address or hostname. Please try again.")

def get_lport():
    while True:
        lport = input("Enter listener port (LPORT): ").strip()
        if is_valid_port(lport):
            return int(lport)
        print("[!] Invalid port number. Please enter an integer between 1 and 65535.")
