import socket
import threading
import os
import datetime
from colorama import init, Fore, Style

init(autoreset=True)  # Initialize colorama for colored output

LOG_DIR = os.path.join(os.path.dirname(__file__), '..', 'logs')

def create_logfile(client_ip, client_port):
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"session_{client_ip.replace('.', '_')}_{client_port}_{timestamp}.txt"
    path = os.path.join(LOG_DIR, filename)
    return open(path, "w", encoding='utf-8'), path

def handle_client(client_socket, addr):
    client_ip, client_port = addr
    print(Fore.GREEN + f"[+] New session: {client_ip}:{client_port}")
    log, log_path = create_logfile(client_ip, client_port)
    cmd_count, resp_count = 0, 0

    try:
        while True:
            command = input(Fore.YELLOW + f"Shell ({client_ip}:{client_port})> " + Style.RESET_ALL)
            if command.strip() == "":
                continue
            log.write(f"Local> {command}\n")
            log.flush()
            cmd_count += 1
            if command.strip().lower() == "exit":
                print(Fore.CYAN + "[!] Closing connection.")
                client_socket.send(command.encode())
                break
            client_socket.send(command.encode())
            data = client_socket.recv(4096)
            if not data:
                print(Fore.RED + "\n[!] Connection closed by client.")
                break
            output = data.decode(errors='ignore')
            print(Fore.CYAN + output + Style.RESET_ALL, end="")
            log.write(f"Remote> {output}\n")
            log.flush()
            resp_count += 1
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Session stopped by user (Ctrl+C).")
    finally:
        client_socket.close()
        log.close()
        print(Fore.GREEN + f"[+] Session with {client_ip}:{client_port} ended.")
        print(Fore.MAGENTA + f"[+] Session log saved: {log_path}")
        print(Fore.MAGENTA + f"[i] Commands sent: {cmd_count}, Responses received: {resp_count}")

def start_listener(lport):
    lhost = "0.0.0.0"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((lhost, lport))
        server_socket.listen(5)
        print(Fore.GREEN + f"[+] Listening on {lhost}:{lport} ...")
        try:
            while True:
                client_socket, addr = server_socket.accept()
                print(Fore.BLUE + f"[+] Connection received from {addr[0]}:{addr[1]}")
                thread = threading.Thread(target=handle_client, args=(client_socket, addr), daemon=True)
                thread.start()
        except KeyboardInterrupt:
            print(Fore.RED + "\n[!] Listener stopped by user (Ctrl+C).")

if __name__ == "__main__":
    try:
        port_str = input(Fore.YELLOW + "Enter the port number to listen on: " + Style.RESET_ALL)
        lport = int(port_str.strip())
        start_listener(lport)
    except ValueError:
        print(Fore.RED + "[!] Invalid port number. Please enter a valid integer.")
