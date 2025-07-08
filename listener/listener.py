# listener.py

import socket

def start_listener(lport):
    lhost = "0.0.0.0"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((lhost, lport))
        server_socket.listen(1)
        print(f"[+] Listening on {lhost}:{lport} ...")
        client_socket, addr = server_socket.accept()
        print(f"[+] Connection received from {addr[0]}:{addr[1]}")
        try:
            while True:
                command = input("Shell> ")
                if command.strip() == "":
                    continue
                if command.strip().lower() == "exit":
                    print("[!] Exiting listener and closing connection.")
                    client_socket.close()
                    break
                client_socket.send(command.encode())
                data = client_socket.recv(4096)
                if not data:
                    print("\n[!] Connection closed by client.")
                    break
                print(data.decode(errors='ignore'), end="")
        except KeyboardInterrupt:
            print("\n[!] Listener stopped by user (Ctrl+C).")
            client_socket.close()

if __name__ == "__main__":
    try:
        port_str = input("Enter the port number to listen on: ")
        lport = int(port_str.strip())
        start_listener(lport)
    except ValueError:
        print("[!] Invalid port number. Please enter a valid integer.")
