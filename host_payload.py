# host_payload.py

import http.server
import socketserver
import os

def serve_directory(directory="output", port=8080):
    """
    Serve the specified directory via a simple HTTP server on the given port.
    Prints a goodbye and thank-you message when stopped with Ctrl+C.
    """
    os.chdir(directory)
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", port), handler) as httpd:
        print(f"[+] Serving '{directory}' at http://0.0.0.0:{port}/")
        print("[+] Press Ctrl+C to stop the server.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[!] Stopped HTTP server. Goodbye Dear 👋😊.")
            print("[*] Thank you for using the payload host! 🙏")
