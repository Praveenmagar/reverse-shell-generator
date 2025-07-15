# Reverse-shell Generator

A menu-driven, multi-encoder reverse shell payload generator for penetration testers and cybersecurity enthusiasts.

---

<p align="center">
  <img src="images/reverse.png" alt="Reverse Shell Generator Banner" width="600"/>
</p>


## Features

- Generate reverse shells for **Python, Bash, PHP**
- Multiple encoding/obfuscation options: **Base64, Hex, ROT13, XOR, Whitespace/Comment Insertion**
- Interactive or command-line mode
- Colorized terminal output
- Personalized for: **Praveen Magar**

---

## Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/Praveenmagar/reverse-shell-generator.git
    cd reverse-shell-generator
    ```

2. **Install dependencies:**
    ```bash
    pip install colorama
    ```
    ```bash
    pip install qrcode[pil]
    ```
    ```bash
    pip install python-whois ipwhois
    ```
    ```bash
    pip install tabulate
    ``` 
    ```bash
    pip install requests
    ```
    ```bash
    pip install reportlab
    ```
    ```bash
    pip install secure-smtplib
    ```
---

## Installation on Linux 
1. Clone the repository
```bash
git clone https://github.com/Praveenmagar/reverse-shell-generator.git
```
2. Change into the project directory
```bash
cd reverse-shell-generator
```
3. Install the required Python package
```bash
pip3 install colorama
```
4. Run the generator (interactive mode)
```bash
python3 generator.py
```
5. Or, run with command-line arguments (example)
```bash
python3 generator.py --ip 10.10.10.10 --port 4444 --payload python --encoder xor --output shell.py
```

* For graphical user interface install this first
```bash
    sudo apt-get install python3-tk 
```

## Usage

**Interactive:**
```bash
python generator.py
```

### Serve Payloads via HTTP

After generating your payload, you can serve it for easy download:

```bash
python host_payload.py
```

