import base64
import codecs  # <--- Add this for rot13
import random # for obfuscator function

def wrap_python(code: str) -> str:
    encoded = base64.b64encode(code.encode()).decode()
    return f"import base64;exec(base64.b64decode('{encoded}'))"

def wrap_bash(code: str) -> str:
    encoded = base64.b64encode(code.encode()).decode()
    return f"echo {encoded} | base64 -d | bash"

def wrap_php(code: str) -> str:
    encoded = base64.b64encode(code.encode()).decode()
    return f"<?php eval(base64_decode('{encoded}')); ?>"
    # This is a common way to auto-decode and execute in PHP.

    # HEX encoder for Python
def wrap_python_hex(code: str) -> str:
    encoded = code.encode().hex()
    return f"exec(bytes.fromhex('{encoded}').decode())"

# ROT13 encoder for Python
def wrap_python_rot13(code: str) -> str:
    encoded = codecs.encode(code, 'rot_13')
    return f"import codecs;exec(codecs.decode('{encoded}', 'rot_13'))"

# XOR encoder for Python
def wrap_python_xor(code: str, key: int = 23) -> str:
    xored = ''.join([f"{ord(c)^key:02x}" for c in code])
    return (
        "code='{}'\n"
        "exec(''.join([chr(int(code[i:i+2],16)^{}) for i in range(0,len(code),2)]))"
    ).format(xored, key)

# Obfuscator function for Python
# This adds random whitespace and comments to the code.
def obfuscate_python(code: str) -> str:
    lines = code.splitlines()
    obfuscated = []
    comments = [
        "# TODO: review this",
        "# Malicious? Nah!",
        "# Just another day at the office",
        "# Insert witty comment here",
        "# Obfuscated by tool"
    ]
    for line in lines:
        # Randomly add whitespace or a comment
        if line.strip() and not line.strip().startswith('#'):
            if random.random() < 0.6:
                line = " " * random.randint(0, 4) + line + " " * random.randint(0, 4)
            if random.random() < 0.4:
                line += " " + random.choice(comments)
        obfuscated.append(line)
        # Optionally insert random blank lines
        if random.random() < 0.2:
            obfuscated.append("")
    return "\n".join(obfuscated)

B64_WRAPPERS = {
    "python": wrap_python,
    "bash": wrap_bash,
    "php": wrap_php,
}

HEX_WRAPPERS = {
    "python": wrap_python_hex,
    # You can add bash/php hex wrappers later
}

ROT13_WRAPPERS = {
    "python": wrap_python_rot13,
}

XOR_WRAPPERS = {
    "python": wrap_python_xor,
}

OBFUSCATOR_WRAPPERS = {
    "python": obfuscate_python,
}