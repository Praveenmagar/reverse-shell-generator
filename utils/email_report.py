# utils/email_report.py

import smtplib
import os
from email.message import EmailMessage

def send_report_via_email(
    to_email, subject, body, file_path,
    smtp_server=None, smtp_port=None, smtp_user=None, smtp_password=None
):
    smtp_server = smtp_server or os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(smtp_port or os.environ.get("SMTP_PORT", 465))
    smtp_user = smtp_user or os.environ.get("SMTP_USER")
    smtp_password = smtp_password or os.environ.get("SMTP_PASSWORD")

    if not all([smtp_user, smtp_password]):
        print("[!] SMTP credentials missing. Set SMTP_USER and SMTP_PASSWORD as environment variables.")
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = to_email
    msg.set_content(body)

    # Attach the file
    with open(file_path, "rb") as f:
        file_data = f.read()
        file_name = os.path.basename(file_path)
        msg.add_attachment(
            file_data, maintype="application",
            subtype="octet-stream", filename=file_name
        )

    try:
        with smtplib.SMTP_SSL(smtp_server, smtp_port) as smtp:
            smtp.login(smtp_user, smtp_password)
            smtp.send_message(msg)
        print(f"[+] Report emailed to {to_email}")
        return True
    except Exception as e:
        print("[!] Failed to send email:", e)
        return False
