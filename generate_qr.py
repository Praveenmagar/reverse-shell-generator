import qrcode

def generate_qr(payload_url, output_img='payload_qr.png'):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=8,
        border=4,
    )
    qr.add_data(payload_url)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    img.save(output_img)
    print(f"[+] QR code generated and saved as {output_img}")

if __name__ == "__main__":
    payload_url = input("Enter the full URL to your hosted payload: ").strip()
    generate_qr(payload_url)
