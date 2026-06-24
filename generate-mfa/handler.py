import json
import pyotp
import qrcode
import base64
from io import BytesIO



def generate_qr_base64(data: str) -> str:
  qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
  qr.add_data(data)
  qr.make(fit=True)
  img = qr.make_image(fill_color="black", back_color="white")
  buffered = BytesIO()
  img.save(buffered, format="PNG")
  return f"data:image/png;base64,{base64.b64encode(buffered.getvalue()).decode('utf-8')}"



def handle(req):
  """Point d'entrée du conteneur OpenFaaS"""
  try:
    username = "unknown_user"
    if req:
      try:
        body = json.loads(req)
        username = body.get("username", "unknown_user")
      except json.JSONDecodeError:
        pass

    mfa_secret = pyotp.random_base32()
    totp = pyotp.TOTP(mfa_secret)
    provisioning_uri = totp.provisioning_uri(name=username, issuer_name="COFRAP Cloud")
    mfa_qr_base64 = generate_qr_base64(provisioning_uri)

    response = {
      "status": "success",
      "username": username,
      "mfaSecret": mfa_secret,
      "mfaQrCode": mfa_qr_base64
    }

    return json.dumps(response), 200

  except Exception as e:
    return json.dumps({"status": "error", "message": str(e)}), 500
