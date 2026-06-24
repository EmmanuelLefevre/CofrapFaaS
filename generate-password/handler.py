import json
import string
import secrets
import base64
from io import BytesIO
import qrcode
from argon2 import PasswordHasher

ph = PasswordHasher()



def generate_secure_password(length=24):
  alphabet_lowercase = string.ascii_lowercase
  alphabet_uppercase = string.ascii_uppercase
  alphabet_digits = string.digits
  alphabet_special = "!:;.~µ!?§@#$%^&*"
  password = [secrets.choice(alphabet_lowercase), secrets.choice(alphabet_uppercase), secrets.choice(alphabet_digits), secrets.choice(alphabet_special)]
  all_characters = alphabet_lowercase + alphabet_uppercase + alphabet_digits + alphabet_special
  for _ in range(length - 4):
    password.append(secrets.choice(all_characters))
  secrets.SystemRandom().shuffle(password)
  return "".join(password)



def hash_password(password: str) -> str:
  return ph.hash(password)



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
    username = "unknown"
    if req:
      try:
        body = json.loads(req)
        username = body.get("username", "unknown")
      except json.JSONDecodeError:
        pass

    password_raw = generate_secure_password(24)
    password_hashed = hash_password(password_raw)
    password_qr = generate_qr_base64(password_raw)

    response = {
      "status": "success",
      "username": username,
      "passwordRaw": password_raw,
      "passwordHashed": password_hashed,
      "passwordQrCode": password_qr
    }

    return json.dumps(response), 200

  except Exception as e:
    return json.dumps({"status": "error", "message": str(e)}), 500
