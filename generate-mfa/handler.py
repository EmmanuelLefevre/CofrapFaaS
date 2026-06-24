import json
import string
import secrets
import base64
from io import BytesIO
import psycopg2
import pyotp
import qrcode
from argon2 import PasswordHasher



DB_CONFIG = "host=postgres-service port=5432 dbname=postgres user=postgres password=mon_mot_de_passe_secret"

ph = PasswordHasher()


def generate_secure_password(length=24):
  alphabet_lowercase = string.ascii_lowercase
  alphabet_uppercase = string.ascii_uppercase
  alphabet_digits = string.digits
  alphabet_special = "!:;.~µ!?§@#$%^&*"

  password = [
    secrets.choice(alphabet_lowercase),
    secrets.choice(alphabet_uppercase),
    secrets.choice(alphabet_digits),
    secrets.choice(alphabet_special)
  ]

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



def save_user_in_db(username: str, password_hashed: str, mfa_secret: str) -> bool:
  try:
    conn = psycopg2.connect(DB_CONFIG)
    with conn.cursor() as cur:

      cur.execute(
        "INSERT INTO users (username, password, mfa_secret) VALUES (%s, %s, %s)",
        (username, password_hashed, mfa_secret)
      )

    conn.commit()
    conn.close()

    return True

  except psycopg2.Error as e:
    print(f"Erreur d'insertion BDD : {e}")

    return False



def handle(req):
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
