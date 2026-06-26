import json
import os
import string
import secrets
import base64
from io import BytesIO
import psycopg2
import qrcode
from argon2 import PasswordHasher


ph = PasswordHasher()


def get_db_connection():
  return psycopg2.connect(
    host=os.environ.get("DB_HOST", "postgres.default.svc.cluster.local"),
    # host=os.environ.get("DB_HOST", "postgres-service"),
    port=os.environ.get("DB_PORT", "5432"),
    dbname=os.environ.get("DB_NAME", "cofrap"),
    user=os.environ.get("DB_USER", "postgres"),
    password=os.environ.get("DB_PASSWORD", "mon_mot_de_passe_secret")
  )



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


def save_user_in_db(username: str, password_hashed: str) -> bool:
  try:
    conn = get_db_connection()

    with conn.cursor() as cur:
      cur.execute(
        "INSERT INTO users (username, password) VALUES (%s, %s)",
        (username, password_hashed)
      )
    conn.commit()
    conn.close()

    return True

  except psycopg2.Error as e:
    print(f"Erreur d'insertion BDD : {e}")

    return False



def handle(req):
  try:
    if not req:
      return json.dumps({"status": "error", "message": "Requête vide"}), 400

    try:
      body = json.loads(req)
      username = body.get("username")

    except json.JSONDecodeError:
      return json.dumps({"status": "error", "message": "Format JSON invalide"}), 400

    if not username:
      return json.dumps({"status": "error", "message": "Nom d'utilisateur requis"}), 400

    password_raw = generate_secure_password(24)
    password_hashed = hash_password(password_raw)
    password_qr = generate_qr_base64(password_raw)

    db_success = save_user_in_db(username, password_hashed)

    if not db_success:
      return json.dumps({"status": "error", "message": "Erreur BDD ou utilisateur déjà existant"}), 500

    response = {
      "status": "success",
      "username": username,
      "passwordRaw": password_raw,
      "passwordQrCode": password_qr
    }

    return json.dumps(response), 200

  except Exception as e:
    return json.dumps({"status": "error", "message": str(e)}), 500
