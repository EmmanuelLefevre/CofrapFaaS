import json
import os
import base64
from io import BytesIO
import psycopg2
import pyotp
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


def generate_qr_base64(data: str) -> str:
  qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
  qr.add_data(data)
  qr.make(fit=True)
  img = qr.make_image(fill_color="black", back_color="white")
  buffered = BytesIO()
  img.save(buffered, format="PNG")

  return f"data:image/png;base64,{base64.b64encode(buffered.getvalue()).decode('utf-8')}"


def update_user_mfa_in_db(username: str, mfa_secret: str) -> bool:
  try:
    conn = get_db_connection()

    with conn.cursor() as cur:
      cur.execute(
        "UPDATE users SET mfa_secret = %s WHERE username = %s",
        (username, mfa_secret)
      )

    conn.commit()
    conn.close()

    return True

  except psycopg2.Error as e:
    print(f"Erreur de mise à jour BDD : {e}")

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

    mfa_secret = pyotp.random_base32()
    totp = pyotp.TOTP(mfa_secret)
    provisioning_uri = totp.provisioning_uri(name=username, issuer_name="COFRAP Cloud")

    mfa_qr_base64 = generate_qr_base64(provisioning_uri)

    db_success = update_user_mfa_in_db(username, mfa_secret)

    if not db_success:
      return json.dumps({"status": "error", "message": "Utilisateur introuvable"}), 404

    response = {
      "status": "success",
      "username": username,
      "mfaQrCode": mfa_qr_base64
    }

    return json.dumps(response), 200

  except Exception as e:
    return json.dumps({"status": "error", "message": str(e)}), 500
