import json
import pyotp
import psycopg2
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()


DB_CONFIG = "host=postgres-service port=5432 dbname=postgres user=postgres password=mon_mot_de_passe_secret"


def get_user_data_from_db(username: str) -> dict:
  try:
    conn = psycopg2.connect(DB_CONFIG)

    with conn.cursor() as cur:
      cur.execute(
        "SELECT id, password, mfa_secret FROM users WHERE username = %s",
        (username,)
      )
      row = cur.fetchone()

    conn.close()

    if row:
      return {
        "id": row[0],
        "password": row[1],
        "mfa_secret": row[2]
      }

    return None

  except psycopg2.Error as e:
    print(f"Erreur de connexion BDD : {e}")

    return None



def handle(req):
  try:
    if not req:
      return json.dumps({"status": "error", "message": "Requête vide"}), 400

    body = json.loads(req)
    username = body.get("username")
    password_input = body.get("password")
    totp_code = body.get("totpCode")

    if not username or not password_input or not totp_code:
      return json.dumps({"status": "error", "message": "Identifiants incomplets"}), 400

    user_data = get_user_data_from_db(username)
    if not user_data:
      return json.dumps({"status": "error", "message": "Identifiants invalides"}), 401

    try:
      ph.verify(user_data["password"], password_input)
    except VerifyMismatchError:
      return json.dumps({"status": "error", "message": "Identifiants invalides"}), 401

    totp = pyotp.TOTP(user_data["mfa_secret"])
    if not totp.verify(totp_code):
      return json.dumps({"status": "error", "message": "Identifiants invalides"}), 401

    user_response = {
      "id": user_data["id"],
      "username": username,
    }

    return json.dumps(user_response), 200

  except Exception as e:
    print(f"Erreur serveur : {e}")

    return json.dumps({"status": "error", "message": "Erreur serveur"}), 500
