import json
import os
import psycopg2
import pyotp

def get_db_connection():
  return psycopg2.connect(
    host=os.environ.get("DB_HOST", "postgres.default.svc.cluster.local"),
    # host=os.environ.get("DB_HOST", "postgres-service"),
    port=os.environ.get("DB_PORT", "5432"),
    dbname=os.environ.get("DB_NAME", "cofrap"),
    user=os.environ.get("DB_USER", "postgres"),
    password=os.environ.get("DB_PASSWORD", "mon_mot_de_passe_secret")
  )


def get_mfa_secret_from_db(username: str) -> str:
  try:
    conn = get_db_connection()

    with conn.cursor() as cur:
      cur.execute(
        "SELECT mfa_secret FROM users WHERE username = %s",
        (username,)
      )
      row = cur.fetchone()

    conn.close()

    return row[0] if row else None

  except psycopg2.Error as e:
    print(f"Erreur de connexion BDD : {e}")
    return None


def activate_user_in_db(username: str) -> bool:
  try:
    conn = get_db_connection()

    with conn.cursor() as cur:
      cur.execute(
        "UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE username = %s",
        (username,)
      )

    conn.commit()
    conn.close()

    return True

  except psycopg2.Error as e:
    print(f"Erreur activation BDD : {e}")
    return False


def handle(req):
  try:
    if not req:
      return json.dumps({"status": "error", "message": "Requête vide"}), 400

    try:
      body = json.loads(req)
      username = body.get("username")
      totp_code = body.get("totpCode")

    except json.JSONDecodeError:
      return json.dumps({"status": "error", "message": "JSON invalide"}), 400

    if not username or not totp_code:
      return json.dumps({"status": "error", "message": "Paramètres manquants"}), 400

    mfa_secret = get_mfa_secret_from_db(username)

    if not mfa_secret:
      return json.dumps({"status": "error", "message": "Utilisateur introuvable"}), 404

    totp = pyotp.TOTP(mfa_secret)
    is_valid = totp.verify(totp_code)

    if is_valid:
      activate_user_in_db(username)
      return json.dumps({"status": "success", "isValid": True}), 200

    else:
      return json.dumps({"status": "error", "message": "Code invalide"}), 401

  except Exception as e:
    return json.dumps({"status": "error", "message": str(e)}), 500
