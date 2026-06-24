import json
import psycopg2
import pyotp



DB_CONFIG = "host=postgres-service port=5432 dbname=postgres user=postgres password=mon_mot_de_passe_secret"


def get_mfa_secret_from_db(username: str) -> str:
  try:
    conn = psycopg2.connect(DB_CONFIG)
    with conn.cursor() as cur:
      cur.execute(
        "SELECT mfa_secret FROM users WHERE username = %s",
        (username,)
      )
      row = cur.fetchone()

    conn.close()

    if row:
      return row[0]

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
    totp_code = body.get("totpCode")

    if not username or not totp_code:
      return json.dumps({"status": "error", "message": "Paramètres manquants"}), 400

    mfa_secret = get_mfa_secret_from_db(username)

    if not mfa_secret:
      return json.dumps({"status": "error", "message": "Utilisateur introuvable ou sans secret MFA"}), 404

    totp = pyotp.TOTP(mfa_secret)
    is_valid = totp.verify(totp_code)

    if is_valid:
      # NOTE: UPDATE en bdd pour activer le compte, etc
      return json.dumps({"status": "success", "valid": True}), 200
    else:
      return json.dumps({"status": "error", "message": "Code TOTP invalide"}), 401

  except Exception as e:
    return json.dumps({"status": "error", "message": str(e)}), 500
