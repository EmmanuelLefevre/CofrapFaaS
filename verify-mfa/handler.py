import json
import pyotp
# import psycopg2 # À décommenter pour ton vrai code BDD



def get_mfa_secret_from_db(username: str) -> str:
  """
  SIMULATION DE TA BASE DE DONNÉES POSTGRESQL.
  Ici, tu feras ton SELECT mfa_secret FROM users WHERE username = %s
  """
  # Pour le test, on imagine que c'est le secret généré par l'étape précédente
  return "0$z4lµ6UYKK^oVzfm!hUwqP1" # Remplace par ton vrai secret de test si besoin



def handle(req):
  """Point d'entrée OpenFaaS"""
  try:
    if not req:
      return json.dumps({"status": "error", "message": "Requête vide"}), 400

    body = json.loads(req)
    username = body.get("username")
    totp_code = body.get("totpCode")

    if not username or not totp_code:
      return json.dumps({"status": "error", "message": "Paramètres manquants"}), 400

    # 1. On récupère le secret en base de données
    mfa_secret = get_mfa_secret_from_db(username)

    # 2. On vérifie le code avec pyotp
    totp = pyotp.TOTP(mfa_secret)
    is_valid = totp.verify(totp_code)

    if is_valid:
      # TODO: Ici tu peux faire un UPDATE en base pour dire "Compte activé"
      return json.dumps({"status": "success", "valid": True}), 200
    else:
      return json.dumps({"status": "error", "message": "Code TOTP invalide"}), 401

  except Exception as e:
    return json.dumps({"status": "error", "message": str(e)}), 500
