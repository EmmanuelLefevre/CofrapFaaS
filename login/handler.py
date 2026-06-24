import json
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
# import psycopg2

ph = PasswordHasher()



def get_user_data_from_db(username: str) -> dict:
  """
  SIMULATION : SELECT id, password_hashed, mfa_secret FROM users WHERE username = %s
  """
  # Pour que tu puisses tester, je mets le hash du mot de passe "Test2026!Test2026!Test20"
  mock_hash = ph.hash("0$z4lµ6UYKK^oVzfm!hUwqP1")
  return {
    "id": "uuid-db-98765",
    "password_hashed": mock_hash,
    "mfa_secret": "JBSWY3DPEHPK3PXP"
  }



def handle(req):
  """Point d'entrée OpenFaaS pour la connexion"""
  try:
    if not req:
      return json.dumps({"status": "error", "message": "Requête vide"}), 400

    body = json.loads(req)
    username = body.get("username")
    password = body.get("password")
    totp_code = body.get("totpCode")

    if not username or not password or not totp_code:
      return json.dumps({"status": "error", "message": "Identifiants incomplets"}), 400

    # 1. Récupération des données BDD
    user_data = get_user_data_from_db(username)
    if not user_data:
      return json.dumps({"status": "error", "message": "Identifiants invalides"}), 401

    # 2. Vérification du mot de passe avec Argon2
    try:
      ph.verify(user_data["password_hashed"], password)
    except VerifyMismatchError:
      # Le mot de passe ne correspond pas
      return json.dumps({"status": "error", "message": "Identifiants invalides"}), 401

    # 3. Vérification du code MFA
    totp = pyotp.TOTP(user_data["mfa_secret"])
    if not totp.verify(totp_code):
      return json.dumps({"status": "error", "message": "Identifiants invalides"}), 401

    # 4. Succès total ! On renvoie l'objet User attendu par ton Angular
    user_response = {
      "id": user_data["id"],
      "username": username,
      # Tu pourras ajouter d'autres champs de ta BDD ici (rôle, email, etc.)
    }

    return json.dumps(user_response), 200

  except Exception as e:
    return json.dumps({"status": "error", "message": "Erreur serveur"}), 500
