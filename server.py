from flask import Flask, request
import json
import string
import secrets
import base64
from io import BytesIO
import qrcode
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

app = Flask(__name__)
ph = PasswordHasher()



# ==========================================
# SIMULATION DE LA BASE DE DONNÉES POSTGRESQL
# (Pour tester le parcours complet en local)
# ==========================================
MOCK_DB = {}



# ==========================================
# UTILITAIRES
# ==========================================
def generate_secure_password(length=24):
  alphabet_lowercase = string.ascii_lowercase
  alphabet_uppercase = string.ascii_uppercase
  alphabet_digits = string.digits
  alphabet_special = "!:;.~µ!?§@#$%^&*"

  password = [
    secrets.choice(alphabet_lowercase), secrets.choice(alphabet_uppercase),
    secrets.choice(alphabet_digits), secrets.choice(alphabet_special)
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



# ==========================================
# ROUTE 1 : GENERATE PASSWORD
# ==========================================
@app.route('/api/generate-password', methods=['POST'])
def mock_openfaas_password():
  try:
    req_data = request.get_data(as_text=True)
    username = "unknown"

    if req_data:
      try:
        body = json.loads(req_data)
        username = body.get("username", "unknown")
      except json.JSONDecodeError:
        pass

    password_raw = generate_secure_password(24)
    password_hashed = hash_password(password_raw)
    password_qr = generate_qr_base64(password_raw)

    # Sauvegarde en BDD simulée
    if username not in MOCK_DB:
      MOCK_DB[username] = {}
    MOCK_DB[username]['password_hashed'] = password_hashed

    response = {
      "status": "success",
      "username": username,
      "passwordRaw": password_raw,
      "passwordQrCode": password_qr
    }

    return json.dumps(response), 200, {'Content-Type': 'application/json'}

  except Exception as e:
    return json.dumps({"status": "error", "message": str(e)}), 500, {'Content-Type': 'application/json'}



# ==========================================
# ROUTE 2 : GENERATE MFA
# ==========================================
@app.route('/api/generate-mfa', methods=['POST'])
def mock_openfaas_mfa():
  try:
    req_data = request.get_data(as_text=True)
    username = "unknown_user"

    if req_data:
      try:
        body = json.loads(req_data)
        username = body.get("username", "unknown_user")
      except json.JSONDecodeError:
        pass

    mfa_secret = pyotp.random_base32()
    totp = pyotp.TOTP(mfa_secret)
    provisioning_uri = totp.provisioning_uri(name=username, issuer_name="COFRAP Cloud")
    mfa_qr_base64 = generate_qr_base64(provisioning_uri)

    # Sauvegarde en BDD simulée
    if username not in MOCK_DB:
      MOCK_DB[username] = {}
    MOCK_DB[username]['mfa_secret'] = mfa_secret

    response = {
      "status": "success",
      "username": username,
      "mfaQrCode": mfa_qr_base64
    }

    return json.dumps(response), 200, {'Content-Type': 'application/json'}

  except Exception as e:
    return json.dumps({"status": "error", "message": str(e)}), 500, {'Content-Type': 'application/json'}



# ==========================================
# ROUTE 3 : VERIFY MFA
# ==========================================
@app.route('/api/verify-mfa', methods=['POST'])
def mock_openfaas_verify_mfa():
  try:
    req_data = request.get_data(as_text=True)

    if not req_data:
      return json.dumps({"status": "error", "message": "Requête vide"}), 400, {'Content-Type': 'application/json'}

    body = json.loads(req_data)
    username = body.get("username")
    totp_code = body.get("totpCode")

    user_data = MOCK_DB.get(username)
    if not user_data or 'mfa_secret' not in user_data:
      return json.dumps({"status": "error", "message": "MFA non configuré"}), 404, {'Content-Type': 'application/json'}

    totp = pyotp.TOTP(user_data['mfa_secret'])
    if totp.verify(totp_code):
      # Ton Angular attend juste un booléen `true` !
      return json.dumps(True), 200, {'Content-Type': 'application/json'}
    else:
      return json.dumps({"status": "error", "message": "Code invalide"}), 401, {'Content-Type': 'application/json'}

  except Exception as e:
    return json.dumps({"status": "error", "message": str(e)}), 500, {'Content-Type': 'application/json'}




# ==========================================
# ROUTE 4 : LOGIN
# ==========================================
@app.route('/api/login', methods=['POST'])
def mock_openfaas_login():
  try:
    req_data = request.get_data(as_text=True)

    if not req_data:
      return json.dumps({"status": "error", "message": "Requête vide"}), 400, {'Content-Type': 'application/json'}

    body = json.loads(req_data)
    username = body.get("username")
    password = body.get("password")
    totp_code = body.get("totpCode")

    user_data = MOCK_DB.get(username)
    if not user_data or 'password_hashed' not in user_data or 'mfa_secret' not in user_data:
      return json.dumps({"status": "error", "message": "Identifiants invalides"}), 401, {'Content-Type': 'application/json'}

    # Vérification Argon2
    try:
      ph.verify(user_data["password_hashed"], password)
    except VerifyMismatchError:
      return json.dumps({"status": "error", "message": "Identifiants invalides"}), 401, {'Content-Type': 'application/json'}

    # Vérification TOTP
    totp = pyotp.TOTP(user_data["mfa_secret"])
    if not totp.verify(totp_code):
      return json.dumps({"status": "error", "message": "Identifiants invalides"}), 401, {'Content-Type': 'application/json'}

    # Renvoi du User object pour Angular
    user_response = {
      "id": f"mock-uuid-{username}",
      "username": username
    }

    return json.dumps(user_response), 200, {'Content-Type': 'application/json'}

  except Exception as e:
    return json.dumps({"status": "error", "message": str(e)}), 500, {'Content-Type': 'application/json'}



if __name__ == '__main__':
  print("🚀 FaaS Mock Server complet démarré sur http://127.0.0.1:5000")
  app.run(port=5000, debug=True)
