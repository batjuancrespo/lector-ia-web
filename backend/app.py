import os
import json
import psycopg2
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import Flask, request, redirect, session, url_for, jsonify
from flask_cors import CORS
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
from google.oauth2 import id_token
import gspread
import pytesseract
from PIL import Image
import io

# --- INICIALIZACIÓN Y CONFIGURACIÓN ---
load_dotenv()
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)

# --- ¡¡¡LA SOLUCIÓN ESTÁ AQUÍ!!! ---
# Configura la cookie de sesión para que funcione en un entorno cross-domain (github.io -> onrender.com)
app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True
)

app.secret_key = os.environ.get("FLASK_SECRET_KEY")

# Configuración de CORS (ya estaba bien, pero la dejamos junto a la otra config)
CORS(app, supports_credentials=True, origins=["https://batjuancrespo.github.io"])


cipher_suite = Fernet(os.environ.get("ENCRYPTION_KEY").encode())

CLIENT_SECRETS_FILE = 'client_secret.json'
SCOPES = ['https://www.googleapis.com/auth/userinfo.email', 
        'https://www.googleapis.com/auth/userinfo.profile', 
        'https://www.googleapis.com/auth/spreadsheets', 
        'openid']

# (El resto del archivo es exactamente igual que antes)

# --- FUNCIONES DE BASE DE DATOS Y CIFRADO ---
def get_db_connection():
    conn = psycopg2.connect(os.environ.get("DATABASE_URL"))
    return conn

def get_user(email):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s;", (email,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    return user

def save_user_credentials(email, credentials):
    encrypted_credentials = cipher_suite.encrypt(credentials.to_json().encode())
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO users (email, credentials) VALUES (%s, %s)
        ON CONFLICT (email) DO UPDATE SET credentials = EXCLUDED.credentials;
    """, (email, encrypted_credentials.decode()))
    conn.commit()
    cur.close()
    conn.close()

def load_credentials_from_db(email):
    user = get_user(email)
    if user:
        decrypted_credentials = cipher_suite.decrypt(user[2].encode())
        return Credentials.from_authorized_user_info(json.loads(decrypted_credentials))
    return None

# --- RUTAS DE AUTENTICACIÓN ---
@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES,
        redirect_uri=url_for('callback', _external=True))
    authorization_url, state = flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    state = session['state']
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state,
        redirect_uri=url_for('callback', _external=True))
    
    flow.fetch_token(authorization_response=request.url)
    
    credentials = flow.credentials
    
    try:
        profile_info = id_token.verify_oauth2_token(
            credentials.id_token, google.auth.transport.requests.Request(), flow.client_config['client_id']
        )
    except ValueError:
        return "Invalid token", 401

    user_email = profile_info.get("email")
    session['email'] = user_email
    
    save_user_credentials(user_email, credentials)
    
    return redirect(os.environ.get("FRONTEND_URL") + "/dashboard.html")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(os.environ.get("FRONTEND_URL"))

# --- RUTAS DE LA API ---
@app.route('/api/profile')
def profile():
    if 'email' in session:
        return jsonify({'logged_in': True, 'email': session['email']})
    return jsonify({'logged_in': False})

@app.route('/api/process-image', methods=['POST'])
def process_image():
    if 'email' not in session:
        return jsonify({'error': 'No autorizado'}), 401
    
    if 'image' not in request.files or 'sheetId' not in request.form:
        return jsonify({'error': 'Falta imagen o ID de la hoja de cálculo'}), 400

    try:
        email = session['email']
        sheet_id = request.form['sheetId']
        file_storage = request.files['image']

        credentials = load_credentials_from_db(email)
        if not credentials:
            return jsonify({'error': 'No se pudieron cargar las credenciales'}), 500

        image_bytes = file_storage.read()
        image = Image.open(io.BytesIO(image_bytes))
        
        texto_extraido = pytesseract.image_to_string(image, lang='spa')

        if not texto_extraido.strip():
            return jsonify({'message': 'No se detectó texto en la imagen.'})

        data_to_save = [[line] for line in texto_extraido.split('\n') if line.strip()]

        if not data_to_save:
             return jsonify({'message': 'No se encontró texto estructurado para guardar.'})

        gc = gspread.authorize(credentials)
        spreadsheet = gc.open_by_key(sheet_id)
        worksheet = spreadsheet.sheet1
        worksheet.append_rows(data_to_save)

        return jsonify({'message': f'¡Éxito! Se han añadido {len(data_to_save)} filas a tu Google Sheet.'})

    except gspread.exceptions.SpreadsheetNotFound:
        return jsonify({'error': 'Hoja de cálculo no encontrada. Revisa el ID y tus permisos de compartir.'}), 404
    except Exception as e:
        print(f"Error en /api/process-image: {e}")
        return jsonify({'error': 'Ocurrió un error interno al procesar la imagen.'}), 500

# --- RUTA PRINCIPAL ---
@app.route('/')
def index():
    return "Backend del Lector IA funcionando."

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)