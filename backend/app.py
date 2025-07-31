import os
import json
import psycopg2
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import Flask, request, redirect, url_for, jsonify
from flask_cors import CORS
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
from google.oauth2 import id_token
import gspread
import pytesseract
from PIL import Image
import io
import jwt
import datetime
from functools import wraps
import traceback # Importamos traceback para logs detallados

# --- INICIALIZACIÓN Y CONFIGURACIÓN ---
load_dotenv()
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
CORS(app, supports_credentials=True, origins=["https://batjuancrespo.github.io"])

cipher_suite = Fernet(os.environ.get("ENCRYPTION_KEY").encode())
CLIENT_SECRETS_FILE = 'client_secret.json'
SCOPES = ['https://www.googleapis.com/auth/userinfo.email', 
        'https://www.googleapis.com/auth/userinfo.profile', 
        'https://www.googleapis.com/auth/spreadsheets', 
        'openid']

# --- Carga Segura del Client ID al inicio de la aplicación ---
# Esto hace que la app sea más robusta y evita errores de "archivo no encontrado" en Render.
try:
    with open(CLIENT_SECRETS_FILE) as f:
        client_config = json.load(f)
        GOOGLE_CLIENT_ID = client_config.get('web', {}).get('client_id')
    if not GOOGLE_CLIENT_ID:
        raise ValueError("Client ID no encontrado en la estructura de client_secret.json")
except FileNotFoundError:
    print(f"ERROR CRÍTICO: El archivo '{CLIENT_SECRETS_FILE}' no fue encontrado. Asegúrate de que existe como un 'Secret File' en Render.")
    GOOGLE_CLIENT_ID = None
except Exception as e:
    print(f"ERROR CRÍTICO al cargar el Client ID: {e}")
    GOOGLE_CLIENT_ID = None


# --- LÓGICA DE TOKENS JWT ---
def create_access_token(data):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, app.secret_key, algorithm="HS256")
    return encoded_jwt

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Formato de token incorrecto'}), 401
        
        if not token:
            return jsonify({'message': 'Falta el token de autorización'}), 401

        try:
            data = jwt.decode(token, app.secret_key, algorithms=["HS256"])
            request.current_user_email = data['email']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'El token ha expirado'}), 401
        except:
            return jsonify({'message': 'El token no es válido'}), 401
        
        return f(*args, **kwargs)
    return decorated

# --- FUNCIONES DE BASE DE DATOS ---
def get_db_connection():
    conn = psycopg2.connect(os.environ.get("DATABASE_URL"))
    return conn

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
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT credentials FROM users WHERE email = %s;", (email,))
    user_data = cur.fetchone()
    cur.close()
    conn.close()
    if user_data:
        decrypted_credentials = cipher_suite.decrypt(user_data[0].encode())
        return Credentials.from_authorized_user_info(json.loads(decrypted_credentials))
    return None

# --- RUTAS DE AUTENTICACIÓN ---
@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES,
        redirect_uri=url_for('callback', _external=True))
    authorization_url, state = flow.authorization_url(access_type='offline', prompt='consent')
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    if not GOOGLE_CLIENT_ID:
        return "Error del servidor: El Client ID de Google no está configurado correctamente. Revisa los logs.", 500

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES,
        redirect_uri=url_for('callback', _external=True))
    
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    
    try:
        profile_info = id_token.verify_oauth2_token(
            credentials.id_token, 
            google.auth.transport.requests.Request(), 
            GOOGLE_CLIENT_ID # Usamos la variable global cargada al inicio
        )
    except ValueError as e:
        print(f"Error al verificar el token de Google: {e}")
        return "Token de Google inválido", 401

    user_email = profile_info.get("email")
    save_user_credentials(user_email, credentials)
    
    access_token = create_access_token(data={"email": user_email})
    
    frontend_url = os.environ.get("FRONTEND_URL").rstrip('/')
    return redirect(f"{frontend_url}/dashboard.html#token={access_token}")

# --- RUTAS DE LA API ---
@app.route('/api/profile')
@token_required
def profile():
    return jsonify({'logged_in': True, 'email': request.current_user_email})

@app.route('/api/process-image', methods=['POST'])
@token_required
def process_image():
    if 'image' not in request.files or 'sheetId' not in request.form:
        return jsonify({'error': 'Falta imagen o ID de la hoja de cálculo'}), 400

    try:
        email = request.current_user_email
        sheet_id = request.form['sheetId']
        file_storage = request.files['image']

        print(f"Iniciando procesamiento para: {email}, Sheet ID: {sheet_id}")

        credentials = load_credentials_from_db(email)
        if not credentials:
            print(f"LOG ERROR: No se encontraron credenciales en la BD para el usuario {email}")
            return jsonify({'error': 'No se pudieron cargar las credenciales del usuario'}), 500
        
        print("Credenciales cargadas desde la BD correctamente.")

        image_bytes = file_storage.read()
        image = Image.open(io.BytesIO(image_bytes))
        print("Imagen leída y abierta correctamente.")

        texto_extraido = pytesseract.image_to_string(image, lang='spa')
        print("Tesseract ha extraído el texto.")

        if not texto_extraido.strip():
            print("Tesseract no devolvió texto.")
            return jsonify({'message': 'No se detectó texto en la imagen.'})

        data_to_save = [[line] for line in texto_extraido.split('\n') if line.strip()]

        if not data_to_save:
             print("El texto extraído no contenía líneas válidas para guardar.")
             return jsonify({'message': 'No se encontró texto estructurado para guardar.'})
        
        print(f"Preparando para guardar {len(data_to_save)} filas en Google Sheets.")
        gc = gspread.authorize(credentials)
        spreadsheet = gc.open_by_key(sheet_id)
        worksheet = spreadsheet.sheet1
        worksheet.append_rows(data_to_save)
        print("¡Éxito! Datos guardados en Google Sheets.")

        return jsonify({'message': f'¡Éxito! Se han añadido {len(data_to_save)} filas a tu Google Sheet.'})

    except gspread.exceptions.SpreadsheetNotFound:
        print(f"LOG ERROR: Spreadsheet no encontrada con ID: {sheet_id}")
        return jsonify({'error': 'Hoja de cálculo no encontrada. Revisa el ID y asegúrate de haberla compartido con tu email.'}), 404
    except Exception as e:
        # Este es el log más importante. Imprimirá el error completo y detallado.
        print(f"LOG ERROR CRÍTICO en /api/process-image: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Ocurrió un error interno muy grave al procesar la imagen. Revisa los logs del servidor.'}), 500
            
@app.route('/')
def index():
    return "Backend del Lector IA funcionando."

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)