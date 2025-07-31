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
from PIL import Image
import io
import jwt
import datetime
from functools import wraps
import traceback
import google.generativeai as genai

# --- INICIALIZACIÓN Y CONFIGURACIÓN ---
load_dotenv()
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
CORS(app, supports_credentials=True, origins=["https://batjuancrespo.github.io"])

try:
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
    if not GEMINI_API_KEY: raise ValueError("GEMINI_API_KEY no configurada.")
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel('gemini-1.5-flash')
    print("SDK de Gemini configurado.")
except Exception as e:
    print(f"ERROR CRÍTICO al configurar Gemini: {e}")
    gemini_model = None

cipher_suite = Fernet(os.environ.get("ENCRYPTION_KEY").encode())
CLIENT_SECRETS_FILE = 'client_secret.json'
SCOPES = ['https://www.googleapis.com/auth/userinfo.email', 
        'https://www.googleapis.com/auth/userinfo.profile', 
        'https://www.googleapis.com/auth/spreadsheets', 
        'openid']

try:
    with open(CLIENT_SECRETS_FILE) as f:
        GOOGLE_CLIENT_ID = json.load(f).get('web', {}).get('client_id')
    if not GOOGLE_CLIENT_ID: raise ValueError("Client ID no encontrado.")
except Exception as e:
    print(f"ERROR CRÍTICO al cargar Client ID: {e}")
    GOOGLE_CLIENT_ID = None

# (Lógica de tokens y BD sin cambios)
def create_access_token(data):
    expire = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    to_encode = data.copy()
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, app.secret_key, algorithm="HS256")

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            try: token = request.headers['Authorization'].split(" ")[1]
            except IndexError: return jsonify({'message': 'Formato de token incorrecto'}), 401
        if not token: return jsonify({'message': 'Falta el token'}), 401
        try:
            data = jwt.decode(token, app.secret_key, algorithms=["HS256"])
            request.current_user_email = data['email']
        except: return jsonify({'message': 'Token no válido o expirado'}), 401
        return f(*args, **kwargs)
    return decorated

def get_db_connection():
    return psycopg2.connect(os.environ.get("DATABASE_URL"))

def save_user_credentials(email, credentials):
    encrypted_credentials = cipher_suite.encrypt(credentials.to_json().encode())
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO users (email, credentials) VALUES (%s, %s) ON CONFLICT (email) DO UPDATE SET credentials = EXCLUDED.credentials;", (email, encrypted_credentials.decode()))
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

# (Rutas de login/callback sin cambios)
@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=url_for('callback', _external=True))
    authorization_url, state = flow.authorization_url(access_type='offline', prompt='consent')
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    if not GOOGLE_CLIENT_ID: return "Error del servidor: Client ID no configurado.", 500
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=url_for('callback', _external=True))
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    try:
        profile_info = id_token.verify_oauth2_token(credentials.id_token, google.auth.transport.requests.Request(), GOOGLE_CLIENT_ID)
    except ValueError as e: return "Token de Google inválido", 401
    user_email = profile_info.get("email")
    save_user_credentials(user_email, credentials)
    access_token = create_access_token(data={"email": user_email})
    frontend_url = os.environ.get("FRONTEND_URL").rstrip('/')
    return redirect(f"{frontend_url}/dashboard.html#token={access_token}")

# --- NUEVAS RUTAS PARA GESTIONAR LAS SHEETS ---
@app.route('/api/sheets', methods=['GET'])
@token_required
def get_user_sheets():
    email = request.current_user_email
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT sheet_id, sheet_name, columns, last_used_at FROM user_sheets WHERE user_email = %s ORDER BY last_used_at DESC;", (email,))
    sheets = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([{'sheet_id': s[0], 'sheet_name': s[1], 'columns': json.loads(s[2])} for s in sheets])

@app.route('/api/sheets', methods=['POST'])
@token_required
def add_user_sheet():
    email = request.current_user_email
    sheet_id = request.json.get('sheet_id')
    if not sheet_id: return jsonify({'error': 'Falta el sheet_id'}), 400
    
    try:
        credentials = load_credentials_from_db(email)
        if not credentials: return jsonify({'error': 'No se pudieron cargar las credenciales'}), 500
        
        gc = gspread.authorize(credentials)
        spreadsheet = gc.open_by_key(sheet_id)
        worksheet = spreadsheet.sheet1
        headers = worksheet.row_values(1) # Leemos la primera fila
        sheet_name = spreadsheet.title
        
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO user_sheets (user_email, sheet_id, sheet_name, columns, last_used_at) VALUES (%s, %s, %s, %s, NOW()) ON CONFLICT (user_email, sheet_id) DO UPDATE SET sheet_name = EXCLUDED.sheet_name, columns = EXCLUDED.columns, last_used_at = NOW();",
            (email, sheet_id, sheet_name, json.dumps(headers))
        )
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({'sheet_id': sheet_id, 'sheet_name': sheet_name, 'columns': headers}), 201
    except gspread.exceptions.SpreadsheetNotFound:
        return jsonify({'error': 'Spreadsheet no encontrada'}), 404
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': 'Error interno al analizar la sheet'}), 500

# --- RUTA DE EXTRACCIÓN CON IA (Modificada) ---
@app.route('/api/extract', methods=['POST'])
@token_required
def extract_data_from_image():
    # (La lógica de esta ruta ahora es la que tenía antes process-image)
    if gemini_model is None: return jsonify({'error': 'IA no configurada'}), 500
    if 'image' not in request.files or 'columns' not in request.form: return jsonify({'error': 'Falta imagen o columnas'}), 400
    try:
        columns = json.loads(request.form['columns'])
        image_bytes = request.files['image'].read()
        image = Image.open(io.BytesIO(image_bytes))
        
        json_structure = json.dumps({col: "" for col in columns})
        prompt_text = f"Analiza la imagen y extrae la información para rellenar este JSON. Responde únicamente con el JSON rellenado, sin explicaciones ni formato de código.\n\nJSON a rellenar:\n{json_structure}"
        
        response = gemini_model.generate_content([prompt_text, image])
        extracted_json_text = response.text.strip().replace('```json', '').replace('```', '').strip()
        extracted_data = json.loads(extracted_json_text)
        
        return jsonify(extracted_data)
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': 'Error interno durante la extracción con IA'}), 500

# --- NUEVA RUTA PARA GUARDAR LOS DATOS FINALES ---
@app.route('/api/save', methods=['POST'])
@token_required
def save_data_to_sheet():
    email = request.current_user_email
    sheet_id = request.json.get('sheet_id')
    data_to_save = request.json.get('data') # Objeto JSON con los datos
    columns_order = request.json.get('columns') # Lista con el orden de las columnas

    if not all([sheet_id, data_to_save, columns_order]):
        return jsonify({'error': 'Faltan datos (sheet_id, data, columns)'}), 400
        
    try:
        credentials = load_credentials_from_db(email)
        if not credentials: return jsonify({'error': 'No se pudieron cargar credenciales'}), 500
        
        gc = gspread.authorize(credentials)
        spreadsheet = gc.open_by_key(sheet_id)
        worksheet = spreadsheet.sheet1
        
        # Ordenamos los datos según el orden de las columnas de la sheet
        row_to_append = [data_to_save.get(col, "") for col in columns_order]
        worksheet.append_row(row_to_append)
        
        # Actualizamos la marca de "último uso"
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE user_sheets SET last_used_at = NOW() WHERE user_email = %s AND sheet_id = %s;", (email, sheet_id))
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({'message': 'Datos guardados correctamente'}), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': 'Error interno al guardar en la sheet'}), 500

@app.route('/')
def index(): return "Backend del Lector IA funcionando."
if __name__ == '__main__': app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)