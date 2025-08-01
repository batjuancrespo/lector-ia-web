import os
import json
import psycopg2
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import Flask, request, redirect, url_for, jsonify, session
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
# --- NUEVAS LIBRERÍAS PARA GOOGLE DRIVE ---
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload

# --- INICIALIZACIÓN Y CONFIGURACIÓN (Sin cambios) ---
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
# --- ¡AÑADIMOS EL SCOPE DE DRIVE! ---
SCOPES = ['https://www.googleapis.com/auth/userinfo.email', 
        'https://www.googleapis.com/auth/userinfo.profile', 
        'https://www.googleapis.com/auth/spreadsheets', 
        'openid',
        'https://www.googleapis.com/auth/drive.file'] # Permiso para crear archivos en Drive
    
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

# --- NUEVA FUNCIÓN PARA SUBIR IMAGEN A GOOGLE DRIVE ---
def upload_image_to_drive(credentials, image_bytes, filename):
    try:
        service = build('drive', 'v3', credentials=credentials)
        
        # Crear un buffer en memoria para la imagen
        image_io = io.BytesIO(image_bytes)
        
        file_metadata = {'name': filename}
        media = MediaIoBaseUpload(image_io, mimetype='image/jpeg', resumable=True)
        
        print(f"Subiendo '{filename}' a Google Drive...")
        file = service.files().create(body=file_metadata, media_body=media, fields='id, webViewLink').execute()
        print("Subida completada.")
        
        # Hacemos el archivo público para que se pueda ver en la sheet
        file_id = file.get('id')
        service.permissions().create(fileId=file_id, body={'type': 'anyone', 'role': 'reader'}).execute()
        print("Permisos del archivo actualizados a público.")
        
        return file.get('webViewLink')
    except Exception as e:
        print(f"Error al subir a Google Drive: {e}")
        traceback.print_exc()
        return None

# (Rutas de login/callback sin cambios)
@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=url_for('callback', _external=True))
    authorization_url, state = flow.authorization_url(access_type='offline', prompt='consent')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    state = session.pop('state', None)
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES, state=state, redirect_uri=url_for('callback', _external=True))
    # ... (el resto de la función es igual)
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

# (Rutas de gestión de sheets sin cambios)
@app.route('/api/sheets', methods=['GET'])
@token_required
def get_user_sheets():
    # ... (código igual)
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
    # ... (código igual)
    email = request.current_user_email
    sheet_id = request.json.get('sheet_id')
    if not sheet_id: return jsonify({'error': 'Falta el sheet_id'}), 400
    try:
        credentials = load_credentials_from_db(email)
        if not credentials: return jsonify({'error': 'No se pudieron cargar las credenciales'}), 500
        gc = gspread.authorize(credentials)
        spreadsheet = gc.open_by_key(sheet_id)
        worksheet = spreadsheet.sheet1
        headers = worksheet.row_values(1)
        sheet_name = spreadsheet.title
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO user_sheets (user_email, sheet_id, sheet_name, columns, last_used_at) VALUES (%s, %s, %s, %s, NOW()) ON CONFLICT (user_email, sheet_id) DO UPDATE SET sheet_name = EXCLUDED.sheet_name, columns = EXCLUDED.columns, last_used_at = NOW();", (email, sheet_id, sheet_name, json.dumps(headers)))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'sheet_id': sheet_id, 'sheet_name': sheet_name, 'columns': headers}), 201
    except gspread.exceptions.SpreadsheetNotFound:
        return jsonify({'error': 'Spreadsheet no encontrada'}), 404
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': 'Error interno al analizar la sheet'}), 500
        
# --- RUTA DE EXTRACCIÓN CON IA MEJORADA PARA RADIOLOGÍA ---
@app.route('/api/extract', methods=['POST'])
@token_required
def extract_data_from_image():
    if gemini_model is None: return jsonify({'error': 'IA no configurada'}), 500
    if 'image' not in request.files: return jsonify({'error': 'Falta imagen'}), 400
    
    try:
        image_bytes = request.files['image'].read()
        image = Image.open(io.BytesIO(image_bytes))
        
        json_structure = {
            "NOMBRE": "",
            "APELLIDOS": "",
            "ID": "",
            "FECHA ESTUDIO": "",
            "SECCION": "",
            "TIPO DE ESTUDIO": ""
        }
        
        prompt_text = f"""
        Eres un asistente experto en analizar imágenes radiológicas para extraer metadatos.
        Analiza la imagen adjunta, que es un estudio radiológico. Extrae la información para rellenar el siguiente objeto JSON.
        - Para 'FECHA ESTUDIO', formatea la fecha como DD/MM/AAAA.
        - Para 'SECCION', clasifica la imagen en una de estas categorías: Craneo, Cuello, Torax, Abdomen, Musculoesqueletico.
        - Para 'TIPO DE ESTUDIO', clasifica el estudio en una de estas categorías: TAC, RM, ECO, OTROS.
        Responde ÚNICAMENTE con el objeto JSON rellenado. No incluyas explicaciones ni formato de código.

        JSON a rellenar:
        {json.dumps(json_structure)}
        """
        
        response = gemini_model.generate_content([prompt_text, image])
        extracted_json_text = response.text.strip().replace('```json', '').replace('```', '').strip()
        extracted_data = json.loads(extracted_json_text)
        
        return jsonify(extracted_data)
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': 'Error interno durante la extracción con IA'}), 500

# --- RUTA DE GUARDADO MEJORADA PARA SUBIR LA IMAGEN ---
@app.route('/api/save', methods=['POST'])
@token_required
def save_data_to_sheet():
    email = request.current_user_email
    
    # Ahora recibimos los datos y la imagen en una petición 'multipart/form-data'
    if 'data' not in request.form or 'sheet_id' not in request.form or 'image' not in request.files:
        return jsonify({'error': 'Faltan datos (data, sheet_id, image)'}), 400
        
    try:
        sheet_id = request.form['sheet_id']
        data_to_save = json.loads(request.form['data'])
        image_file = request.files['image']
        
        credentials = load_credentials_from_db(email)
        if not credentials: return jsonify({'error': 'No se pudieron cargar credenciales'}), 500
        
        # 1. Subir imagen a Google Drive
        image_bytes = image_file.read()
        # Creamos un nombre de archivo único
        filename = f"estudio_{data_to_save.get('ID', 'sin_id')}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.jpg"
        image_link = upload_image_to_drive(credentials, image_bytes, filename)
        
        if not image_link:
            return jsonify({'error': 'No se pudo subir la imagen a Google Drive'}), 500
            
        # 2. Preparar la fila para Google Sheets
        data_to_save['FOTO'] = f'=IMAGE("{image_link}")'
        
        # Asumimos un orden fijo de columnas
        columns_order = ['NOMBRE', 'APELLIDOS', 'ID', 'FECHA ESTUDIO', 'SECCION', 'TIPO DE PATOLOGIA', 'TIPO DE ESTUDIO', 'FOTO']
        row_to_append = [data_to_save.get(col, "") for col in columns_order]
        
        # 3. Guardar en la Sheet
        gc = gspread.authorize(credentials)
        spreadsheet = gc.open_by_key(sheet_id)
        worksheet = spreadsheet.sheet1
        worksheet.append_row(row_to_append)
        
        # 4. Actualizar 'last_used'
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE user_sheets SET last_used_at = NOW() WHERE user_email = %s AND sheet_id = %s;", (email, sheet_id))
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({'message': 'Datos e imagen guardados correctamente'}), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': 'Error interno al guardar en la sheet'}), 500
    
@app.route('/')
def index(): return "Backend del Lector IA funcionando."
if __name__ == '__main__': app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)