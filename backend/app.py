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

# --- NUEVA LIBRERÍA PARA GEMINI ---
import google.generativeai as genai

# --- INICIALIZACIÓN Y CONFIGURACIÓN ---
load_dotenv()
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
CORS(app, supports_credentials=True, origins=["https://batjuancrespo.github.io"])

# --- CONFIGURACIÓN DE LA API DE GEMINI ---
try:
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
    if not GEMINI_API_KEY:
        raise ValueError("La variable de entorno GEMINI_API_KEY no está configurada.")
    genai.configure(api_key=GEMINI_API_KEY)
    # Seleccionamos el modelo multimodal (que puede ver imágenes)
    gemini_model = genai.GenerativeModel('gemini-1.5-flash') 
    print("SDK de Gemini configurado correctamente.")
except Exception as e:
    print(f"ERROR CRÍTICO al configurar Gemini: {e}")
    gemini_model = None

# (El resto de la configuración inicial no cambia)
cipher_suite = Fernet(os.environ.get("ENCRYPTION_KEY").encode())
CLIENT_SECRETS_FILE = 'client_secret.json'
SCOPES = ['https://www.googleapis.com/auth/userinfo.email', 
        'https://www.googleapis.com/auth/userinfo.profile', 
        'https://www.googleapis.com/auth/spreadsheets', 
        'openid']

try:
    with open(CLIENT_SECRETS_FILE) as f:
        client_config = json.load(f)
        GOOGLE_CLIENT_ID = client_config.get('web', {}).get('client_id')
    if not GOOGLE_CLIENT_ID:
        raise ValueError("Client ID no encontrado")
except Exception as e:
    print(f"ERROR CRÍTICO al cargar el Client ID: {e}")
    GOOGLE_CLIENT_ID = None

# (Toda la lógica de tokens y base de datos no cambia)
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
            try: token = request.headers['Authorization'].split(" ")[1]
            except IndexError: return jsonify({'message': 'Formato de token incorrecto'}), 401
        if not token: return jsonify({'message': 'Falta el token de autorización'}), 401
        try:
            data = jwt.decode(token, app.secret_key, algorithms=["HS256"])
            request.current_user_email = data['email']
        except jwt.ExpiredSignatureError: return jsonify({'message': 'El token ha expirado'}), 401
        except: return jsonify({'message': 'El token no es válido'}), 401
        return f(*args, **kwargs)
    return decorated

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

# (Las rutas de autenticación no cambian)
@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES,
        redirect_uri=url_for('callback', _external=True))
    authorization_url, state = flow.authorization_url(access_type='offline', prompt='consent')
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    if not GOOGLE_CLIENT_ID: return "Error del servidor: Client ID no configurado.", 500
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES,
        redirect_uri=url_for('callback', _external=True))
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    try:
        profile_info = id_token.verify_oauth2_token(
            credentials.id_token, 
            google.auth.transport.requests.Request(), 
            GOOGLE_CLIENT_ID
        )
    except ValueError as e: return "Token de Google inválido", 401
    user_email = profile_info.get("email")
    save_user_credentials(user_email, credentials)
    access_token = create_access_token(data={"email": user_email})
    frontend_url = os.environ.get("FRONTEND_URL").rstrip('/')
    return redirect(f"{frontend_url}/dashboard.html#token={access_token}")

@app.route('/api/profile')
@token_required
def profile():
    return jsonify({'logged_in': True, 'email': request.current_user_email})

# --- RUTA DE PROCESAMIENTO DE IMAGEN COMPLETAMENTE REESCRITA ---
@app.route('/api/process-image', methods=['POST'])
@token_required
def process_image():
    if gemini_model is None:
        return jsonify({'error': 'El servicio de IA no está configurado correctamente.'}), 500
        
    if 'image' not in request.files or 'sheetColumns' not in request.form:
        return jsonify({'error': 'Falta imagen o las columnas de la hoja de cálculo'}), 400

    try:
        email = request.current_user_email
        # Las columnas ahora vienen como un string JSON desde el frontend
        sheet_columns_json = request.form['sheetColumns'] 
        sheet_columns = json.loads(sheet_columns_json)
        
        file_storage = request.files['image']
        image_bytes = file_storage.read()
        image = Image.open(io.BytesIO(image_bytes))
        
        # Construimos el prompt para Gemini
        # 1. Creamos el objeto JSON que queremos que rellene
        json_structure_to_fill = json.dumps({col: "" for col in sheet_columns})

        # 2. El texto del prompt que le da las instrucciones
        prompt_text = f"""
        Eres un asistente experto en extracción de datos de documentos.
        Analiza la imagen adjunta y extrae la información necesaria para rellenar el siguiente objeto JSON.
        Interpreta los datos de la imagen para que coincidan con el significado de cada campo.
        Si no encuentras un valor para un campo, déjalo como un string vacío.
        Tu respuesta DEBE ser únicamente el objeto JSON rellenado, sin ningún texto adicional, explicación o comillas de bloque de código.

        JSON a rellenar:
        {json_structure_to_fill}
        """
        
        # 3. Hacemos la llamada a la API de Gemini
        print("Enviando petición a Gemini...")
        response = gemini_model.generate_content([prompt_text, image])
        print("Respuesta recibida de Gemini.")

        # 4. Limpiamos y parseamos la respuesta
        # Gemini puede devolver el JSON dentro de un bloque de código markdown (```json ... ```)
        extracted_json_text = response.text.strip().replace('```json', '').replace('```', '').strip()
        
        try:
            # Intentamos convertir el texto a un objeto JSON real
            extracted_data = json.loads(extracted_json_text)
        except json.JSONDecodeError:
            print(f"ERROR: Gemini no devolvió un JSON válido. Respuesta recibida:\n{response.text}")
            return jsonify({'error': 'La IA no devolvió una respuesta con el formato esperado.'}), 500

        # ¡Éxito! Devolvemos los datos extraídos al frontend para la verificación del usuario
        return jsonify(extracted_data)

    except Exception as e:
        print(f"LOG ERROR CRÍTICO en /api/process-image: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Ocurrió un error interno muy grave al procesar la imagen.'}), 500

# (La ruta de guardado final y la ruta principal no cambian)
@app.route('/')
def index():
    return "Backend del Lector IA funcionando."

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)