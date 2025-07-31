# --- Fase 1: Entorno de Construcción ---
# Usamos una imagen oficial de Python 3.10 como base
FROM python:3.10.11-slim

# Establecemos el directorio de trabajo dentro del contenedor
WORKDIR /app

# Actualizamos los paquetes del sistema operativo e instalamos Tesseract y el idioma español
# El `-y` responde "sí" a todas las preguntas
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    tesseract-ocr-spa \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Copiamos primero el archivo de requerimientos para aprovechar el caché de Docker
COPY requirements.txt .

# Instalamos las dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiamos el resto del código de la aplicación
COPY . .

# --- Fase 2: Ejecución ---
# El comando que Render usará para iniciar la aplicación
# Expone el puerto 10000, que es el que Render espera por defecto para Docker
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:10000"]