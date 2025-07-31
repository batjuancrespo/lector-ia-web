# --- Fase 1: Entorno de Construcción ---
FROM python:3.10.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    tesseract-ocr-spa \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# --- Fase 2: Ejecución ---
# El comando que Render usará para iniciar la aplicación
# Aumentamos el timeout a 120 segundos para dar tiempo a que el modelo de IA cargue en frío
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:10000", "--timeout", "120"]