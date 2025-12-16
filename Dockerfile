# Imagen mínima y segura
FROM python:3.12-slim

# Evitar cache, paquetes no requeridos
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Crear usuario no root
RUN useradd -m appuser

WORKDIR /app

# Instalar dependencias sin cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar solo el código
COPY --chown=appuser:appuser . .

# Crear directorio cache con permisos seguros
RUN mkdir -p .cache/payloads && \
    chown -R appuser:appuser .cache

# Cambio a usuario sin privilegios
USER appuser

# Sistema de archivos solo lectura, salvo /app/.cache
VOLUME ["/app/.cache"]

CMD ["python", "main.py"]
