FROM python:3.11-slim
WORKDIR /app

# Copia o requirements da pasta "back" e instala
COPY back/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia todos os arquivos do "back" (main.py, etc)
COPY back/ .

# Copia a pasta "drivers" para dentro do contêiner
COPY drivers/ ./drivers/

# Inicia a API
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]