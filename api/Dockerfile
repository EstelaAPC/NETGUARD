FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    snmp \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY ollama_client.py .
COPY alert_service.py .
COPY telegram_ai_bot.py .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
