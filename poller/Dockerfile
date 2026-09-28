FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .
CMD ["python", "main.py"]
RUN apt-get update && apt-get install -y --no-install-recommends \
    snmp iperf3 fping iputils-ping netcat-openbsd \
 && rm -rf /var/lib/apt/lists/*
