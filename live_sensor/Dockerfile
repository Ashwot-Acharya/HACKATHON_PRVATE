FROM python:3.12-slim

# Install system dependencies required for packet sniffing (libpcap)
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the sensor script
COPY sensor.py .

# Command to run the sensor (requires --net=host and --cap-add=NET_RAW / --cap-add=NET_ADMIN in docker run)
ENTRYPOINT ["python", "sensor.py"]
