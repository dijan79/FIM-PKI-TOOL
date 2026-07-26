# =============================================================================
# Dockerfile - FIM-PKI Sentinel
# Author: Dijan Ghale
#
# This image runs a Tkinter GUI application. Because Tkinter needs a
# graphical display, the container forwards its display to the HOST
# machine's X server (see README.md for full instructions).
# =============================================================================

FROM python:3.11-slim

LABEL maintainer="Dijan Ghale" \
      description="File Integrity Monitoring Tool with PKI, GUI & Docker Support"

# System dependencies: Tkinter GUI toolkit + libs required by matplotlib
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-tk \
    libgl1 \
    libglib2.0-0 \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Ensure runtime directories exist (also created at runtime by config.py)
RUN mkdir -p keys certs logs CSV_logs data

# Display variable - overridden by docker-compose / run command
ENV DISPLAY=:0

CMD ["python", "fim_gui.py"]
