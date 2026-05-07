FROM python:3.11-slim

LABEL description="File Carving Suite for DFIR"

WORKDIR /app

# Install system dependencies for Pillow and EWFs
RUN apt-get update && apt-get install -y --no-install-recommends \
    libewf-dev \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir .[full]

COPY . .

ENTRYPOINT ["python3", "carver.py"]
