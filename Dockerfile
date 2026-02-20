FROM python:3.11-slim

WORKDIR /app

# Tkinter + X11 libraries needed for GUI apps
RUN apt-get update && apt-get install -y \
    python3-tk tk \
    libx11-6 libxext6 libxrender1 libxtst6 libxi6 \
    && rm -rf /var/lib/apt/lists/*

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

RUN chmod +x /app/entrypoint.sh

CMD ["/app/entrypoint.sh"]

