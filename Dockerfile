FROM mcr.microsoft.com/playwright/python:v1.41.0-jammy

WORKDIR /app

# FFmpegインストール
RUN apt-get update && apt-get install -y ffmpeg && rm -rf /var/lib/apt/lists/*

# 依存関係インストール
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# アプリをコピー
COPY . .

# ポートはRailwayの$PORTを使用
ENV PORT=8080
EXPOSE 8080

COPY start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"]
