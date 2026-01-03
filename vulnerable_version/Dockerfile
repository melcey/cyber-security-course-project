FROM python:3.9-slim

WORKDIR /app


COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
ENV SQLITE_PATH=/vulnerable_version/scada.db
ENV PORT_NUM=5001
COPY . .

EXPOSE 5001

CMD ["python", "app.py"]