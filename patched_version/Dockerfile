FROM python:3.9-slim

WORKDIR /app


COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
ENV SQLITE_PATH=/patched_version/scada.db
ENV PORT_NUM=5002

COPY . .

EXPOSE 5002

CMD ["python", "app.py"]