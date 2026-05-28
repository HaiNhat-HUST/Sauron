FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src

EXPOSE 8000

# FastAPI app via uvicorn (Linux: default loop is fine for psycopg async).
CMD ["python", "-m", "src.web"]
