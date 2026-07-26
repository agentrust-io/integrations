FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sentinel/ ./sentinel/
COPY sample_trace.json .

ENV PYTHONPATH=/app
EXPOSE 8001

CMD ["uvicorn", "sentinel.main:app", "--host", "0.0.0.0", "--port", "8001"]
