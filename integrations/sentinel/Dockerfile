FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY sample_trace.json .

ENV PYTHONPATH=/app
EXPOSE 8001

CMD ["uvicorn", "src.server:app", "--host", "0.0.0.0", "--port", "8001"]