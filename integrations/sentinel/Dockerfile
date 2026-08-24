FROM python:3.11-slim@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sentinel/ ./sentinel/
COPY sample_trace.json .

ENV PYTHONPATH=/app
EXPOSE 8001

CMD ["uvicorn", "sentinel.main:app", "--host", "0.0.0.0", "--port", "8001"]
