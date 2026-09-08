FROM python:3.11-slim@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7

WORKDIR /app

# requirements.txt states the constraints; requirements.lock.txt is the
# resolved, hash-pinned form and is what actually gets installed, so a rebuild
# of this image fetches the same bytes it did the first time. Recompile with:
#   uv pip compile integrations/sentinel/requirements.txt
#     --generate-hashes --universal --python-version 3.11
#     -o integrations/sentinel/requirements.lock.txt
COPY requirements.txt requirements.lock.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock.txt

COPY sentinel/ ./sentinel/
COPY sample_trace.json .

ENV PYTHONPATH=/app
EXPOSE 8001

CMD ["uvicorn", "sentinel.main:app", "--host", "0.0.0.0", "--port", "8001"]
