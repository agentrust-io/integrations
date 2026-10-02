# A pinned multi-architecture base, not a claim of bit-reproducible image output.
FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_NO_PROGRESS=1 \
    UV_NO_CACHE=1

COPY uv-bootstrap.txt /opt/uv-bootstrap.txt
RUN python -m pip install --disable-pip-version-check --no-cache-dir \
    --only-binary=:all: --require-hashes -r /opt/uv-bootstrap.txt

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-managed-python

RUN useradd --uid 10001 --user-group --create-home --shell /usr/sbin/nologin runner
COPY --chown=10001:10001 . .
USER 10001:10001

CMD ["./scripts/smoke.sh"]
