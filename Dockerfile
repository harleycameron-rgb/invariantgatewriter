FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PUBLIC_HOST=0.0.0.0

WORKDIR /app

# Ed25519 support for gate-qualification/2. Wheels only: the slim image has no
# compiler, and binary-only installs never run package build scripts.
COPY requirements-ed25519.txt ./
RUN pip install --only-binary=:all: -r requirements-ed25519.txt \
 && python -c "from cryptography.hazmat.primitives.asymmetric import ed25519; ed25519.Ed25519PrivateKey.generate()"

COPY --chown=65532:65532 invariantgatewriter/ ./invariantgatewriter/
USER 65532:65532
EXPOSE 8080
CMD ["python", "-m", "invariantgatewriter.public_node"]
