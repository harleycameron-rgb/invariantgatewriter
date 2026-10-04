FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PUBLIC_HOST=0.0.0.0

WORKDIR /app
COPY --chown=65532:65532 invariantgatewriter/ ./invariantgatewriter/
USER 65532:65532
EXPOSE 8080
CMD ["python", "-m", "invariantgatewriter.public_node"]
