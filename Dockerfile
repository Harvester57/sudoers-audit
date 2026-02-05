ARG BUILDKIT_SBOM_SCAN_STAGE=true
# Cf. https://hub.docker.com/r/chainguard/python/
FROM chainguard/python:latest-dev@sha256:ef5d416c769204462bf6a8af9b4ea327a870fdced32c5372ac43c4ef29dc614c AS builder

ENV LANG=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ="Europe/Paris"

USER root

WORKDIR /app

RUN python -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install .

# Cf. https://hub.docker.com/r/chainguard/python/
FROM chainguard/python:latest@sha256:679d04611404a759ea36a05d4d09ca35e632fdc6dd47d0b6566706825540b106

LABEL maintainer="florian.stosse@gmail.com"
LABEL lastupdate="2026-01-07"
LABEL author="Florian Stosse"
LABEL description="sudoers-audit, built using Python Chainguard base image"
LABEL license="MIT license"

ENV LANG=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ="Europe/Paris"

WORKDIR /app

COPY --from=builder /app/venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

ENTRYPOINT ["sudoers-audit"]
