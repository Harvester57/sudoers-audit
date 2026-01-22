ARG BUILDKIT_SBOM_SCAN_STAGE=true
# Cf. https://hub.docker.com/r/chainguard/python/
FROM chainguard/python:latest-dev@sha256:42fdb3929d1c051cf648dec4d9d84518b12a67f08cb8e256cdca96d89fbb49b9 AS builder

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
FROM chainguard/python:latest@sha256:6252e33e2d954d5d4188e68c8268545baa5e05d47f62d9bec295e5cc063bd07f

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
