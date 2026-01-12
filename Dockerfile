ARG BUILDKIT_SBOM_SCAN_STAGE=true
# Cf. https://hub.docker.com/r/chainguard/python/
FROM chainguard/python:latest-dev@sha256:e74973526261c4ad07fb144bc1636f1b4b2d19f2c74d311a2040cb520276ca08 AS builder

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
FROM chainguard/python:latest@sha256:95d87904ddeb9ad7eb4c534f93640504dae1600f2d68dca9ba62c2f2576952bf

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
