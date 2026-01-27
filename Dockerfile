ARG BUILDKIT_SBOM_SCAN_STAGE=true
# Cf. https://hub.docker.com/r/chainguard/python/
FROM chainguard/python:latest-dev@sha256:698abbe8777bcc5b370c6c198c48a7aa86bd418c7234bbdae1fe06235cd121b8 AS builder

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
FROM chainguard/python:latest@sha256:4171eedf8acce898abcb5c694a42469834cf90f4fa83beaefa180db7ed023cbf

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
