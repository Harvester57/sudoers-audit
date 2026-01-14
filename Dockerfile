ARG BUILDKIT_SBOM_SCAN_STAGE=true
# Cf. https://hub.docker.com/r/chainguard/python/
FROM chainguard/python:latest-dev@sha256:22f5e61aee4674dbab203655a7a4530f4f7a9e08b81ec781e68a8c3230ae07f7 AS builder

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
FROM chainguard/python:latest@sha256:c61c2d11da44d85e79d8957bd1d21ba4b0313e96801b460bb3f44d256e5beb58

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
