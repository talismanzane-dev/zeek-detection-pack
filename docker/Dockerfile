# syntax=docker/dockerfile:1
#
# zeek-detection-pack analyzer image.
#   build:  docker build -f docker/Dockerfile -t zeek-detection-pack .
#   run:    docker run --rm -v "$PWD/logs:/lab/logs:ro" zeek-detection-pack run --logs /lab/logs
#
# Dependencies are installed from uv.lock (exact, hash-pinned versions).
# Behind a TLS-intercepting proxy, supply its CA bundle as a build secret:
#   docker build --secret id=extra_ca,src=/path/to/ca-bundle.pem -f docker/Dockerfile .

ARG PYTHON_IMAGE=python:3.12-slim

FROM ghcr.io/astral-sh/uv:0.11.32 AS uv

FROM ${PYTHON_IMAGE} AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src
# Third-party dependencies first, for layer caching.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -s /run/secrets/extra_ca ]; then export SSL_CERT_FILE=/run/secrets/extra_ca; fi; \
    uv sync --frozen --no-dev --no-install-project
# Then the project itself (non-editable, with the default config bundled).
COPY zdp ./zdp
COPY config ./config
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -s /run/secrets/extra_ca ]; then export SSL_CERT_FILE=/run/secrets/extra_ca; fi; \
    uv sync --frozen --no-dev --no-editable

FROM ${PYTHON_IMAGE}
LABEL org.opencontainers.image.title="zeek-detection-pack" \
      org.opencontainers.image.description="Batch detection analytics over Zeek logs" \
      org.opencontainers.image.source="https://github.com/talismanzane-dev/zeek-detection-pack" \
      org.opencontainers.image.licenses="MIT"
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin zdp
COPY --from=build /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
# Labeled fixtures + gate definitions so the image can run the harness.
COPY fixtures ./fixtures
COPY quality_gates.yaml ./
COPY tools/check_gates.py ./tools/check_gates.py
USER zdp
HEALTHCHECK --interval=60s --timeout=30s --start-period=10s --retries=3 CMD ["zdp", "selftest"]
ENTRYPOINT ["zdp"]
CMD ["--help"]
