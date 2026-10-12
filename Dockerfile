# QuantumShield runtime: Python 3.15 (SSLContext.set_groups / SSLSocket.group)
# on Debian trixie, whose OpenSSL 3.5 (library and CLI) provides ML-KEM and ML-DSA.
ARG BASE_IMAGE=python:3.15-rc-slim-trixie
FROM ${BASE_IMAGE}
WORKDIR /opt/quantumshield
COPY pyproject.toml README.md ./
COPY quantumshield ./quantumshield
COPY tests ./tests
COPY demo ./demo
RUN pip install --no-cache-dir ".[test]" \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin qs
# Run as an unprivileged user; the demo's tool container overrides this to write files.
USER 10001
ENTRYPOINT ["quantumshield"]
CMD ["info"]
