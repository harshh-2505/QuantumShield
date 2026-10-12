# QuantumShield runtime: Python 3.15 (SSLContext.set_groups / SSLSocket.group)
# on Debian trixie, whose OpenSSL 3.5 (library and CLI) provides ML-KEM and ML-DSA.
ARG BASE_IMAGE=python:3.15-rc-slim-trixie
FROM ${BASE_IMAGE}
WORKDIR /opt/quantumshield
COPY pyproject.toml README.md ./
COPY quantumshield ./quantumshield
COPY tests ./tests
COPY demo ./demo
RUN pip install --no-cache-dir ".[test]"
ENTRYPOINT ["quantumshield"]
CMD ["info"]
