# Aegis Foundry - autonomous detection engineering for Splunk.
#
# Default container run is the fully offline, deterministic mock demo
# (zero credentials needed):
#     docker build -t aegis-foundry . && docker run --rm aegis-foundry
#
# Live mode (see docker-compose.yml, profile "live"):
#     docker run --rm -e AEGIS_MODE=live -e SPLUNK_REST_URL=... aegis-foundry run --mode live

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY . /app

# Editable install keeps the package importable from /app so the bundled
# demo/fixtures directory resolves relative to the source tree at runtime.
RUN pip install -e .

ENTRYPOINT ["aegis-foundry"]
CMD ["run", "--mode", "mock", "--auto-approve"]
