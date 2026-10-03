# RAKSHA AI — the sealed-deployment image. Built once on a networked machine, carried to the
# air-gapped node on removable media, and run with the cable pulled. No RUN step fetches anything
# at runtime; all dependencies are baked in or mounted from the bundle.
FROM python:3.11-slim

# Toolchains the language adapters need. Pinned, installed at build time only.
RUN apt-get update && apt-get install -y --no-install-recommends \
        openjdk-17-jdk-headless maven git curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/raksha
COPY raksha/ ./raksha/
COPY schemas/ ./schemas/
COPY pyproject.toml ./
# Runtime has no third-party Python deps by design; dev extras are not installed in the image.
RUN pip install --no-cache-dir -e . || true

# The offline model server (vLLM) and the dependency mirrors are separate services in the
# compose file; this image is the orchestrator only.
ENV RAKSHA_SEALED=1
ENTRYPOINT ["python", "-m", "raksha.orchestrator"]
