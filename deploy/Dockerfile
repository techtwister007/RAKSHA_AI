# RAKSHA AI — the sealed-deployment image. Built once on a networked machine, carried to the
# air-gapped node on removable media, and run with the cable pulled. No RUN step fetches anything
# at runtime; all dependencies are baked in or mounted from the bundle.
#
# Pin the base image and package versions when the bundle is built (record the digests in the
# bundle manifest); the build machine is the only one that ever sees a package mirror.
FROM python:3.11-slim

# Toolchains the language adapters need: JDK + Maven (Java lane), gcc (C lane, ASan), git (patch
# apply / rollback). No curl or wget: a no-egress image carries no download tools.
RUN apt-get update && apt-get install -y --no-install-recommends \
        openjdk-17-jdk-headless maven git gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/raksha
COPY pyproject.toml ./
COPY raksha/ ./raksha/
COPY console/ ./console/
COPY schemas/ ./schemas/
COPY demo-targets/ ./demo-targets/
# Runtime has no third-party Python deps by design. A failed install fails the build — never hidden.
RUN pip install --no-cache-dir .

# The offline model server (vLLM) is a separate service in the compose file. Targets are mounted
# read-only at /targets; the jury submission and evidence bundles are written to /out.
ENV RAKSHA_SEALED=1 \
    RAKSHA_TARGETS=/targets \
    RAKSHA_OUT=/out \
    RAKSHA_CONSOLE_HOST=0.0.0.0 \
    PYTHONPATH=/opt/raksha
EXPOSE 8080
ENTRYPOINT ["python", "-m", "raksha.orchestrator"]
