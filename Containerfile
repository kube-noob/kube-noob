# kube-noob container image (OpenShift restricted-v2 compatible: non-root, arbitrary UID, group 0 writable dirs).
# Build:  docker build -f Containerfile -t kube-noob:dev .
# CI resolves BASE_IMAGE to an immutable digest at build time and records it in the SLSA provenance.
ARG BASE_IMAGE=registry.access.redhat.com/ubi9/python-312:latest

FROM ${BASE_IMAGE} AS build
USER 0
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE requirements.lock ./
COPY src ./src
COPY examples ./examples
RUN python3 -m pip install --no-cache-dir --upgrade "pip>=24.3" "build>=1.2" \
 && python3 -m build --wheel --outdir /wheels . \
 && python3 -m venv /opt/kube-noob \
 && /opt/kube-noob/bin/pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements.lock \
 && /opt/kube-noob/bin/pip install --no-cache-dir --no-deps /wheels/*.whl \
 && /opt/kube-noob/bin/kube-noob --version

FROM ${BASE_IMAGE}
ARG VERSION=0.9.2
# Red Hat container certification (preflight HasRequiredLabel) needs name, vendor, version, release, summary,
# description and maintainer; the MCP Registry verifies ownership of OCI images through io.modelcontextprotocol.*.
LABEL name="kube-noob" \
      vendor="kube-noob project" \
      version="${VERSION}" \
      release="1" \
      summary="Offline-first Kubernetes/OpenShift/ROSA learning, audit and debugging MCP server" \
      description="kube-noob audits, generates and debugs Kubernetes, OpenShift, ROSA HCP, Helm and RHACS configuration with a deterministic engine and local knowledge; web and cluster access are opt-in and read-only." \
      maintainer="kube-noob maintainers (https://github.com/aashishmahajan/kube-noob)" \
      io.modelcontextprotocol.server.name="io.github.kube-noob/kube-noob" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.title="kube-noob" \
      org.opencontainers.image.description="Offline-first Kubernetes/OpenShift/ROSA/Helm/RHACS learning, audit and debugging MCP server" \
      org.opencontainers.image.source="https://github.com/aashishmahajan/kube-noob" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.k8s.display-name="kube-noob" \
      io.openshift.tags="kubernetes,openshift,mcp,security"
USER 0
COPY --from=build /opt/kube-noob /opt/kube-noob
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /licenses/
RUN mkdir -p /var/lib/kube-noob /etc/kube-noob \
 && chgrp -R 0 /var/lib/kube-noob /etc/kube-noob \
 && chmod -R g=u /var/lib/kube-noob /etc/kube-noob
# webEnabled / cluster.enabled are deliberately not baked in as env vars: env overrides the config file, so an image
# default would silently ignore `webEnabled: true` in a mounted config. Both default to false in code.
ENV PATH="/opt/kube-noob/bin:${PATH}" \
    KUBE_NOOB_DATA_DIR=/var/lib/kube-noob \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp
# Numeric non-root user; OpenShift replaces it with a namespace-range UID in group 0, which still works.
USER 1001
WORKDIR /var/lib/kube-noob
EXPOSE 8080
ENTRYPOINT ["kube-noob"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
