# Enclave measurements depend on these base image bytes.
# Tag and digest move together so the pin stays on amazonlinux:2023.
FROM amazonlinux:2023@sha256:694092ae18877ed4e3cb9b643759ba95df1f12af12528fefa18f60f79d4c1568

ARG ENCLAVE_MAX_WORKERS=50
ENV ENCLAVE_MAX_WORKERS=${ENCLAVE_MAX_WORKERS}

RUN dnf update -y && \
    dnf install -y ca-certificates nmap-ncat && \
    dnf clean all && \
    rm -rf /var/cache/dnf

# This Dockerfile assumes that you have already built a binary on the host
# machine using the GitHub Actions workflow, and we just copy it into the
# container. This makes builds faster and more cacheable than a multi-stage
# build-in-Docker approach.
COPY ./bin/tee-auction-enclave /usr/local/bin/tee-auction-enclave

RUN chmod +x /usr/local/bin/tee-auction-enclave

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD echo '{"type":"ping","message":"health_check"}' | nc 127.0.0.1 5000 || exit 1

ENTRYPOINT ["/usr/local/bin/tee-auction-enclave"]

CMD []
