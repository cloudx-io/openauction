# Enclave measurements depend on these base image bytes.
# The digest is the pin; keep the 2023 tag beside it so refreshes stay on that major.
FROM amazonlinux:2023@sha256:181f98c48832fe926f8ca3b6ffeafcce128e96e77b93d08fbe9a9bc9403ce284

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
