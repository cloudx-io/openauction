# Enclave measurements depend on these base image bytes.
# The digest is the pin; keep the 2023 tag beside it so refreshes stay on that major.
FROM amazonlinux:2023@sha256:bb1c85fe00170acd8a653de5f68cf77c7ec67234a130b18fad7ca1de1f61e3d3

ARG ENCLAVE_MAX_WORKERS=50
ENV ENCLAVE_MAX_WORKERS=${ENCLAVE_MAX_WORKERS}

RUN dnf update -y && \
    dnf install -y ca-certificates && \
    dnf clean all && \
    rm -rf /var/cache/dnf

# This Dockerfile assumes that you have already built a binary on the host
# machine using the GitHub Actions workflow, and we just copy it into the
# container. This makes builds faster and more cacheable than a multi-stage
# build-in-Docker approach.
COPY ./bin/tee-auction-enclave /usr/local/bin/tee-auction-enclave

RUN chmod +x /usr/local/bin/tee-auction-enclave

ENTRYPOINT ["/usr/local/bin/tee-auction-enclave"]

CMD []
