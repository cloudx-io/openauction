#!/bin/bash
set -euo pipefail

# CI-optimized EIF build script for GitHub Actions
# This script builds an Enclave Image File (EIF) from a Docker container image
# on an AWS Nitro-compatible EC2 instance.
#
# Usage: build-eif-ci.sh <DOCKER_IMAGE_URI> <OUTPUT_EIF_PATH> [AWS_REGION]
#
# Arguments:
#   DOCKER_IMAGE_URI: Full URI of the Docker image in ECR
#   OUTPUT_EIF_PATH: Path where the EIF file should be written
#   AWS_REGION: (Optional) AWS region, defaults to us-east-1
#
# Environment Variables:
#   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN: AWS credentials
#
# Outputs:
#   - EIF file at OUTPUT_EIF_PATH
#   - PCR measurements JSON at OUTPUT_EIF_PATH.measurements.json
#   - PCR measurements to stdout for GitHub Actions

# Parse arguments
if [ $# -lt 2 ]; then
    echo "ERROR: Missing required arguments"
    echo "Usage: $0 <DOCKER_IMAGE_URI> <OUTPUT_EIF_PATH> [AWS_REGION]"
    exit 1
fi

IMAGE_URI="$1"
EIF_FILE="$2"
AWS_REGION="${3:-${AWS_REGION:-us-east-1}}"

# Create output directory if it doesn't exist
EIF_DIR=$(dirname "$EIF_FILE")
mkdir -p "$EIF_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" >&2
}

cleanup_on_failure() {
    log_error "EIF builder failed - cleaning up"
    docker system prune -f 2> /dev/null || true
    exit 1
}

validate_prerequisites() {
    log "Validating prerequisites..."
    
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI not found - required for ECR authentication"
        return 1
    fi
    log "✓ AWS CLI available: $(aws --version | head -n1)"

    if ! command -v docker &> /dev/null; then
        log_error "Docker not found - required for image operations"
        return 1
    fi
    log "✓ Docker available: $(docker --version)"

    if ! command -v nitro-cli &> /dev/null; then
        log_error "Nitro CLI not found - required for EIF building"
        return 1
    fi
    log "✓ Nitro CLI available: $(nitro-cli --version 2>&1 | head -n1 || echo 'version unknown')"

    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials not configured"
        log_error "Set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or attach IAM instance profile"
        return 1
    fi
    log "✓ AWS credentials configured"
}

# Set up error handling
trap cleanup_on_failure ERR

main() {
    log "========================================="
    log "CloudX Nitro Enclave EIF Builder (CI)"
    log "========================================="
    log "Docker Image: $IMAGE_URI"
    log "Output EIF: $EIF_FILE"
    log "AWS Region: $AWS_REGION"
    log "========================================="

    validate_prerequisites

    # Extract account ID from ECR URI
    local account_id
    account_id=$(echo "$IMAGE_URI" | cut -d'.' -f1)
    local ecr_endpoint="${account_id}.dkr.ecr.${AWS_REGION}.amazonaws.com"
    
    log "ECR Endpoint: $ecr_endpoint"

    # Authenticate to ECR
    log "Authenticating to ECR..."
    if ! aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$ecr_endpoint" 2>&1 | grep -i "login succeeded"; then
        log_error "Failed to authenticate to ECR"
        return 1
    fi
    log "✓ ECR authentication successful"

    # Pull the Docker image
    log "Pulling Docker image: $IMAGE_URI"
    if ! docker pull "$IMAGE_URI"; then
        log_error "Failed to pull Docker image: $IMAGE_URI"
        log_error "Verify the image exists and credentials are correct"
        return 1
    fi
    log "✓ Docker image pulled successfully"

    # Build EIF from Docker image
    log "Building EIF from Docker image..."
    
    local build_output="/tmp/nitro-build-output.json"
    if ! nitro-cli build-enclave \
        --docker-uri "$IMAGE_URI" \
        --output-file "$EIF_FILE" \
        > "$build_output" 2>&1; then
        log_error "Failed to build EIF from Docker image"
        if [ -f "$build_output" ]; then
            log_error "Build output:"
            cat "$build_output" >&2
        fi
        return 1
    fi

    # Verify EIF was created
    if [ ! -f "$EIF_FILE" ]; then
        log_error "EIF file not created: $EIF_FILE"
        return 1
    fi

    local eif_size
    eif_size=$(du -h "$EIF_FILE" | cut -f1)
    log "✓ EIF created successfully"
    log "  File: $EIF_FILE"
    log "  Size: $eif_size"

    # Extract and save PCR measurements
    log "Extracting PCR measurements..."
    
    local measurements_file="${EIF_FILE}.measurements.json"
    
    # nitro-cli outputs text format, extract PCR values and strip formatting
    local pcr0 pcr1 pcr2
    pcr0=$(grep -i "PCR0" "$build_output" | awk '{print $NF}' | tr -d ',"' || echo "unknown")
    pcr1=$(grep -i "PCR1" "$build_output" | awk '{print $NF}' | tr -d ',"' || echo "unknown")
    pcr2=$(grep -i "PCR2" "$build_output" | awk '{print $NF}' | tr -d ',"' || echo "unknown")

    # Create JSON file for GitHub Actions and downstream tools
    cat > "$measurements_file" <<EOF
{
  "Measurements": {
    "PCR0": "$pcr0",
    "PCR1": "$pcr1",
    "PCR2": "$pcr2"
  }
}
EOF

    log "PCR Measurements:"
    log "  PCR0: $pcr0"
    log "  PCR1: $pcr1"
    log "  PCR2: $pcr2"
    log "✓ PCR measurements saved to: $measurements_file"

    # Output for GitHub Actions
    echo "PCR0=$pcr0"
    echo "PCR1=$pcr1"
    echo "PCR2=$pcr2"

    # Cleanup Docker resources to free space
    log "Cleaning up Docker resources..."
    docker rmi "$IMAGE_URI" 2> /dev/null || true
    docker system prune -f 2> /dev/null || true
    log "✓ Cleanup complete"

    log "========================================="
    log "EIF Build Complete!"
    log "========================================="
    log "EIF File: $EIF_FILE"
    log "Size: $eif_size"
    log "Measurements: $measurements_file"
    log "========================================="

    return 0
}

# Run main function
main "$@"

