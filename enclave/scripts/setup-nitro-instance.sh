#!/bin/bash
set -euo pipefail

# Setup script for AWS Nitro-compatible EC2 instances
# Prepares an instance for building Enclave Image Files (EIFs)
#
# Usage: setup-nitro-instance.sh
#
# Requirements:
#   - Amazon Linux 2023 or compatible OS
#   - Nitro-compatible EC2 instance type (c5, m5, r5, etc.)
#   - Root or sudo access
#
# This script installs:
#   - AWS Nitro Enclaves CLI
#   - Docker (if not already installed)
#   - jq for JSON processing
#   - Configures Nitro Enclaves allocator

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" >&2
}

check_os() {
    log "Checking operating system..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        log "Detected OS: $NAME $VERSION"
        
        # Check if Amazon Linux 2023
        if [[ "$ID" == "amzn" && "$VERSION_ID" == "2023" ]]; then
            log "✓ Amazon Linux 2023 detected"
            return 0
        elif [[ "$ID" == "amzn" ]]; then
            log "Amazon Linux detected (version: $VERSION_ID)"
            return 0
        else
            log "Warning: This script is optimized for Amazon Linux 2023"
            log "Detected: $NAME $VERSION"
            log "Continuing anyway..."
            return 0
        fi
    else
        log_error "Cannot determine OS version"
        return 1
    fi
}

install_nitro_cli() {
    log "Installing AWS Nitro Enclaves CLI..."
    
    if command -v nitro-cli &> /dev/null; then
        log "Nitro CLI already installed: $(nitro-cli --version 2>&1 | head -n1 || echo 'version unknown')"
        return 0
    fi
    
    # Install from Amazon Linux repository
    if command -v dnf &> /dev/null; then
        sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
    elif command -v yum &> /dev/null; then
        sudo yum install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
    else
        log_error "Package manager not found (dnf or yum required)"
        return 1
    fi
    
    if command -v nitro-cli &> /dev/null; then
        log "✓ Nitro CLI installed: $(nitro-cli --version 2>&1 | head -n1 || echo 'installed')"
    else
        log_error "Nitro CLI installation failed"
        return 1
    fi
}

install_docker() {
    log "Checking Docker installation..."
    
    if command -v docker &> /dev/null; then
        log "Docker already installed: $(docker --version)"
        # Docker is installed but might not be running - ensure it's started
        if ! sudo systemctl is-active --quiet docker; then
            log "Starting Docker service..."
            sudo systemctl start docker
            sudo systemctl enable docker

            # Wait for Docker daemon
            for i in {1..10}; do
                if sudo docker info &> /dev/null; then
                    log "✓ Docker daemon started"
                    break
                fi
                log "Waiting for Docker daemon... (attempt $i/10)"
                sleep 2
            done
        else
            log "✓ Docker service already running"
        fi
        return 0
    fi
    
    log "Installing Docker..."
    
    if command -v dnf &> /dev/null; then
        sudo dnf install -y docker
    elif command -v yum &> /dev/null; then
        sudo yum install -y docker
    else
        log_error "Package manager not found (dnf or yum required)"
        return 1
    fi
    
    # Start Docker service
    log "Starting Docker service..."
    sudo systemctl start docker
    sudo systemctl enable docker

    # Wait for Docker socket to be available
    for i in {1..10}; do
        if sudo docker info &> /dev/null; then
            log "Docker daemon is running"
            break
        fi
        log "Waiting for Docker daemon... (attempt $i/10)"
        sleep 2
    done

    # Add current user to docker group (if not root)
    if [ "$EUID" -ne 0 ]; then
        sudo usermod -aG docker "$USER" || true
        log "Note: You may need to log out and back in for docker group changes to take effect"
    fi
    
    log "✓ Docker installed: $(sudo docker --version)"
}

install_dependencies() {
    log "Installing additional dependencies..."
    
    local packages=("jq" "curl" "awscli")
    
    for pkg in "${packages[@]}"; do
        if ! command -v "$pkg" &> /dev/null; then
            log "Installing $pkg..."
            if command -v dnf &> /dev/null; then
                sudo dnf install -y "$pkg"
            elif command -v yum &> /dev/null; then
                sudo yum install -y "$pkg"
            fi
        else
            log "✓ $pkg already installed"
        fi
    done
}

configure_nitro_allocator() {
    log "Configuring Nitro Enclaves allocator..."
    
    # Create allocator config directory
    sudo mkdir -p /etc/nitro_enclaves
    
    # Create allocator configuration
    # Allocate memory and CPUs for enclave building
    # These are conservative values suitable for c5.xlarge and similar instances
    cat << 'EOF' | sudo tee /etc/nitro_enclaves/allocator.yaml > /dev/null
---
# Enclave memory in MiB (6GB for EIF building)
memory_mib: 6144

# Number of vCPUs to allocate (2 CPUs for building)
cpu_count: 2

# CPU pool configuration
# 0 = dedicated for enclave
cpu_pool: 0
EOF
    
    log "✓ Allocator configuration created"
    
    # Enable and start allocator service
    if systemctl list-unit-files | grep -q nitro-enclaves-allocator; then
        log "Enabling nitro-enclaves-allocator service..."
        sudo systemctl enable nitro-enclaves-allocator.service
        sudo systemctl start nitro-enclaves-allocator.service
        
        # Wait a moment for service to stabilize
        sleep 2
        
        if systemctl is-active --quiet nitro-enclaves-allocator; then
            log "✓ Nitro Enclaves allocator service running"
        else
            log "Warning: Allocator service not running (may need Nitro-compatible instance)"
            log "This is normal on non-Nitro instances or in virtualized environments"
        fi
    else
        log "Warning: nitro-enclaves-allocator service not found"
        log "This is normal on non-Nitro instances"
    fi
}

verify_setup() {
    log "Verifying setup..."
    
    local all_good=true
    
    # Check nitro-cli
    if command -v nitro-cli &> /dev/null; then
        log "✓ nitro-cli: $(nitro-cli --version 2>&1 | head -n1 || echo 'installed')"
    else
        log_error "✗ nitro-cli not found"
        all_good=false
    fi
    
    # Check Docker
    if command -v docker &> /dev/null; then
        log "✓ docker: $(docker --version)"
    else
        log_error "✗ docker not found"
        all_good=false
    fi
    
    # Check jq
    if command -v jq &> /dev/null; then
        log "✓ jq: $(jq --version)"
    else
        log "Warning: jq not found (recommended for PCR parsing)"
    fi
    
    # Check AWS CLI
    if command -v aws &> /dev/null; then
        log "✓ aws-cli: $(aws --version 2>&1 | head -n1)"
    else
        log_error "✗ aws-cli not found"
        all_good=false
    fi
    
    # Check allocator config
    if [ -f /etc/nitro_enclaves/allocator.yaml ]; then
        log "✓ allocator.yaml configured"
    else
        log_error "✗ allocator.yaml not found"
        all_good=false
    fi
    
    if [ "$all_good" = true ]; then
        log "========================================="
        log "✓ Setup complete!"
        log "========================================="
        log "Instance is ready for EIF building"
        log "Run build-eif-ci.sh to build an EIF"
        return 0
    else
        log_error "========================================="
        log_error "Setup incomplete - check errors above"
        log_error "========================================="
        return 1
    fi
}

main() {
    log "========================================="
    log "Nitro Instance Setup for EIF Building"
    log "========================================="
    
    check_os
    install_nitro_cli
    install_docker
    install_dependencies
    configure_nitro_allocator
    verify_setup
    
    log "========================================="
    log "Setup script completed"
    log "========================================="
}

# Run main function
main "$@"

