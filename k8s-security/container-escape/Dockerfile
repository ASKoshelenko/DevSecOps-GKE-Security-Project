# =============================================================================
# Container Image with Security Testing Tools
# =============================================================================
#
# PURPOSE: Build an image containing common tools used during container escape
# demonstrations. This image is used with privileged-pod.yaml for authorized
# security testing.
#
# BUILD:
#   docker build -t k8s-escape-demo:latest .
#
# WARNING: This image contains tools that can be used to escape containers.
# Only use in authorized testing environments.
#
# =============================================================================

FROM ubuntu:22.04

LABEL maintainer="security-demo"
LABEL description="Container escape demonstration image for authorized security testing"
LABEL purpose="educational"

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------------------
# Install security testing and debugging tools
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    # ---- Networking tools ----
    curl \
    wget \
    netcat-openbsd \
    nmap \
    dnsutils \
    iproute2 \
    iputils-ping \
    tcpdump \
    socat \
    # ---- Process & system tools ----
    procps \
    psmisc \
    htop \
    strace \
    ltrace \
    # ---- Filesystem tools ----
    util-linux \
    mount \
    fdisk \
    # ---- Container-specific tools ----
    # nsenter is part of util-linux (for namespace traversal)
    # unshare is part of util-linux (for namespace creation)
    # ---- Compilers & build tools (for kernel exploits) ----
    gcc \
    g++ \
    make \
    # ---- Python (for scripting exploits) ----
    python3 \
    python3-pip \
    python3-requests \
    # ---- General utilities ----
    vim \
    jq \
    tree \
    file \
    less \
    ca-certificates \
    openssh-client \
    # ---- Kubernetes tools ----
    apt-transport-https \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Install kubectl inside the container
# (Useful for demonstrating API access from within a compromised container)
# ---------------------------------------------------------------------------
RUN curl -fsSL https://dl.k8s.io/release/v1.23.17/bin/linux/amd64/kubectl \
        -o /usr/local/bin/kubectl \
    && chmod +x /usr/local/bin/kubectl

# ---------------------------------------------------------------------------
# Install Docker CLI (for interacting with mounted Docker socket)
# ---------------------------------------------------------------------------
RUN curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-24.0.7.tgz \
        -o /tmp/docker.tgz \
    && tar -xzf /tmp/docker.tgz -C /tmp \
    && mv /tmp/docker/docker /usr/local/bin/docker \
    && rm -rf /tmp/docker /tmp/docker.tgz

# ---------------------------------------------------------------------------
# Install amicontained - tool to check container security settings
# ---------------------------------------------------------------------------
RUN curl -fsSL https://github.com/genuinetools/amicontained/releases/download/v0.4.9/amicontained-linux-amd64 \
        -o /usr/local/bin/amicontained \
    && chmod +x /usr/local/bin/amicontained || true

# ---------------------------------------------------------------------------
# Install deepce - container escape detection/exploitation tool
# ---------------------------------------------------------------------------
RUN curl -fsSL https://github.com/stealthcopter/deepce/raw/main/deepce.sh \
        -o /usr/local/bin/deepce.sh \
    && chmod +x /usr/local/bin/deepce.sh || true

# ---------------------------------------------------------------------------
# Add demo scripts
# ---------------------------------------------------------------------------
COPY escape-demo.sh /opt/escape-demo.sh
RUN chmod +x /opt/escape-demo.sh

# ---------------------------------------------------------------------------
# Create a marker file to identify this container
# ---------------------------------------------------------------------------
RUN echo "THIS IS INSIDE THE CONTAINER" > /container-marker.txt

# Set working directory
WORKDIR /opt

# Default command - keep the container running for interactive use
CMD ["sleep", "infinity"]
