# Dockerfile.dvls-base - DVLS base image for HTTPS deployment (Simplified)
FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install essential dependencies for DVLS
RUN apt-get update && apt-get install -y \
    # Core utilities
    wget \
    curl \
    apt-transport-https \
    software-properties-common \
    ca-certificates \
    unzip \
    tar \
    file \
    nano \
    # Network utilities for troubleshooting
    netcat-openbsd \
    net-tools \
    iputils-ping \
    dnsutils \
    # SSL/Certificate utilities (required for DVLS HTTPS)
    openssl \
    # Database client utilities
    telnet \
    # Process utilities for debugging
    procps \
    htop \
    # System utilities
    sudo \
    # Required for .NET applications
    libc6 \
    libgcc1 \
    libgssapi-krb5-2 \
    libicu70 \
    libssl3 \
    libstdc++6 \
    zlib1g \
    # Required for SQL Server connectivity
    libodbc1 \
    odbcinst \
    && rm -rf /var/lib/apt/lists/*

# Install PowerShell 7 (latest stable)
RUN wget -q https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb \
    && dpkg -i packages-microsoft-prod.deb \
    && rm packages-microsoft-prod.deb \
    && apt-get update \
    && apt-get install -y powershell \
    && rm -rf /var/lib/apt/lists/*

# Verify PowerShell installation
RUN pwsh --version

# Create DVLS user and group (matching official script)
RUN useradd -N dvls \
    && groupadd dvls \
    && usermod -a -G dvls dvls \
    && mkdir -p /opt/devolutions/dvls

# Create script mount points (will be populated via ConfigMaps at runtime)
RUN mkdir -p /runtime-scripts /config-templates /log-scripts \
    && chmod 755 /runtime-scripts /config-templates /log-scripts

# Set proper permissions (matching official script pattern)
RUN chown -R dvls:dvls /opt/devolutions/dvls \
    && chmod 550 /opt/devolutions/dvls

# Create directories that DVLS expects
RUN mkdir -p /opt/devolutions/dvls/App_Data \
    && chown -R dvls:dvls /opt/devolutions/dvls/App_Data \
    && chmod 770 /opt/devolutions/dvls/App_Data

# Set up certificate directory with proper permissions
RUN mkdir -p /opt/devolutions/dvls/certs \
    && chown dvls:dvls /opt/devolutions/dvls/certs \
    && chmod 750 /opt/devolutions/dvls/certs

# Environment variables for production
ENV SCHEDULER_EMBEDDED=true
ENV ASPNETCORE_ENVIRONMENT=Production
ENV DOTNET_RUNNING_IN_CONTAINER=true
ENV ASPNETCORE_URLS=https://0.0.0.0:5000

# Expose DVLS HTTPS port (port 5000 as per official documentation)
EXPOSE 5000

# Default working directory
WORKDIR /opt/devolutions/dvls

# Health check for HTTPS endpoint (will be overridden by Kubernetes probes)
HEALTHCHECK --interval=30s --timeout=10s --start-period=300s --retries=3 \
    CMD curl -k -f https://localhost:5000/ || exit 1

# Simple entrypoint that can be overridden
ENTRYPOINT ["/bin/bash"]

# Default command - can be overridden in Kubernetes manifests
CMD ["-c", "echo 'DVLS Base Image Ready for HTTPS - Override CMD in Kubernetes manifest'; sleep infinity"]