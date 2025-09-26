FROM debian:bookworm-slim
LABEL maintainer="Devolutions Inc."

ENV DEBIAN_FRONTEND=noninteractive

# Install DVLS dependencies (without PowerShell)
RUN set -eux; \
    apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
        nano git wget curl jq openssh-server \
        software-properties-common apt-transport-https ca-certificates; \
    rm -rf /var/lib/apt/lists/*

# Install PowerShell 7 from GitHub releases
RUN set -eux; \
    ARCH="$(dpkg --print-architecture)"; \
    case "$ARCH" in \
        amd64) PS_ARCH='x64' ;; \
        arm64) PS_ARCH='arm64' ;; \
        *) echo "Unsupported architecture: $ARCH" && exit 1 ;; \
    esac; \
    PS_VERSION=$(curl -s https://api.github.com/repos/PowerShell/PowerShell/releases/latest | jq -r '.tag_name' | sed 's/^v//'); \
    echo "Installing PowerShell $PS_VERSION for $PS_ARCH"; \
    wget -q "https://github.com/PowerShell/PowerShell/releases/download/v${PS_VERSION}/powershell-${PS_VERSION}-linux-${PS_ARCH}.tar.gz"; \
    mkdir -p /opt/microsoft/powershell/7; \
    tar -xzf "powershell-${PS_VERSION}-linux-${PS_ARCH}.tar.gz" -C /opt/microsoft/powershell/7; \
    chmod +x /opt/microsoft/powershell/7/pwsh; \
    ln -sf /opt/microsoft/powershell/7/pwsh /usr/local/bin/pwsh; \
    rm "powershell-${PS_VERSION}-linux-${PS_ARCH}.tar.gz"

ENV XDG_CACHE_HOME="/tmp/.cache"
ENV XDG_DATA_HOME="/tmp/.local/share"
ENV POWERSHELL_TELEMETRY_OPTOUT="1"

# Copy DVLS tarball from build context
COPY DVLS.*.tar.gz /tmp/

# Install DVLS and set permissions
RUN bash -c ' \
    set -euxo pipefail; \
    FILENAME="$(find /tmp -maxdepth 1 -name "DVLS.*.tar.gz" | head -n 1)"; \
    INSTALL_DIR="/opt/devolutions/dvls"; \
    echo "Extracting $FILENAME to $INSTALL_DIR..."; \
    mkdir -p "$INSTALL_DIR"; \
    tar -xzf "$FILENAME" -C "$INSTALL_DIR" --strip-components=1; \
    chmod 660 "$INSTALL_DIR/appsettings.json"; \
    chmod 770 "$INSTALL_DIR/App_Data"; \
    rm -f "$FILENAME"; \
    echo "✅ DVLS installed and permissions set" \
'

# Prepare DVLS user, directory structure, and permissions
RUN set -eux; \
    useradd -N dvls && groupadd dvls && usermod -a -G dvls dvls; \
    mkdir -p \
        /opt/devolutions/dvls \
        /opt/devolutions/dvls/App_Data \
        /opt/devolutions/dvls/certs \
        /runtime-scripts \
        /config-templates \
        /log-scripts; \
    chown -R dvls:dvls /opt/devolutions/dvls; \
    chmod 550 /opt/devolutions/dvls; \
    chmod 770 /opt/devolutions/dvls/App_Data; \
    chmod 750 /opt/devolutions/dvls/certs; \
    chmod 755 /runtime-scripts /config-templates /log-scripts

# Environment variables for production
ENV SCHEDULER_EMBEDDED=true
ENV ASPNETCORE_ENVIRONMENT=Production
ENV DOTNET_RUNNING_IN_CONTAINER=true
ENV ASPNETCORE_URLS=https://0.0.0.0:5000

# Expose DVLS HTTPS port (port 5000 as per official documentation)
EXPOSE 5000

# Default working directory
WORKDIR /opt/devolutions/dvls

ENV DVLS_EXECUTABLE_PATH="/opt/devolutions/dvls/Devolutions.Server"

# Install Devolutions.PowerShell module from PSGallery
RUN pwsh -Command "Install-Module -Name Devolutions.PowerShell -Scope AllUsers -Force"

COPY entrypoint.ps1 /usr/local/bin/entrypoint.ps1
RUN chmod +x /usr/local/bin/entrypoint.ps1
ENTRYPOINT ["pwsh", "-File", "/usr/local/bin/entrypoint.ps1"]
