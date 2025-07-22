FROM debian:bookworm-slim
LABEL maintainer="Devolutions Inc."

ENV DEBIAN_FRONTEND=noninteractive

# Install essential dependencies for DVLS
RUN apt-get update && apt-get install -y --no-install-recommends \
    nano git wget curl jq software-properties-common apt-transport-https ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install PowerShell 7
RUN wget -q https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb \
    && dpkg -i packages-microsoft-prod.deb \
    && rm packages-microsoft-prod.deb \
    && apt-get update \
    && apt-get install -y powershell \
    && rm -rf /var/lib/apt/lists/*

ENV XDG_CACHE_HOME="/tmp/.cache"
ENV XDG_DATA_HOME="/tmp/.local/share"
ENV POWERSHELL_TELEMETRY_OPTOUT="1"

# Download DVLS and verify SHA256 hash
RUN bash -c ' \
    set -euxo pipefail; \
    PRODUCT_JSON="$(curl -s https://devolutions.net/productinfo.json)"; \
    DOWNLOAD_LINE="$(echo "$PRODUCT_JSON" | jq -r ".DVLS.Current.Files[] | select(.Type == \"tar.gz\" and .Arch == \"x64\") | \"\(.Url) \(.Hash)\"")"; \
    read -r DOWNLOAD_URL HASH_EXPECTED <<< "$DOWNLOAD_LINE"; \
    FILENAME="/tmp/$(basename "$DOWNLOAD_URL")"; \
    echo "Downloading $DOWNLOAD_URL..."; \
    curl -sSL "$DOWNLOAD_URL" -o "$FILENAME"; \
    HASH_ACTUAL="$(sha256sum "$FILENAME" | awk "{ print toupper(\$1) }")"; \
    if [ "$HASH_ACTUAL" != "$HASH_EXPECTED" ]; then \
        echo "❌ Hash mismatch! Expected: $HASH_EXPECTED, Got: $HASH_ACTUAL" >&2; \
        exit 1; \
    fi; \
    echo "✅ Hash OK." \
'

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

ENV DVLS_EXECUTABLE_PATH="/opt/devolutions/dvls/Devolutions.Server"

# Install Devolutions.PowerShell module from PSGallery
RUN pwsh -Command "Install-Module -Name Devolutions.PowerShell -Scope AllUsers -Force"

COPY entrypoint.ps1 /usr/local/bin/entrypoint.ps1
RUN chmod +x /usr/local/bin/entrypoint.ps1
ENTRYPOINT ["pwsh", "-File", "/usr/local/bin/entrypoint.ps1"]