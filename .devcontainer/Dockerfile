FROM mcr.microsoft.com/devcontainers/go:1-1.24

# Tools useful for networking/WireGuard testing inside the container
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    wireguard-tools \
    iproute2 \
    iptables \
    tcpdump \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
