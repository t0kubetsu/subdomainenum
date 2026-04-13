# ===========================================================================
# Stage 1 – Go-based tools: subfinder, amass, gobuster, assetfinder
# ===========================================================================
FROM golang:latest AS go-builder

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/owasp-amass/amass/v4/...@latest && \
    go install -v github.com/OJ/gobuster/v3@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest

# ===========================================================================
# Stage 2 – Python runtime with all tools installed
# ===========================================================================
FROM python:slim

LABEL org.opencontainers.image.title="subdomainenum" \
      org.opencontainers.image.description="Passive & active subdomain enumeration CLI" \
      org.opencontainers.image.source="https://github.com/t0kubetsu/subdomainenum"

# System tools: dnsrecon, wfuzz, git (for SecLists sparse checkout), curl
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        curl \
        unzip \
        dnsrecon \
        wfuzz \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy Go-compiled binaries
COPY --from=go-builder /go/bin/subfinder    /usr/local/bin/subfinder
COPY --from=go-builder /go/bin/amass        /usr/local/bin/amass
COPY --from=go-builder /go/bin/gobuster     /usr/local/bin/gobuster
COPY --from=go-builder /go/bin/assetfinder  /usr/local/bin/assetfinder

# findomain – download pre-built Linux binary from GitHub releases
# (package was removed from crates.io)
RUN curl -sL \
        "https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux-i386.zip" \
        -o /tmp/findomain.zip && \
    unzip /tmp/findomain.zip -d /tmp && \
    mv /tmp/findomain /usr/local/bin/findomain && \
    chmod +x /usr/local/bin/findomain && \
    rm /tmp/findomain.zip

# ---------------------------
# SecLists – sparse checkout (DNS + Web-Content only, avoids 1.5 GB clone)
# ---------------------------
ARG SECLISTS_REF=master
RUN git clone --filter=blob:none --no-checkout --depth=1 \
        https://github.com/danielmiessler/SecLists.git /opt/SecLists && \
    cd /opt/SecLists && \
    git sparse-checkout init --cone && \
    git sparse-checkout set Discovery/DNS Discovery/Web-Content && \
    git checkout ${SECLISTS_REF} && \
    rm -rf /opt/SecLists/.git

# ---------------------------
# Install the subdomainenum package
# ---------------------------
WORKDIR /app
COPY pyproject.toml ./
COPY subdomainenum/ ./subdomainenum/

RUN pip install --no-cache-dir -e "."

# Output directory for saved reports
RUN mkdir /reports

VOLUME ["/reports"]

ENTRYPOINT ["subdomainenum"]
CMD ["--help"]
