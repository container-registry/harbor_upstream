# Dockerfile for Harbor Trivy Adapter
# Based on .dagger/main.go buildTrivyAdapter logic (lines 595-629)

FROM golang:1.24.6 AS builder

ARG TARGETARCH

# Build trivy-adapter (lines 598-614)
WORKDIR /go/src/github.com/goharbor/
RUN git clone -b v0.33.2 https://github.com/goharbor/harbor-scanner-trivy.git

WORKDIR /go/src/github.com/goharbor/harbor-scanner-trivy
RUN CGO_ENABLED=0 go build -o ./binary/scanner-trivy cmd/scanner-trivy/main.go

# Download trivy binary (multi-arch support)
RUN case "${TARGETARCH}" in \
      amd64) TRIVY_ARCH="64bit" ;; \
      arm64) TRIVY_ARCH="ARM64" ;; \
      *) echo "Unsupported architecture: ${TARGETARCH}" && exit 1 ;; \
    esac && \
    wget --progress=dot:giga -O trivyDownload "https://github.com/aquasecurity/trivy/releases/download/v0.64.1/trivy_0.64.1_Linux-${TRIVY_ARCH}.tar.gz" && \
    tar -zxvf trivyDownload && \
    cp trivy ./binary/trivy

# Final stage - use aquasec/trivy base image (line 620)
FROM aquasec/trivy:0.58.1

# Copy CA certificates
COPY --from=alpine:3.21.3 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binaries from builder (lines 622-623)
COPY --from=builder /go/src/github.com/goharbor/harbor-scanner-trivy/binary/scanner-trivy /home/scanner/bin/scanner-trivy
COPY --from=builder /go/src/github.com/goharbor/harbor-scanner-trivy/binary/trivy /usr/local/bin/trivy

# Set environment variable (line 625)
ENV TRIVY_VERSION=v0.33.2

WORKDIR /

# Expose ports (lines 626-627)
EXPOSE 8080
EXPOSE 8443

# Set entrypoint (line 628)
ENTRYPOINT ["/home/scanner/bin/scanner-trivy"]
