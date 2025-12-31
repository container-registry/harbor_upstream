# Dockerfile for Harbor Nginx Proxy
# Based on .dagger/main.go buildNginx logic (lines 566-574)
# Security: Uses unprivileged nginx image (runs as UID 101, not root)

FROM nginxinc/nginx-unprivileged:alpine

# Copy CA certificates (as root temporarily for this layer)
USER root
COPY --from=alpine:3.21.3 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# Switch back to nginx user (UID 101)
USER 101

WORKDIR /

# Expose port 8080 (unprivileged nginx listens on 8080, not 80)
EXPOSE 8080

# Set entrypoint (line 573)
ENTRYPOINT ["nginx", "-g", "daemon off;"]
