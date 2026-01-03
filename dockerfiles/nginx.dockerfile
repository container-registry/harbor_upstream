# Dockerfile for Harbor Nginx Proxy
# Based on .dagger/main.go buildNginx logic (lines 566-574)
# Note: Uses standard nginx image from docker.io (runs as root by default)

FROM docker.io/nginx:1-alpine3.21

WORKDIR /

# Expose port 8080 (hardened nginx listens on 8080)
EXPOSE 8080

# Set entrypoint (line 573)
ENTRYPOINT ["nginx", "-g", "daemon off;"]
