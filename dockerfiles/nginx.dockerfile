# Dockerfile for Harbor Nginx Proxy
# Based on .dagger/main.go buildNginx logic (lines 566-574)
# Security: Uses hardened nginx image from dhi.io

FROM dhi.io/nginx:1-alpine3.21

WORKDIR /

# Expose port 8080 (hardened nginx listens on 8080)
EXPOSE 8080

# Set entrypoint (line 573)
ENTRYPOINT ["nginx", "-g", "daemon off;"]
