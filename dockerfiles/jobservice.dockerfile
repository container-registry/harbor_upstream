FROM scratch
COPY --from=alpine:3.21.3 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ARG TARGETARCH
COPY bin/linux-${TARGETARCH}/jobservice /jobservice
WORKDIR /
EXPOSE 8080
ENTRYPOINT ["/jobservice", "-c", "/etc/jobservice/config.yml"]
