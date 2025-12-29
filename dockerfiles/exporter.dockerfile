FROM scratch
COPY --from=alpine:3.21.3 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ARG TARGETARCH
COPY bin/linux-${TARGETARCH}/harbor-exporter /harbor-exporter
WORKDIR /
EXPOSE 8080
ENTRYPOINT ["/harbor-exporter"]
