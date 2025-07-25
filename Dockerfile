# TODO: Figure out a way to use distroless image.
# Didn't manage to install openssl in distroless image.
FROM       debian:12-slim

# Expose TARGETOS and TARGETARCH variables. These are supported by Docker when using BuildKit, but must be "enabled" using ARG.
ARG        TARGETOS
ARG        TARGETARCH

RUN apt-get update && apt-get install -y openssl ca-certificates && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY       bin/appgw_ingress_${TARGETOS}_${TARGETARCH} /bin/appgw_ingress
ENTRYPOINT [ "/bin/appgw_ingress" ]

LABEL org.opencontainers.image.title="application-gateway-kubernetes-ingress" \
      org.opencontainers.image.source="https://github.com/grafana/application-gateway-kubernetes-ingress/tree/master/cmd/appgw-ingress" \
      org.opencontainers.image.revision="${REVISION}"
