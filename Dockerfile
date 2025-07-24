FROM       gcr.io/distroless/static-debian12

# Expose TARGETOS and TARGETARCH variables. These are supported by Docker when using BuildKit, but must be "enabled" using ARG.
ARG        TARGETOS
ARG        TARGETARCH

COPY       bin/appgw_ingress_${TARGETOS}_${TARGETARCH} /bin/appgw_ingress
ENTRYPOINT [ "/bin/appgw_ingress" ]


LABEL org.opencontainers.image.title="application-gateway-kubernetes-ingress" \
      org.opencontainers.image.source="https://github.com/grafana/application-gateway-kubernetes-ingress/tree/master/cmd/appgw-ingress" \
      org.opencontainers.image.revision="${REVISION}"
