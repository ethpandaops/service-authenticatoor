FROM golang:1.25-alpine AS builder

WORKDIR /src

# Cache module downloads.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/authenticatoor \
    ./cmd/authenticatoor

# ─────────────────────────────────────────────────────────────────────────────

FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.source="https://github.com/ethpandaops/service-authenticatoor"
LABEL org.opencontainers.image.description="Issues short-lived RS256 JWTs for users authenticated by an upstream SSO proxy"

COPY --from=builder /out/authenticatoor /usr/local/bin/authenticatoor

USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/authenticatoor"]
CMD ["--config", "/etc/authenticatoor/config.yaml"]
