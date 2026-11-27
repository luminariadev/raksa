FROM golang:1.26-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
COPY playbooks ./playbooks

ARG VERSION=0.3.0
ARG COMMIT=docker
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X github.com/luminariadev/raksa/internal/schema.Version=${VERSION} -X github.com/luminariadev/raksa/internal/schema.Commit=${COMMIT} -X github.com/luminariadev/raksa/internal/schema.BuildDate=${BUILD_DATE}" \
    -o /out/raksa ./cmd/raksa

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /workspace
COPY --from=builder /out/raksa /usr/local/bin/raksa
EXPOSE 8787
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/usr/local/bin/raksa", "version"]
ENTRYPOINT ["/usr/local/bin/raksa"]
CMD ["--help"]
