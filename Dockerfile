# syntax=docker/dockerfile:1

ARG GO_VERSION=1.27.3
FROM golang:${GO_VERSION}-alpine AS build

WORKDIR /src

RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /out/gomta ./cmd/gomta

FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S -g 10001 gomta \
    && adduser -S -D -H -u 10001 -G gomta gomta \
    && mkdir -p /var/lib/gomta \
    && chown gomta:gomta /var/lib/gomta

COPY --from=build /out/gomta /usr/local/bin/gomta
COPY docker/entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

WORKDIR /var/lib/gomta
USER gomta

EXPOSE 2525 5587 8080
VOLUME ["/var/lib/gomta"]
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD wget -q -O - "${GOMTA_HEALTHCHECK_URL:-http://127.0.0.1:8080/healthz}" >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["serve"]
