# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG TARGETVARIANT

ENV GOTOOLCHAIN=local

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 \
    GOOS="$TARGETOS" \
    GOARCH="$TARGETARCH" \
    GOARM="${TARGETVARIANT#v}" \
    go build -trimpath -ldflags="-s -w" -o /out/ja3proxy ./cmd/ja3proxy

FROM gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2

LABEL org.opencontainers.image.source="https://github.com/LyleMi/ja3proxy"

WORKDIR /app

COPY --from=builder /out/ja3proxy /app/ja3proxy

ENTRYPOINT ["/app/ja3proxy"]
