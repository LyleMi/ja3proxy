FROM golang:1.24 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /app/ja3proxy

FROM gcr.io/distroless/cc-debian12

WORKDIR /app

COPY --from=builder /app/ja3proxy /app/ja3proxy
ENTRYPOINT ["/app/ja3proxy"]
