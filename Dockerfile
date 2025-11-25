FROM golang:1.24-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o gateway ./cmd/gateway

FROM alpine:latest

WORKDIR /app

COPY --from=builder /build/gateway .

CMD ["/app/gateway"]
