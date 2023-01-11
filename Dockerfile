# syntax=docker/dockerfile:1.4
FROM cgr.dev/chainguard/go:1.19 as builder

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN mkdir out
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o ./out/ ./cmd/...
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o ./out/ github.com/cloudflare/cfssl/cmd/cfssl
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o ./out/ github.com/cloudflare/cfssl/cmd/cfssljson

FROM cgr.dev/chainguard/alpine-base:latest
WORKDIR /app
COPY cfssl/ ./cfssl/
COPY --from=0 /build/out ./bin
