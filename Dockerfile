# syntax=docker/dockerfile:1

# Build stage: compile the plugin for the target platform.
# BuildKit provides TARGETOS/TARGETARCH automatically for each requested platform.
FROM --platform=$BUILDPLATFORM golang:1.26 AS builder

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildTime=${BUILD_TIME}" \
    -o /out/vault-plugin-secrets-openai ./cmd/vault-plugin-secrets-openai

# Final stage
# FROM gcr.io/distroless/static-debian12 # also works.
FROM alpine:3.24

# OpenAI API calls require trusted root CAs for outbound TLS.
RUN apk add --no-cache ca-certificates

LABEL org.opencontainers.image.title="vault-plugin-secrets-openai"
LABEL org.opencontainers.image.description="HashiCorp Vault OpenAI Dynamic Secrets Plugin"
LABEL org.opencontainers.image.authors="Ricardo Oliveira"
LABEL org.opencontainers.image.source="https://github.com/gitrgoliveira/vault-plugin-secrets-openai"

COPY --from=builder /out/vault-plugin-secrets-openai /bin/vault-plugin-secrets-openai

ENTRYPOINT ["/bin/vault-plugin-secrets-openai"]
