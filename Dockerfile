FROM golang:1.24.3-alpine3.22 AS build

WORKDIR /src
COPY . .
RUN apk add --no-cache make git
RUN make build-release

FROM alpine:3.22
LABEL org.opencontainers.image.title="vault-plugin-secrets-openai"
LABEL org.opencontainers.image.description="HashiCorp Vault OpenAI Dynamic Secrets Plugin"
LABEL org.opencontainers.image.authors="Ricardo Oliveira"
LABEL org.opencontainers.image.source="https://github.com/gitrgoliveira/vault-plugin-secrets-openai"

RUN addgroup -S vault && adduser -S vault -G vault
USER vault:vault
WORKDIR /home/vault

COPY --from=build /src/bin/vault-plugin-secrets-openai /home/vault/vault-plugin-secrets-openai

ENTRYPOINT ["/home/vault/vault-plugin-secrets-openai"]
