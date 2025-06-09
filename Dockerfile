# FROM gcr.io/distroless/static-debian12 # also works.
FROM alpine:3.22
LABEL org.opencontainers.image.title="vault-plugin-secrets-openai"
LABEL org.opencontainers.image.description="HashiCorp Vault OpenAI Dynamic Secrets Plugin"
LABEL org.opencontainers.image.authors="Ricardo Oliveira"
LABEL org.opencontainers.image.source="https://github.com/gitrgoliveira/vault-plugin-secrets-openai"

COPY bin/vault-plugin-secrets-openai /bin/vault-plugin-secrets-openai

ENTRYPOINT ["/bin/vault-plugin-secrets-openai"]
