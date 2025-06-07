# Vault OpenAI Dynamic Secrets Plugin - prompt for CoPilot Agent

The Vault plugin needs to create a dynamic secrets engine for [OpenAI project service accounts](https://platform.openai.com/docs/api-reference/project-service-accounts)
To setup everything up, it should use a [Admin API keys as root config](https://platform.openai.com/docs/api-reference/admin-api-keys)

Use the repository of the Vault LDAP plugin as a reference for the implementation: [Vault LDAP Plugin](https://github.com/hashicorp/vault-plugin-secrets-ldap)

As reference to implement the root config rotation use this repo https://github.com/hashicorp/vault-plugin-secrets-gcp

Other useful links:
- [Vault LDAP Dynamic Secrets Documentation](https://developer.hashicorp.com/vault/docs/secrets/ldap)
 - [OpenAI authentication documentation](https://platform.openai.com/docs/api-reference/authentication)

Write a PROJECT_STATUS.md file that summarizes the current status of the project, completed tasks, remaining tasks, and next steps.
