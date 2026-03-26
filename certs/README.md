# TLS Certificates

If your Vault server uses a private/self-signed CA, place the CA certificate in this directory as `vault-ca.pem`. The Dockerfile will automatically build a combined CA bundle so that both httpx (Vault API) and requests (Google Auth token refresh) trust it.

If your Vault uses a publicly-trusted certificate (or you're not using Vault), no action is needed — the Dockerfile uses the system CA bundle by default.
