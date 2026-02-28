# =============================================================================
# X-CloudSentinel Test Sample: INSECURE Dockerfile
# This file contains INTENTIONAL security issues for testing
# DO NOT use in production!
# =============================================================================

# SIQ-DOC-002: Using :latest tag (non-reproducible builds)
FROM node:latest

# SIQ-DOC-004: Secrets hardcoded in ENV instructions
ENV API_KEY="sk-1234567890abcdefghijklmnop"
ENV DB_PASSWORD="SuperSecretPassword123!"
ENV SECRET_TOKEN="my-private-token-value"
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# SIQ-DOC-005: Sensitive ARG with default value
ARG PRIVATE_KEY=my-private-key-default-value
ARG PASSWORD=default_admin_password

WORKDIR /app

# SIQ-DOC-003: Using ADD instead of COPY
ADD . /app
ADD package.json /app/package.json

RUN npm install --production

# SIQ-DOC-010: Curl piped to shell (supply chain risk)
RUN curl -sL https://example.com/install.sh | bash

# SIQ-DOC-007: Exposing SSH port
EXPOSE 22
EXPOSE 3000
EXPOSE 3389

# SIQ-DOC-009: Using sudo
RUN sudo apt-get update && sudo apt-get install -y curl

# SIQ-DOC-001: Running as root
USER root

CMD ["node", "server.js"]

# SIQ-DOC-006: Missing HEALTHCHECK instruction
# (No HEALTHCHECK defined anywhere in this Dockerfile)

