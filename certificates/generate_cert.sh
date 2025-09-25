#!/bin/bash
# Generate self-signed SSL certificate for development
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
    -subj "/C=US/ST=State/L=City/O=CodeGrey/CN=dev.codegrey.ai"
echo "SSL certificates generated: cert.pem and key.pem"
