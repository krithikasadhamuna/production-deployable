#!/bin/bash

# NGINX Setup Script for CodeGrey SOC Platform
# Run this on your AWS server (15.207.6.45)

echo "========================================"
echo "Setting up NGINX for CodeGrey SOC"
echo "========================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Install NGINX if not installed
if ! command -v nginx &> /dev/null; then
    echo "Installing NGINX..."
    apt-get update
    apt-get install -y nginx certbot python3-certbot-nginx
else
    echo "NGINX is already installed"
fi

# Copy configuration
echo "Setting up NGINX configuration..."
cp nginx_config/soc_platform.conf /etc/nginx/sites-available/

# Enable the site
ln -sf /etc/nginx/sites-available/soc_platform.conf /etc/nginx/sites-enabled/

# Remove default site if exists
rm -f /etc/nginx/sites-enabled/default

# Test configuration
echo "Testing NGINX configuration..."
nginx -t

if [ $? -ne 0 ]; then
    echo "ERROR: NGINX configuration test failed!"
    exit 1
fi

# Get SSL certificate using Let's Encrypt
echo ""
echo "Setting up SSL certificate..."
echo "Make sure dev.codegrey.ai points to 15.207.6.45 first!"
echo ""
read -p "Is DNS configured? (y/n): " DNS_READY

if [ "$DNS_READY" = "y" ]; then
    certbot --nginx -d dev.codegrey.ai --non-interactive --agree-tos --email admin@codegrey.ai
else
    echo "Skipping SSL setup. You can run this later:"
    echo "  sudo certbot --nginx -d dev.codegrey.ai"
fi

# Reload NGINX
echo "Reloading NGINX..."
systemctl reload nginx

# Setup firewall
echo "Configuring firewall..."
ufw allow 'Nginx Full'
ufw allow OpenSSH
ufw --force enable

echo ""
echo "========================================"
echo "NGINX Setup Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo "1. Ensure DNS A record points dev.codegrey.ai to 15.207.6.45"
echo "2. Start your Flask app: python3 start_production_server.py"
echo "3. Test: curl https://dev.codegrey.ai/api/agents"
echo ""
echo "To check status:"
echo "  systemctl status nginx"
echo "  tail -f /var/log/nginx/soc_platform_error.log"
echo ""
