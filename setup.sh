 #!/bin/bash

echo "
▓█████▄  ▄▄▄    ██▒   █▓▓██   ██▓ ▄▄▄██▀▀▀▒█████   ███▄    █ ▓█████   ██████ 
▒██▀ ██▌▒████▄ ▓██░   █▒ ▒██  ██▒   ▒██  ▒██▒  ██▒ ██ ▀█   █ ▓█   ▀ ▒██    ▒ 
░██   █▌▒██  ▀█▄▓██  █▒░  ▒██ ██░   ░██  ▒██░  ██▒▓██  ▀█ ██▒▒███   ░ ▓██▄   
░▓█▄   ▌░██▄▄▄▄██▒██ █░░  ░ ▐██▓░▓██▄██▓ ▒██   ██░▓██▒  ▐▌██▒▒▓█  ▄   ▒   ██▒
░▒████▓  ▓█   ▓██▒▒▀█░    ░ ██▒▓░ ▓███▒  ░ ████▓▒░▒██░   ▓██░░▒████▒▒██████▒▒
 ▒▒▓  ▒  ▒▒   ▓▒█░░ ▐░     ██▒▒▒  ▒▓▒▒░  ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ░░ ▒░ ░▒ ▒▓▒ ▒ ░
 ░ ▒  ▒   ▒   ▒▒ ░░ ░░   ▓██ ░▒░  ▒ ░▒░    ░ ▒ ▒░ ░ ░░   ░ ▒░ ░ ░  ░░ ░▒  ░ ░
 ░ ░  ░   ░   ▒     ░░   ▒ ▒ ░░   ░ ░ ░  ░ ░ ░ ▒     ░   ░ ░    ░   ░  ░  ░  
   ░          ░  ░   ░   ░ ░      ░   ░      ░ ░           ░    ░  ░      ░  
 ░                  ░    ░ ░                                                 
 "

echo "Installing dependencies..."
apt-get update

# Install Docker
echo "Installing Docker..."
apt-get update && apt-get install -y docker.io

# Install Trivy
echo "Installing Trivy..."
wget https://github.com/aquasecurity/trivy/releases/download/v0.53.0/trivy_0.53.0_Linux-64bit.deb
dpkg -i trivy_0.53.0_Linux-64bit.deb  || echo "Failed to install Trivy"

if ! command -v trivy &>/dev/null; then
    echo "Trivy could not be found, attempting to add to PATH"
    export PATH=$PATH:/usr/local/bin
fi

# Verify installation
if command -v trivy &>/dev/null; then
    echo "Trivy is installed at $(which trivy)"
else
    echo "Trivy installation failed"
    exit 1
fi


# Install Terraform
echo "Installing Terraform..."
wget https://releases.hashicorp.com/terraform/1.9.0/terraform_1.9.0_linux_amd64.zip
unzip terraform_1.9.0_linux_amd64.zip
mv terraform /usr/local/bin/

# Install Conftest
echo "Installing Conftest..."
wget https://github.com/open-policy-agent/conftest/releases/download/v0.54.0/conftest_0.54.0_Linux_x86_64.tar.gz
tar xzf conftest_0.54.0_Linux_x86_64.tar.gz
mv conftest /usr/local/bin/

echo "Setup complete."
