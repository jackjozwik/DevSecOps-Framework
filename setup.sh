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
sudo apt-get update

# Install Docker
echo "Installing Docker..."
sudo apt-get update && sudo apt-get install -y docker.io

# Install Trivy
echo "Installing Trivy..."
wget https://github.com/aquasecurity/trivy/releases/download/v0.53.0/trivy_0.53.0_Linux-64bit.deb
sudo dpkg -i trivy_0.53.0_Linux-64bit.deb

# Install Terraform
echo "Installing Terraform..."
wget https://releases.hashicorp.com/terraform/1.9.0/terraform_1.9.0_linux_amd64.zip
unzip terraform_1.9.0_linux_amd64.zip
sudo mv terraform /usr/local/bin/

# Install Conftest
echo "Installing Conftest..."
wget https://github.com/open-policy-agent/conftest/releases/download/v0.54.0/conftest_0.54.0_Linux_x86_64.tar.gz
tar xzf conftest_0.54.0_Linux_x86_64.tar.gz
sudo mv conftest /usr/local/bin/

echo "Setup complete."
