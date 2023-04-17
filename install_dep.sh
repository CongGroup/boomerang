#!/bin/bash

# SSH service config, optional
sudo sed -ie 's/^#AuthorizedKeysFile.*$/AuthorizedKeysFile .ssh\/authorized_keys/g' /etc/ssh/sshd_config
echo "ssh-rsa your_public_key== user@server" > ~/.ssh/authorized_keys
sudo service ssh restart

# Intel SGX dirver
sudo apt install -y dkms
wget https://download.01.org/intel-sgx/sgx-linux/2.16/distro/ubuntu18.04-server/sgx_linux_x64_driver_1.41.bin
sudo chmod 777 ./sgx_linux_x64_driver_1.41.bin
sudo ./sgx_linux_x64_driver_1.41.bin
sudo rm ./sgx_linux_x64_driver_1.41.bin

## Docker install, 3 ways
# 1
# sudo apt install docker.io
# sudo systemctl start docker
# sudo systemctl enable docker

# 2
# sudo apt install apt-transport-https ca-certificates curl software-properties-common
# curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
# sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
# sudo apt update
# sudo apt install docker-ce

# 3
sudo apt install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://mirrors.ustc.edu.cn/docker-ce/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://mirrors.ustc.edu.cn/docker-ce/linux/ubuntu $(lsb_release -cs) stable"
sudo apt update
sudo apt install -y docker-ce

# Pull mininum dependency env from docker hub
sudo docker pull polariris/boomerang:2209
# sudo docker load < boomerang.tar

## Cmds executed in local pc
# Copy id_rsa_boomerang to ~/.ssh/
# scp -o StrictHostKeyChecking=no -i ./Boomerang/keys/id_rsa_host -P 22 ./Boomerang/keys/id_rsa_boomerang ubuntu@{ip}:~/.ssh