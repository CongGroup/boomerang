#!/bin/bash

# SSH service config, optional
sudo sed -ie 's/^#AuthorizedKeysFile.*$/AuthorizedKeysFile .ssh\/authorized_keys/g' /etc/ssh/sshd_config
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDhcjDOtw6yt7nitNBF4mP3Vb1dYWFnPMuA+6hDIb9JvcSpu1WgsLw4TaUuyGtWBv3H7JdNaROoqlSIC0vkJaMAwtOHIPHAQIaCJN8SH1TCDzxhp8VnWfEvF+g91fomFGQY7ahxr+LrO5JjlXk+DiiKKTBvQKxyhCi90jKIewRdSImWvYQWEc8Eca5XP0l/1K1gmiecRp5aeQ6seOuVnhhCNQigK+2ys1uGoJjh+3ouQHB92EKvJom1hTrvyVZAsn7rSZdbA9ayBV6DlilE38+0TXbcUSRUsRowGC3XC/0ujjzj47OyRco3qg/sk5S0SQ4Z89wp+76rNI1ch9xXPnc0azSQp2vufiiTHg4HOrJXkVtU1PGCFOyivcgZyl+zTUx4z3LkIs4BoovZnCvkaZxv/SfLZfb71kXtBl5bfmBEt0vhOsYTweEA4sC9muQdHbVjdQg29j1MowU0E0T/MecT2HWCAZJSaMKOUe+aoFqRx+ChH/SAa2EUltJU/wBko9hIgheJXN7JXIDPVU/yhlonTHUXQ0RHWPobY0tlMnPaXkY2lg79gVe0YhtOKZDIhSSkVfUC2KcWuZKRvRPpwhUY0YjsJodh3AyHDw6Xx6QnGs6/0FOxoEcWUYSQCjIs6VpwKRwt+GkMuLEn9AtKEPEL3XBTscvPUDtgNH14tKyNHQ== ubuntu@VM-0-14-ubuntu" > ~/.ssh/authorized_keys
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