#!/bin/bash

# SSH service config
sudo sed -ie 's/^#AuthorizedKeysFile.*$/AuthorizedKeysFile .ssh\/authorized_keys/g' /etc/ssh/sshd_config
echo "ssh-rsa your_public_key user@server" > ~/.ssh/authorized_keys
sudo service ssh restart