FROM ubuntu:18.04

WORKDIR /root

COPY ./keys/id_rsa_docker.pub /root/
RUN apt update\
    && apt install -y apt-transport-https ca-certificates curl gnupg lsb-release\
    && apt install -y wget cmake build-essential\
    && echo "" > /etc/apt/sources.list\
    && echo\
    "deb https://mirrors.ustc.edu.cn/ubuntu/ bionic main restricted universe multiverse\n\
    deb https://mirrors.ustc.edu.cn/ubuntu/ bionic-security main restricted universe multiverse\n\
    deb https://mirrors.ustc.edu.cn/ubuntu/ bionic-updates main restricted universe multiverse\n\
    deb https://mirrors.ustc.edu.cn/ubuntu/ bionic-backports main restricted universe multiverse\n"\
    >> /etc/apt/sources.list\
    && echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main'| tee /etc/apt/sources.list.d/intel-sgx.list\
    && wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -\
    && apt update\
    && apt install -y libsgx-launch libsgx-urts\
    && apt install -y libsgx-epid libsgx-urts\
    && apt install -y libsgx-quote-ex libsgx-urts\
    && apt install -y openssh-server\
    && mkdir -p /var/run/sshd\
    && sed -ri 's/session required pam_loginuid.so/#session required pam_loginuid.so/g' /etc/pam.d/sshd\
    && echo "PermitRootLogin yes\nAuthorizedKeysFile /root/id_rsa_docker.pub\n" >> /etc/ssh/sshd_config\
    && cd /root/\
    && wget https://github.com/docopt/docopt.cpp/archive/refs/tags/v0.6.3.tar.gz\
    && tar -zxf /root/v0.6.3.tar.gz\
    && cd /root/docopt.cpp-0.6.3/\
    && cmake .\
    && make install\
    && cd /root/\
    && wget https://www.openssl.org/source/openssl-1.1.1q.tar.gz\
    && tar -zxf /root/openssl-1.1.1q.tar.gz\
    && cd /root/openssl-1.1.1q/\
    && ./config\
    && make\
    && make install

# CMD ["/bin/bash"]
ENTRYPOINT /usr/sbin/sshd -D 