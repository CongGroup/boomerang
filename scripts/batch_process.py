import os, sys, signal, time, json, math
import logging
import threading
import subprocess
import argparse
import datetime


def exec_local_cmd(cmd, printCmd=True):
    if printCmd:
        print("Calling: %s" % cmd)
    try:
        with subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid) as p:
            pass
    except Exception as e:
        logging.error("Terminated: " + cmd + " " + str(e))


def exec_remote_cmd(ip_list, remote_cmd):
    ths = []
    for ip in ip_list:
        # print(ip)
        local_cmd = "ssh -o StrictHostKeyChecking=no -i ./Boomerang/keys/id_rsa_host ubuntu@{ip} -p 22 \"{remote_cmd}\"".format(
            ip=ip, remote_cmd=remote_cmd)
        # exec_local_cmd(local_cmd)
        ths.append(threading.Thread(target=exec_local_cmd, args=(local_cmd, )))
    for th in ths:
        th.start()
    for th in ths:
        th.join()


def copy_to_remote(ip_list, local_file_path, to_dir):
    ths = []
    for ip in ip_list:
        local_cmd = "scp -o StrictHostKeyChecking=no -i ./Boomerang/keys/id_rsa_host -P 22 {local_path} ubuntu@{ip}:{to_dir}\n".format(
            ip=ip, local_path=local_file_path, to_dir=to_dir)
        ths.append(threading.Thread(target=exec_local_cmd, args=(local_cmd, )))
    for th in ths:
        th.start()
    for th in ths:
        th.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--install-key", action='store_true', help="install key on all remote servers")
    parser.add_argument("--install-dep", action='store_true', help="install dependencies on all remote servers")

    args = parser.parse_args()

    # Load network config
    f = open("../config/config_multi_server.json", "r")
    cf = json.load(f)
    ip_list = []
    for priv_ip, pub_ip in cf["nat"].items():
        ip_list.append(pub_ip)
    print(ip_list)

    # install id_rsa_host ssh key
    if args.install_key:
        f_sh = open("./batch_process.sh", "w")
        f_sh.write("#!/bin/bash\n\n")
        for ip in ip_list:
            cmd = "scp -P 22 ./id_rsa_host_setup.sh ubuntu@{ip}:~/\n".format(
                ip=ip)  # scp cannot create dir recursively!
            f_sh.write(cmd)
        for ip in ip_list:
            cmd = "ssh ubuntu@{ip} -p 22 \"sudo bash ~/id_rsa_host_setup.sh\"\n".format(ip=ip)
            f_sh.write(cmd)
        f_sh.close()

    # Copy id_rsa_docker to remote machines
    if args.install_dep:
        copy_to_remote(ip_list, "../keys/id_rsa_docker", "~/.ssh")
        exec_remote_cmd(ip_list, "chmod 400 ~/.ssh/id_rsa_docker")  # Add authority to key

    # Copy install_dep.sh to remote machines and install it
    if args.install_dep:
        copy_to_remote(ip_list, "../install_dep.sh", "~/")
        exec_remote_cmd(ip_list, "sudo bash ~/install_dep.sh")