import os, sys, signal, time, json
import logging
import threading
import subprocess
import argparse
import threading

# logging.basicConfig(format="[%(asctime)s] %(levelname)s: %(message)s",
#                     level=logging.INFO)

local_sub_processes = []
finish_exp = threading.Semaphore(0)


def config_logging(log_dir):
    if not os.path.exists(log_dir):
        os.mkdir(log_dir)

    # log_filename = datetime.datetime.now().strftime("%Y-%m-%d-%H%M") + ".log"
    log_filepath = os.path.join(log_dir, "all.log")

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(stream=sys.stdout)
    fh = logging.FileHandler(filename=log_filepath, encoding="utf-8")
    formatter = logging.Formatter("%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s: %(message)s")
    ch.setFormatter(formatter)
    fh.setFormatter(formatter)
    logger.addHandler(ch)
    logger.addHandler(fh)
    logging.getLogger('matplotlib.font_manager').disabled = True

    logging.info("Current log file {}".format(log_filepath))


class LogPipe(threading.Thread):

    def __init__(self, level):
        """Setup the object with a logger and a loglevel
        and start the thread
        """
        threading.Thread.__init__(self)
        self.daemon = False
        self.level = level
        self.fdRead, self.fdWrite = os.pipe()
        self.pipeReader = os.fdopen(self.fdRead)
        self.start()

    def fileno(self):
        """Return the write file descriptor of the pipe
        """
        return self.fdWrite

    def run(self):
        """Run the thread, logging everything.
        """
        for line in iter(self.pipeReader.readline, ''):
            logging.log(self.level, line.strip('\n'))
            if line.strip('\n') == "Finish exp":
                finish_exp.release()

        self.pipeReader.close()

    def close(self):
        """Close the write end of the pipe.
        """
        os.close(self.fdWrite)


def get_unique_ips(ips_list):
    unique_ips_set = set()
    for ip in ips_list:
        unique_ips_set.add(ip)
    return list(unique_ips_set)


def get_ip_port(addr):
    idx = addr.find(":")
    return (addr[:idx], addr[idx + 1:])


class RemoteDocker:

    def __init__(self, priv_ip, priv_port, pub_ip, host_key, docker_key, logpipe, cpu_set=""):
        self.priv_ip = priv_ip
        self.priv_port = priv_port

        self.pub_ip = pub_ip
        self.pub_port = "22"

        self.ctrl_ip = priv_ip
        self.ctrl_port = str(int(priv_port) + 100)

        self.host_key = host_key
        self.docker_key = docker_key

        self.logpipe = logpipe

        self.cpu_set = cpu_set

    def start(self, use_sgx=True):
        if use_sgx:
            self._exec_remote_cmd(
                r"sudo docker run -d {cpu_set} -p {ctrl_port}:22 -p {priv_port}:{priv_port} --device /dev/sgx_enclave:/dev/sgx_enclave polariris/boomerang:2209"
                .format(cpu_set=self.cpu_set, ctrl_port=self.ctrl_port,
                        priv_port=self.priv_port), self.pub_ip, self.pub_port, "ubuntu", self.host_key)
        else:
            self._exec_remote_cmd(
                r"sudo docker run -d -p {ctrl_port}:22 -p {priv_port}:{priv_port} polariris/boomerang:2209".format(
                    ctrl_port=self.ctrl_port, priv_port=self.priv_port), self.pub_ip, self.pub_port, "ubuntu",
                self.host_key)

    def stop(self):
        self._exec_remote_cmd(
            r"[ \$(sudo docker container ls | grep {priv_port} | wc -l) -eq 0 ] || sudo docker stop \$(sudo docker container ls | grep {priv_port} | awk \"{{print \\\$1}}\")"
            .format(priv_port=self.priv_port), self.pub_ip, self.pub_port, "ubuntu", self.host_key)
        self._exec_remote_cmd(
            r"[ \$(sudo docker container ls -a | grep Exited | wc -l) -eq 0 ] || sudo docker rm \$(sudo docker container ls -a | grep Exited | awk \"{print \\\$1}\")",
            self.pub_ip, self.pub_port, "ubuntu", self.host_key)

    def exec_cmd(self, cmd, blockCmd=True):
        host_cmd = r"ssh -o StrictHostKeyChecking=no -i {docker_key} root@127.0.0.1 -p {ctrl_port} \"{cmd}\"".format(
            docker_key=self.docker_key, ctrl_port=self.ctrl_port, cmd=cmd)
        self._exec_remote_cmd(host_cmd, self.pub_ip, self.pub_port, "ubuntu", self.host_key, blockCmd)

    def copy_file(self, local_filepath, remote_dir):
        self._copy_file2remote(local_filepath, "/tmp", self.pub_ip, self.pub_port, "ubuntu", self.host_key)
        local_filename = local_filepath.split("/")[-1]
        self.exec_cmd(r"[ -d {remote_dir} ] || mkdir -p {remote_dir}".format(remote_dir=remote_dir))
        self._exec_remote_cmd(
            r"scp -o StrictHostKeyChecking=no -i {docker_key} -P {ctrl_port} /tmp/{local_filename} root@127.0.0.1:{remote_dir}"
            .format(docker_key=self.docker_key,
                    ctrl_port=self.ctrl_port,
                    local_filename=local_filename,
                    remote_dir=remote_dir), self.pub_ip, self.pub_port, "ubuntu", self.host_key)

    def copy_dir(self, local_dir, remote_dir):
        local_dir_name = local_dir.strip("/").split("/")[-1]
        self._exec_remote_cmd(
            r"[ -d /tmp/{local_dir_name} ] && rm -rf /tmp/{local_dir_name}".format(local_dir_name=local_dir_name),
            self.pub_ip, self.pub_port, "ubuntu", self.host_key)
        self._copy_dir2remote(local_dir, "/tmp/{local_dir_name}".format(local_dir_name=local_dir_name), self.pub_ip,
                              self.pub_port, "ubuntu", self.host_key)
        self.exec_cmd(r"[ -d {remote_dir} ] || mkdir -p {remote_dir}".format(remote_dir=remote_dir))
        self._exec_remote_cmd(
            r"scp -o StrictHostKeyChecking=no -i {docker_key} -P {ctrl_port} -r /tmp/{local_dir_name} root@127.0.0.1:{remote_dir}"
            .format(docker_key=self.docker_key,
                    ctrl_port=self.ctrl_port,
                    local_dir_name=local_dir_name,
                    remote_dir=remote_dir), self.pub_ip, self.pub_port, "ubuntu", self.host_key)

    def kill(self, process_name):
        self.exec_cmd(
            r"[[ \\\$(ps -A | grep {process_name} | awk \\\"{{print \\\\\\\$1}}\\\") ]] && ps -A | grep {process_name} | awk \\\"{{print \\\\\\\$1}}\\\" | xargs kill"
            .format(process_name=process_name))
        # self.exec_cmd("[[ \\\\\\$(ps -A | grep {process_name} | awk \\\\\\\"{{print \\\\\\$1}}\\\\\\\") ]] && echo yes || echo no".format(process_name=process_name))

    def _exec_local_cmd(self, cmd, blockCmd=True, printCmd=False):
        if printCmd:
            print("Calling: %s" % cmd)
        try:
            if blockCmd:
                # with subprocess.Popen(cmd.split(),
                #                       stdout=self.logpipe,
                #                       stderr=self.logpipe,
                #                       preexec_fn=os.setsid) as p:
                #     pass
                with subprocess.Popen(cmd, shell=True, stdout=self.logpipe, stderr=self.logpipe,
                                      preexec_fn=os.setsid) as p:
                    pass
            else:
                local_sub_processes.append(
                    subprocess.Popen(cmd, shell=True, stdout=self.logpipe, stderr=self.logpipe, preexec_fn=os.setsid))
        except Exception as e:
            logging.error("Terminated: " + cmd + " " + str(e))

    def _exec_remote_cmd(self, cmd, hostname, port, user, key=None, blockCmd=True):
        if key:
            cmd = "ssh -o StrictHostKeyChecking=no -i {key} {user}@{hostname} -p {port} \"{cmd}\"".format(
                key=key, user=user, hostname=hostname, port=port, cmd=cmd)
        else:
            cmd = "ssh -o StrictHostKeyChecking=no -t {user}@{hostname} -p {port} \"{cmd}\"".format(
                key=key, user=user, hostname=hostname, port=port, cmd=cmd)  # -t preudo tty for entering passwd
        self._exec_local_cmd(cmd, blockCmd)

    def _copy_file2remote(self, local_filename, remote_dir, hostname, port, user, key=None):
        cmd = "scp -o StrictHostKeyChecking=no -i {key} -P {port} {local_filename} {user}@{hostname}:{remote_dir}".format(
            key=key, port=port, local_filename=local_filename, user=user, hostname=hostname, remote_dir=remote_dir)
        self._exec_local_cmd(cmd)

    def _copy_dir2remote(self, local_dir, remote_dir, hostname, port, user, key=None):
        if not os.path.isdir(local_dir):
            raise "Input:local_dir must be dir"
        cmd = "scp -o StrictHostKeyChecking=no -i {key} -P {port} -r {local_dir} {user}@{hostname}:{remote_dir}".format(
            key=key, port=port, local_dir=local_dir, user=user, hostname=hostname, remote_dir=remote_dir)
        self._exec_local_cmd(cmd)


def batch_start(docker, use_sgx=True):
    docker.start(use_sgx)


def batch_update(docker, local_ress, remote_dirs):
    for local_res, remote_dir in list(zip(local_ress, remote_dirs)):
        if os.path.isdir(local_res):
            docker.copy_dir(local_res, remote_dir)
        else:
            docker.copy_file(local_res, remote_dir)


def batch_update_multi_dockers(dockers, local_ress, remote_dirs):
    for docker in dockers:
        for local_res, remote_dir in list(zip(local_ress, remote_dirs)):
            if os.path.isdir(local_res):
                docker.copy_dir(local_res, remote_dir)
            else:
                docker.copy_file(local_res, remote_dir)


def batch_stop(docker):
    docker.stop()


def batch_kill(docker, process_name):
    docker.kill(process_name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", action='store_true', help="start docker")
    parser.add_argument("--update", action='store_true', help="update file")
    parser.add_argument("--run", action='store_true', help="run server")
    parser.add_argument("--stop", action='store_true', help="stop docker")
    parser.add_argument("--update-config", action='store_true', help="update file")
    parser.add_argument("--exec-cmd", action='store_true', help="execute remote commands")

    args = parser.parse_args()

    keys_dir = "../keys"
    build_dir = "../build"
    scripts_dir = "../scripts"
    config_dir = "../config"
    log_dir = "../log"

    config_logging(log_dir)
    logpipe = LogPipe(logging.INFO)

    clt_binary = os.path.join(build_dir, "Client")
    enode_binary = os.path.join(build_dir, "ENode")
    enode_enclave_so = os.path.join(build_dir, "ENodeEnclaveLib.signed.so")
    bnode_binary = os.path.join(build_dir, "BNode")
    bnode_enclave_so = os.path.join(build_dir, "BNodeEnclaveLib.signed.so")

    docker_boomerang_dir = "/root/Boomerang"

    # Load network config
    f = open(os.path.join(config_dir, "config_multi_server.json"), "r")
    cf = json.load(f)

    mapping_priv2pub_ip = cf["nat"]

    clt_remote_dockers = []
    enode_remote_dockers = []
    bnode_remote_dockers = []

    # Remote docker config
    for priv_addr in cf["clt_addr"]:
        priv_ip, priv_port = tuple(priv_addr.split(":"))
        pub_ip = mapping_priv2pub_ip[priv_ip]
        host_key = os.path.join(keys_dir, "id_rsa_host")  # local dir
        docker_key = "~/.ssh/id_rsa_docker"  # host dir not local dir
        clt_remote_dockers.append(RemoteDocker(priv_ip, priv_port, pub_ip, host_key, docker_key, logpipe))
        #   "--cpuset-cpus=1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16"))

    # Multi-Sever Experiment
    for priv_addr in cf["enode_addr"]:
        priv_ip, priv_port = tuple(priv_addr.split(":"))
        pub_ip = mapping_priv2pub_ip[priv_ip]
        host_key = os.path.join(keys_dir, "id_rsa_host")  # local dir
        docker_key = "~/.ssh/id_rsa_docker"  # host dir not local dir

        enode_remote_dockers.append(RemoteDocker(priv_ip, priv_port, pub_ip, host_key, docker_key, logpipe))
      
    # Multi-Sever Experiment
    for priv_addr in cf["bnode_addr"]:
        priv_ip, priv_port = tuple(priv_addr.split(":"))
        pub_ip = mapping_priv2pub_ip[priv_ip]
        host_key = os.path.join(keys_dir, "id_rsa_host")  # local dir
        docker_key = "~/.ssh/id_rsa_docker"  # host dir not local dir

        bnode_remote_dockers.append(RemoteDocker(priv_ip, priv_port, pub_ip, host_key, docker_key, logpipe))

    # Execute docker commands
    if args.exec_cmd:
        remote_cmd = "sudo docker container ls -a"
        for remote_docker in bnode_remote_dockers:
            remote_docker.exec_cmd(remote_cmd)

        for remote_docker in enode_remote_dockers:
            remote_docker.exec_cmd(remote_cmd)

        for remote_docker in clt_remote_dockers:
            remote_docker.exec_cmd(remote_cmd)

    # Run docker
    if args.start:
        ths = []
        for remote_docker in bnode_remote_dockers:
            ths.append(threading.Thread(target=batch_start, args=(remote_docker, )))

        for remote_docker in enode_remote_dockers:
            ths.append(threading.Thread(target=batch_start, args=(remote_docker, )))

        for remote_docker in clt_remote_dockers:
            ths.append(threading.Thread(target=batch_start, args=(
                remote_docker,
                False,
            )))

        for th in ths:
            th.start()

        for th in ths:
            th.join()

    # Update file in remote docker
    if args.update:
        ths = []

        prev_pub_ip = ""
        batch_dockers = []
        local_res = [config_dir, bnode_binary, bnode_enclave_so]
        remote_dir = [
            docker_boomerang_dir,
            os.path.join(docker_boomerang_dir, "build"),
            os.path.join(docker_boomerang_dir, "build")
        ]
        for remote_docker in bnode_remote_dockers:
            if remote_docker.pub_ip != prev_pub_ip:
                if len(batch_dockers) != 0:
                    ths.append(
                        threading.Thread(target=batch_update_multi_dockers,
                                         args=(batch_dockers.copy(), local_res.copy(), remote_dir.copy())))
                batch_dockers.clear()
            batch_dockers.append(remote_docker)
            prev_pub_ip = remote_docker.pub_ip
        if len(batch_dockers) != 0:
            ths.append(
                threading.Thread(target=batch_update_multi_dockers,
                                 args=(batch_dockers.copy(), local_res.copy(), remote_dir.copy())))
            batch_dockers.clear()

        prev_pub_ip = ""
        batch_dockers = []
        local_res = [config_dir, enode_binary, enode_enclave_so]
        remote_dir = [
            docker_boomerang_dir,
            os.path.join(docker_boomerang_dir, "build"),
            os.path.join(docker_boomerang_dir, "build")
        ]
        for remote_docker in enode_remote_dockers:
            if remote_docker.pub_ip != prev_pub_ip:
                if len(batch_dockers) != 0:
                    ths.append(
                        threading.Thread(target=batch_update_multi_dockers,
                                         args=(batch_dockers.copy(), local_res.copy(), remote_dir.copy())))
                batch_dockers.clear()
            batch_dockers.append(remote_docker)
            prev_pub_ip = remote_docker.pub_ip
        if len(batch_dockers) != 0:
            ths.append(
                threading.Thread(target=batch_update_multi_dockers,
                                 args=(batch_dockers.copy(), local_res.copy(), remote_dir.copy())))
            batch_dockers.clear()

        prev_pub_ip = ""
        batch_dockers = []
        local_res = [config_dir, clt_binary]
        remote_dir = [
            docker_boomerang_dir,
            os.path.join(docker_boomerang_dir, "build"),
            os.path.join(docker_boomerang_dir, "build")
        ]
        for remote_docker in clt_remote_dockers:
            if remote_docker.pub_ip != prev_pub_ip:
                if len(batch_dockers) != 0:
                    ths.append(
                        threading.Thread(target=batch_update_multi_dockers,
                                         args=(batch_dockers.copy(), local_res.copy(), remote_dir.copy())))
                batch_dockers.clear()
            batch_dockers.append(remote_docker)
            prev_pub_ip = remote_docker.pub_ip
        if len(batch_dockers) != 0:
            ths.append(
                threading.Thread(target=batch_update_multi_dockers,
                                 args=(batch_dockers.copy(), local_res.copy(), remote_dir.copy())))
            batch_dockers.clear()

        for th in ths:
            th.start()

        for th in ths:
            th.join()

    # Run server in remote docker
    if args.run:
        try:
            user_num_list = [2**12]  # TODO
            enode_bnode_num_list = [(1, 7), (4, 4), (7, 1)]  # TODO  The number of enode/bnode
            round_num = 13  # TODO
            run_gap = 20  # TODO The gap time (s) between bnode and enode start up, 10 for 1M, 15 for 2M, 20 for 4M

            for enode_num, bnode_num in enode_bnode_num_list:
                for user_num in user_num_list:
                    clt_send_recv_parallel_num = 32  # 32 is best for 104C, 16 is best for 16C TODO
                    enode_recv_parallel_num = 2  # 2 is best perfomance
                    bnode_recv_parallel_num = 1  # bnode recv thread num is unaffected
                    enclave_worker_thread_num = 4  # 4 is best! not 8 or 16 whatever mac core num is

                    config_path = os.path.join(docker_boomerang_dir, "config/config_multi_server.json")
                    use_B_padding = True

                    logging.info("Start experiment, enode_num = {}, bnode = {}, user_num = {}, round_num = {}".format(
                        enode_num, bnode_num, user_num, round_num))

                    # Startup server in remote docker
                    bnode_id = 0
                    for remote_docker in bnode_remote_dockers[:bnode_num]:
                        binary_path = os.path.join(docker_boomerang_dir, "build/BNode")
                        enclave_path = os.path.join(docker_boomerang_dir, "build/BNodeEnclaveLib.signed.so")

                        cmd = "{binary} --id {id} -u {user_num} -r {round_num} -p {parallel_num} -w {worker_thread_num} -e {enclave_path} -c {config_path} -i eth0 {use_B_padding} --enode-num {enode_num} --bnode-num {bnode_num}".format(
                            binary=binary_path,
                            id=bnode_id,
                            user_num=user_num,
                            round_num=round_num,
                            parallel_num=bnode_recv_parallel_num,
                            worker_thread_num=enclave_worker_thread_num,
                            enclave_path=enclave_path,
                            config_path=config_path,
                            use_B_padding="--use-B" if use_B_padding else "",
                            enode_num=enode_num,
                            bnode_num=bnode_num)
                        bnode_id += 1
                        remote_docker.exec_cmd(cmd, False)
                    # input()
                    time.sleep(run_gap)

                    enode_id = 0
                    for remote_docker in enode_remote_dockers[:enode_num]:
                        binary_path = os.path.join(docker_boomerang_dir, "build/ENode")
                        enclave_path = os.path.join(docker_boomerang_dir, "build/ENodeEnclaveLib.signed.so")
                        cmd = "{binary} --id {id} -u {user_num} -r {round_num} -p {parallel_num} -w {worker_thread_num} -e {enclave_path} -c {config_path} -i eth0 {use_B_padding} --enode-num {enode_num} --bnode-num {bnode_num}".format(
                            binary=binary_path,
                            id=enode_id,
                            user_num=user_num,
                            round_num=round_num,
                            parallel_num=enode_recv_parallel_num,
                            worker_thread_num=enclave_worker_thread_num,
                            enclave_path=enclave_path,
                            config_path=config_path,
                            use_B_padding="--use-B" if use_B_padding else "",
                            enode_num=enode_num,
                            bnode_num=bnode_num)
                        enode_id += 1
                        remote_docker.exec_cmd(cmd, False)
                    # input()
                    time.sleep(run_gap)

                    clt_id = 0
                    for remote_docker in clt_remote_dockers:
                        binary_path = os.path.join(docker_boomerang_dir, "build/Client")

                        cmd = "{binary} --id {id} -u {user_num} -r {round_num} -p {parallel_num} -c {config_path} --enode-num {enode_num} --bnode-num {bnode_num}".format(
                            binary=binary_path,
                            id=clt_id,
                            user_num=user_num,
                            round_num=round_num,
                            parallel_num=clt_send_recv_parallel_num,
                            config_path=config_path,
                            enode_num=enode_num,
                            bnode_num=bnode_num)
                        clt_id += 1
                        remote_docker.exec_cmd(cmd, False)
                    # input()
                    finish_exp.acquire()

                    # Kill server in remote docker
                    ths = []
                    for remote_docker in bnode_remote_dockers[:bnode_num]:
                        ths.append(threading.Thread(target=batch_kill, args=(remote_docker, "BNode")))
                    for th in ths:
                        th.start()
                    for th in ths:
                        th.join()
                    ths.clear()

                    for remote_docker in enode_remote_dockers[:enode_num]:
                        ths.append(threading.Thread(target=batch_kill, args=(remote_docker, "ENode")))
                    for th in ths:
                        th.start()
                    for th in ths:
                        th.join()
                    ths.clear()

                    for remote_docker in clt_remote_dockers:
                        remote_docker.kill("Client")

                    # Kill subprocess in local host
                    for sp in local_sub_processes:
                        os.killpg(os.getpgid(sp.pid), signal.SIGTERM)
                        # print("Stop local subprocess {}".format(sp.pid))
                    local_sub_processes.clear()
        except KeyboardInterrupt:  # for ctrl+c quit
            # Kill server in remote docker
            ths = []
            for remote_docker in bnode_remote_dockers:
                ths.append(threading.Thread(target=batch_kill, args=(remote_docker, "BNode")))
            for th in ths:
                th.start()
            for th in ths:
                th.join()
            ths.clear()

            for remote_docker in enode_remote_dockers:
                ths.append(threading.Thread(target=batch_kill, args=(remote_docker, "ENode")))
            for th in ths:
                th.start()
            for th in ths:
                th.join()
            ths.clear()

            for remote_docker in clt_remote_dockers:
                remote_docker.kill("Client")

            # Kill subprocess in local host
            for sp in local_sub_processes:
                os.killpg(os.getpgid(sp.pid), signal.SIGTERM)
                print("Stop local subprocess {}".format(sp.pid))
            local_sub_processes.clear()

    # Stop docker
    if args.stop:
        ths = []
        for remote_docker in clt_remote_dockers:
            ths.append(threading.Thread(target=batch_stop, args=(remote_docker, )))

        for remote_docker in enode_remote_dockers:
            ths.append(threading.Thread(target=batch_stop, args=(remote_docker, )))

        for remote_docker in bnode_remote_dockers:
            ths.append(threading.Thread(target=batch_stop, args=(remote_docker, )))

        for th in ths:
            th.start()

        for th in ths:
            th.join()

    logpipe.close()