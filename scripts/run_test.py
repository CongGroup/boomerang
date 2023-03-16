import os, sys, signal, time, json, math
import logging
import threading
import subprocess
import argparse

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
    formatter = logging.Formatter(
        "%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s: %(message)s")
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
            r"sudo docker stop \$(sudo docker container ls | grep {priv_port} | awk \"{{print \\\$1}}\")"
            .format(priv_port=self.priv_port), self.pub_ip, self.pub_port,
            "ubuntu", self.host_key)
        self._exec_remote_cmd(
            r"sudo docker rm \$(sudo docker container ls -a | grep Exited | awk \"{print \\\$1}\")",
            self.pub_ip, self.pub_port, "ubuntu", self.host_key)

    def exec_cmd(self, cmd, blockCmd=True):
        host_cmd = r"ssh -o StrictHostKeyChecking=no -i {docker_key} root@127.0.0.1 -p {ctrl_port} \"{cmd}\"".format(
            docker_key=self.docker_key, ctrl_port=self.ctrl_port, cmd=cmd)
        self._exec_remote_cmd(host_cmd, self.pub_ip, self.pub_port, "ubuntu",
                              self.host_key, blockCmd)

    def copy_file(self, local_filepath, remote_dir):
        self._copy_file2remote(local_filepath, "/tmp", self.pub_ip,
                               self.pub_port, "ubuntu", self.host_key)
        local_filename = local_filepath.split("/")[-1]
        self.exec_cmd(r"[ -d {remote_dir} ] || mkdir -p {remote_dir}".format(
            remote_dir=remote_dir))
        self._exec_remote_cmd(
            r"scp -o StrictHostKeyChecking=no -i {docker_key} -P {ctrl_port} /tmp/{local_filename} root@127.0.0.1:{remote_dir}"
            .format(docker_key=self.docker_key,
                    ctrl_port=self.ctrl_port,
                    local_filename=local_filename,
                    remote_dir=remote_dir), self.pub_ip, self.pub_port,
            "ubuntu", self.host_key)

    def copy_dir(self, local_dir, remote_dir):
        local_dir_name = local_dir.strip("/").split("/")[-1]
        self._exec_remote_cmd(
            r"[ -d /tmp/{local_dir_name} ] && rm -rf /tmp/{local_dir_name}".
            format(local_dir_name=local_dir_name), self.pub_ip, self.pub_port,
            "ubuntu", self.host_key)
        self._copy_dir2remote(
            local_dir,
            "/tmp/{local_dir_name}".format(local_dir_name=local_dir_name),
            self.pub_ip, self.pub_port, "ubuntu", self.host_key)
        self.exec_cmd(r"[ -d {remote_dir} ] || mkdir -p {remote_dir}".format(
            remote_dir=remote_dir))
        self._exec_remote_cmd(
            r"scp -o StrictHostKeyChecking=no -i {docker_key} -P {ctrl_port} -r /tmp/{local_dir_name} root@127.0.0.1:{remote_dir}"
            .format(docker_key=self.docker_key,
                    ctrl_port=self.ctrl_port,
                    local_dir_name=local_dir_name,
                    remote_dir=remote_dir), self.pub_ip, self.pub_port,
            "ubuntu", self.host_key)

    def kill(self, process_name):
        self.exec_cmd(
            r"[[ \\\$(ps -A | grep {process_name} | awk \\\"{{print \\\\\\\$1}}\\\") ]] && ps -A | grep {process_name} | awk \\\"{{print \\\\\\\$1}}\\\" | xargs kill"
            .format(process_name=process_name))
        # self.exec_cmd("[[ \\\\\\$(ps -A | grep {process_name} | awk \\\\\\\"{{print \\\\\\$1}}\\\\\\\") ]] && echo yes || echo no".format(process_name=process_name))

    def _exec_local_cmd(self, cmd, blockCmd=True, printCmd=True):
        if printCmd:
            print("Calling: %s" % cmd)
        try:
            if blockCmd:
                # with subprocess.Popen(cmd.split(),
                #                       stdout=self.logpipe,
                #                       stderr=self.logpipe,
                #                       preexec_fn=os.setsid) as p:
                #     pass
                with subprocess.Popen(cmd,
                                      shell=True,
                                      stdout=self.logpipe,
                                      stderr=self.logpipe,
                                      preexec_fn=os.setsid) as p:
                    pass
            else:
                local_sub_processes.append(
                    subprocess.Popen(cmd,
                                     shell=True,
                                     stdout=self.logpipe,
                                     stderr=self.logpipe,
                                     preexec_fn=os.setsid))
        except Exception as e:
            logging.error("Terminated: " + cmd + " " + str(e))

    def _exec_remote_cmd(self,
                         cmd,
                         hostname,
                         port,
                         user,
                         key=None,
                         blockCmd=True):
        if key:
            cmd = "ssh -o StrictHostKeyChecking=no -i {key} {user}@{hostname} -p {port} \"{cmd}\"".format(
                key=key, user=user, hostname=hostname, port=port, cmd=cmd)
        else:
            cmd = "ssh -o StrictHostKeyChecking=no -t {user}@{hostname} -p {port} \"{cmd}\"".format(
                key=key, user=user, hostname=hostname, port=port,
                cmd=cmd)  # -t preudo tty for entering passwd
        self._exec_local_cmd(cmd, blockCmd)

    def _copy_file2remote(self,
                          local_filename,
                          remote_dir,
                          hostname,
                          port,
                          user,
                          key=None,
                          printfn=print):
        cmd = "scp -o StrictHostKeyChecking=no -i {key} -P {port} {local_filename} {user}@{hostname}:{remote_dir}".format(
            key=key,
            port=port,
            local_filename=local_filename,
            user=user,
            hostname=hostname,
            remote_dir=remote_dir)
        self._exec_local_cmd(cmd, printfn)

    def _copy_dir2remote(self,
                         local_dir,
                         remote_dir,
                         hostname,
                         port,
                         user,
                         key=None,
                         printfn=print):
        if not os.path.isdir(local_dir):
            raise "Input:local_dir must be dir"
        cmd = "scp -o StrictHostKeyChecking=no -i {key} -P {port} -r {local_dir} {user}@{hostname}:{remote_dir}".format(
            key=key,
            port=port,
            local_dir=local_dir,
            user=user,
            hostname=hostname,
            remote_dir=remote_dir)
        self._exec_local_cmd(cmd, printfn)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", action='store_true', help="start docker")
    parser.add_argument("--update", action='store_true', help="update file")
    parser.add_argument("--run", action='store_true', help="run server")
    parser.add_argument("--stop", action='store_true', help="stop docker")
    args = parser.parse_args()

    keys_dir = "../keys"
    build_dir = "../build"
    scripts_dir = "../scripts"
    config_dir = "../config"
    log_dir = "../log"

    config_logging(log_dir)
    logpipe = LogPipe(logging.INFO)

    clt_binary = os.path.join(build_dir, "TestClient")
    ss_binary = os.path.join(build_dir, "TestSubServer")
    ss_enclave_so = os.path.join(build_dir,
                                 "TestSubServerEnclaveLib.signed.so")

    docker_boomerang_dir = "/root/Boomerang"

    # Load network config
    f = open(os.path.join(config_dir, "config_single_server.json"), "r")
    cf = json.load(f)

    mapping_priv2pub_ip = cf["nat"]

    clt_remote_dockers = []
    ss_remote_dockers = []

    # Remote docker config
    assert len(cf["clt_addr"]) == 1
    for priv_addr in cf["clt_addr"]:
        priv_ip, priv_port = tuple(priv_addr.split(":"))
        pub_ip = mapping_priv2pub_ip[priv_ip]
        host_key = os.path.join(keys_dir, "id_rsa_host")  # local dir
        docker_key = "~/.ssh/id_rsa_docker"  # host dir not local dir
        clt_remote_dockers.append(
            RemoteDocker(priv_ip, priv_port, pub_ip, host_key, docker_key,
                         logpipe))

    assert len(cf["bnode_addr"]) == 1
    for priv_addr in cf["bnode_addr"]:
        print(priv_addr)
        priv_ip, priv_port = tuple(priv_addr.split(":"))
        pub_ip = mapping_priv2pub_ip[priv_ip]
        host_key = os.path.join(keys_dir, "id_rsa_host")  # local dir
        docker_key = "~/.ssh/id_rsa_docker"  # host dir not local dir
        ss_remote_dockers.append(
            RemoteDocker(priv_ip, priv_port, pub_ip, host_key, docker_key,
                         logpipe))

    # Run docker
    if args.start:
        for remote_docker in ss_remote_dockers:
            remote_docker.start()

        for remote_docker in clt_remote_dockers:
            remote_docker.start(False)

    # Update file in remote docker
    if args.update:
        for remote_docker in ss_remote_dockers:
            remote_docker.copy_dir(config_dir, docker_boomerang_dir)
            remote_docker.copy_file(ss_binary,
                                    os.path.join(docker_boomerang_dir, "build"))
            remote_docker.copy_file(ss_enclave_so,
                                    os.path.join(docker_boomerang_dir, "build"))

        for remote_docker in clt_remote_dockers:
            remote_docker.copy_dir(config_dir, docker_boomerang_dir)
            remote_docker.copy_file(clt_binary,
                                    os.path.join(docker_boomerang_dir, "build"))

    # Run server in remote docker
    if args.run:
        try:
            enclave_worker_thread_num = 4  # TODO
            factor_list = range(10, 21)  # TODO User Number=2^factor
            run_gap = 20  # TODO The gap time between enode and clt start up

            for factor in factor_list:
                user_num = int(math.pow(2, factor))
                round_num = 13  # TODO
                clt_send_recv_parallel_num = 32  # TODO
                ss_recv_parallel_num = 2  # TODO
                config_path = os.path.join(docker_boomerang_dir,
                                           "config/config_single_server.json")

                logging.info(
                    "Start experiment, user_num = 2^{}, round_num = {}, core_num = {}"
                    .format(factor, round_num, enclave_worker_thread_num))

                bnode_id = 0
                for remote_docker in ss_remote_dockers:
                    binary_path = os.path.join(docker_boomerang_dir,
                                               "build/TestSubServer")
                    enclave_path = os.path.join(
                        docker_boomerang_dir,
                        "build/TestSubServerEnclaveLib.signed.so")
                    config_path = os.path.join(
                        docker_boomerang_dir, "config/config_single_server.json")
                    cmd = "{binary} --id {id} -p {parallel_num} -e {enclave_path} -c {config_path} -i eth0 -w {worker_thread_num}".format(
                        binary=binary_path,
                        id=bnode_id,
                        parallel_num=ss_recv_parallel_num,
                        enclave_path=enclave_path,
                        config_path=config_path,
                        worker_thread_num=enclave_worker_thread_num)
                    bnode_id += 1
                    remote_docker.exec_cmd(cmd, False)
                time.sleep(run_gap)

                clt_id = 0
                for remote_docker in clt_remote_dockers:
                    binary_path = os.path.join(docker_boomerang_dir,
                                               "build/TestClient")

                    config_path = os.path.join(
                        docker_boomerang_dir, "config/config_single_server.json")
                    cmd = "{binary} --id {id} -u {user_num} -r {round_num} -p {parallel_num} -c {config_path}".format(
                        binary=binary_path,
                        id=clt_id,
                        user_num=user_num,
                        round_num=round_num,
                        parallel_num=clt_send_recv_parallel_num,
                        config_path=config_path)
                    clt_id += 1
                    remote_docker.exec_cmd(cmd, False)
                # input()
                finish_exp.acquire()

                # Kill server in remote docker
                for remote_docker in ss_remote_dockers:
                    remote_docker.kill("TestSubServer")

                for remote_docker in clt_remote_dockers:
                    remote_docker.kill("TestClient")

                # Kill subprocess in local host
                for sp in local_sub_processes:
                    os.killpg(os.getpgid(sp.pid), signal.SIGTERM)
                    print("Stop local subprocess {}".format(sp.pid))
                local_sub_processes.clear()
        except KeyboardInterrupt:  # for ctrl+c quit
            # Kill server in remote docker
            for remote_docker in ss_remote_dockers:
                remote_docker.kill("TestSubServer")

            for remote_docker in clt_remote_dockers:
                remote_docker.kill("TestClient")

            # Kill subprocess in local host
            for sp in local_sub_processes:
                os.killpg(os.getpgid(sp.pid), signal.SIGTERM)
                print("Stop local subprocess {}".format(sp.pid))
            local_sub_processes.clear()

    # Stop docker
    if args.stop:
        for remote_docker in clt_remote_dockers:
            remote_docker.stop()

        for remote_docker in ss_remote_dockers:
            remote_docker.stop()

    logpipe.close()