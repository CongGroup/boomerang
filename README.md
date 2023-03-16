# 1. Installation

<details>
  <summary>Prerequisites</summary>

<!--TODO: Precise OS versions-->

- Operating systems
  - Ubuntu 18.04
- Compute backends
  - Intel CPU with SGX support
   </details>

## 1.1 Complete Compilation Environment Installation
### Foundation
```
sudo apt install -y dkms
sudo apt install -y build-essential ocaml ocamlbuild automake autoconf libtool wget python libssl-dev git cmake perl
```

### SGX Driver & SGX PSW & SGX SDK

```
# SGX Driver
wget https://download.01.org/intel-sgx/sgx-linux/2.16/distro/ubuntu18.04-server/sgx_linux_x64_driver_1.41.bin
sudo chmod 777 ./sgx_linux_x64_driver_1.41.bin
sudo ./sgx_linux_x64_driver_1.41.bin
sudo rm ./sgx_linux_x64_driver_1.41.bin

# SGX PSW
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main'| tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
sudo apt update
sudo apt install -y libsgx-launch libsgx-urts
sudo apt install -y libsgx-epid libsgx-urts
sudo apt install -y libsgx-quote-ex libsgx-urts

# SGX SDK
wget https://download.01.org/intel-sgx/sgx-linux/2.16/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.16.100.4.bin
sudo chmod 777 ./sgx_linux_x64_sdk_2.16.100.4.bin
sudo ./sgx_linux_x64_sdk_2.16.100.4.bin
sudo rm ./sgx_linux_x64_sdk_2.16.100.4.bin

echo "source /opt/intel/sgxsdk/environment" >> ~/.bashrc
```

Modify `CMAKE_MODULE_PATH` in `src/CMakeLists.txt` according to the actual installation position of SGX SDK, default is `/opt/intel/sgxsdk`.

### docopt (Option Parser)
```
wget https://github.com/docopt/docopt.cpp/archive/refs/tags/v0.6.3.tar.gz\
tar -zxf ./v0.6.3.tar.gz\
cd ./docopt.cpp-0.6.3/\
cmake .\
make install
```

### gRPC & Protocol Buffer
Ref to (link)[https://grpc.io/docs/languages/cpp/quickstart/]
Please reset `PROTO_INSTALL_DIR` and `GRPC_INSTALL_DIR` in `src/CMakeLists.txt` by the actual installation position.


## 1.2 Minimum Executable Environment Installation
```
cd scripts/  # work dir is limited to scripts 
python3 batch_process.py --install-key  # generate batch_process.sh for batch installation of ssh keys
sudo chmod 777 ./batch_process.sh
./batch_process.sh  # enter passwd manually
python3 batch_process.py --install-dep  # install minimum executable environment on all remote servers, no need for passwd
```
Installations on all remote servers are parallelized according to `/config/config_multi_server.json`, all IPs in `nat` are included.


# 2. Local Run Guide

If you only test the system locally, you need to install [Complete Compilation Environment](#11-complete-compilation-environment-installation) on the **local machine**.

Compile all binaries.

```python
mkdir build; cd build; cmake ..
make all
```

Run B Node, Entry Node and Client according to the configuration file `/config/config_local.json`.

```
cd scripts/
./run_bnode.sh
./run_enode.sh
./run_client.sh
```

# 3. Multi-server Deployment Guide

Install [Complete Compilation Environment](#11-complete-compilation-environment-installation) on the **local machine** and install [Minimum Executable Environment](#12-minimum-executable-environment-installation) on multi **remote servers**. Larger number of supported users requires modification of configuration files `/src/bnode/Enclave/Enclave.config.xml` and `/src/enode/Enclave/Enclave.config.xml`.

Compile all binaries on the **local machine** with the complete compilation environment.

```python
mkdir build; cd build; cmake ..
make all
```

Modify `/config/config_multi_server.json` file. Format shows as below. `port` is recommended to be a number larger than 1024 and be successive in the same machine.

```python
clt_addr: {
    private ip:port
}
enode_addr: {
    private ip:port
}
bnode_addr: {
    private ip:port
}
nat: {
    private ip:public ip
}
```

Run remote dockers on **remote servers** by the config file.

```python
cd scripts/  # work dir is limited to scripts 
python3 run.py --start
```

Copy binaries and config files to remote dockers on **remote servers**.

```python
python3 run.py --update
```

Run binary on remote dockers by sequence.

```python
python3 run.py --run
```

Stop all dockers safely.

```python
python3 run.py --stop
```

All parameters in `/scripts/run.py` that can be modified are marked as TODO.

# 4. Extra Detail
`/src/client /src/enode /src/bnode /src/common` : all files related to the multi-servers Boomerang+.

`/src/test_client /src/test_bnode /src/common` : all files related to the single-server Boomerang.

`/scripts/run.py ` : scripts for running the multi-servers Boomerang+ on remote servers.

`/scripts/run_test.py ` : scripts for running the Boomerang on remote servers.

`/run_client.sh /run_enode.sh /run_bnode.sh` : for testing Boomerang+ on the local.

`/run_test_client.sh /run_test_bnode.sh` : for testting Boomerang on the local.


If you need to test the network latency, please find the `TEST_NETWORK_LATENCY` variables in this project and assign them to `True`, the default values are `False`.
If you need to modify the package size, please modify `PKT_SIZE` in `/src/common/ds.hpp`, the default is 256.
If you need to modify the mac size, please modify `MAC_SIZE` in `/src/common/ds.hpp`, the default is 16.