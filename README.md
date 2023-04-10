# 1. Installation

<details>
  <summary>Prerequisites</summary>

<!--TODO: Precise OS versions-->

- Operating systems
  - Ubuntu 18.04
  - gcc 7.50 (not change)
  - cmake 3.26.3 (snap install cmake --classic)
  - make 4.1 (not change)
  - openssl 1.1.1t (sgxssl requires)
- Compute backends
  - Intel CPU with SGX support
   </details>

## 1.1 Complete Compilation Environment Installation
### Foundation
```
sudo apt install -y dkms
sudo apt install -y build-essential ocaml ocamlbuild automake autoconf libtool wget python libssl-dev git cmake perl
```
***
### SGX Driver & SGX PSW & SGX SDK & SGX SSL
* linux sgx: 2.16
* sgx driver: 1.41
* sgx sdk: 2.16
* sgx psw: no version
* sgx ssl: linux-2.16-1.1.1m (https://github.com/intel/intel-sgx-ssl/archive/refs/tags/lin_2.16_1.1.1m_update.zip)
* openssl: 1.1.1m
#### test if SGX is supported
```
git clone https://github.com/ayeks/SGX-hardware.git
cd SGX-hardware
gcc test-sgx.c -o test-sgx
./test-sgx
```
the output should be like this
```
...
Extended feature bits (EAX=07H, ECX=0H)
eax: 0 ebx: 29c6fbf ecx: 0 edx: 0
sgx available: 1

CPUID Leaf 12H, Sub-Leaf 0 of Intel SGX Capabilities (EAX=12H,ECX=0)
eax: 1 ebx: 0 ecx: 0 edx: 241f
sgx 1 supported: 1
sgx 2 supported: 0
...
```

or you can check using "cpuid -1 | grep -i sgx"
the output should be like this, note that the first two lines must be true, and at least one of the last two lines needs to be true.
```
  SGX: Software Guard Extensions supported = true
  SGX_LC: SGX launch config supported      = true
  SGX capability (0x12/0):
  SGX1 supported                         = true
  SGX2 supported                         = false
  SGX attributes (0x12/1):
```
if supported, install all SGX tools in /opt/intel:
```
sudo mkdir -p /opt/intel
cd /opt/intel
```
**!!! WARNING: Do not try to change the installation path, some variables are hard-coded in the code !!!**

#### SGX Driver
```
sudo wget https://download.01.org/intel-sgx/sgx-linux/2.16/distro/ubuntu18.04-server/sgx_linux_x64_driver_1.41.bin
sudo chmod 777 ./sgx_linux_x64_driver_1.41.bin
sudo ./sgx_linux_x64_driver_1.41.bin
```
#### SGX PSW
```
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main'| sudo tee /etc/apt/sources.list.d/intel-sgx.list
sudo su
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
su <username>
sudo apt update
sudo apt install -y libsgx-launch libsgx-urts
sudo apt install -y libsgx-epid libsgx-urts
sudo apt install -y libsgx-quote-ex libsgx-urts
```
#### SGX SDK
```
sudo wget https://download.01.org/intel-sgx/sgx-linux/2.16/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.16.100.4.bin
sudo chmod 777 ./sgx_linux_x64_sdk_2.16.100.4.bin
sudo ./sgx_linux_x64_sdk_2.16.100.4.bin
```
choose "no" and change the install path to "/opt/intel"
**!!! warning: install path must be "/opt/intel" !!!**
```
echo "source /opt/intel/sgxsdk/environment" >> ~/.bashrc
source ~/.bashrc
```
You can find sample code for testing from /opt/intel/sgxsdk/SampleCode/SampleEnclave
```
pushd /opt/intel/sgxsdk/SampleCode/SampleEnclave
sudo make
./app
popd
```
the output should be like:
```
Checksum(0x0x7ffed9a2bb00, 100) = 0xfffd4143
Info: executing thread synchronization, please wait...  
Info: SampleEnclave successfully returned.
Enter a character before exit ...
```
from boomerang copy FindSGXSDK.cmake to /opt/intel/sgxsdk/
```
cp <CodePath>/boomerang/FindSGXSDK.cmake /opt/intel/sgxsdk/
```
#### SGX SSL
install ToolChain
```
sudo wget https://download.01.org/intel-sgx/sgx-linux/2.16/as.ld.objdump.r4.tar.gz
sudo tar -zxf ./as.ld.objdump.r4.tar.gz
sudo cp external/toolset/ubuntu18.04/* /usr/local/bin/
which ar  as  ld  objcopy  objdump  ranlib
```
ought to be all in /usr/local/bin
```
sudo wget https://github.com/intel/intel-sgx-ssl/archive/refs/tags/lin_2.16_1.1.1m_update.zip
sudo unzip lin_2.16_1.1.1m_update.zip
pushd intel-sgx-ssl-lin_2.16_1.1.1m_update/openssl_source
sudo wget https://openssl.org/source/openssl-1.1.1m.tar.gz
popd
pushd intel-sgx-ssl-lin_2.16_1.1.1m_update/Linux
sudo make all test
sudo make install
popd
```
*If you insist on changing the location of the sgx family installation, look for the location marked # change_sgx_path in the code and change it to the corresponding value by referring to the normal location.*
**!!! WARNING: Changing the installation location has not been successfully tested !!!**

***
Recommended for subsequent installations in boomerang/thirdparty

***

### docopt (Option Parser)

```
wget https://github.com/docopt/docopt.cpp/archive/refs/tags/v0.6.3.tar.gz
tar -zxf ./v0.6.3.tar.gz
pushd ./docopt.cpp-0.6.3/
cmake .
sudo make install
popd
```
***

### gRPC & Protocol Buffer
```
cd thirdparty
git submodule update --init
```
Protobuf:
```
sudo apt-get install build-essential autoconf libtool pkg-config automake zlib1g-dev
pushd protobuf/cmake
mkdir build
pushd build
cmake -Dprotobuf_BUILD_TESTS=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=`pwd`/../install ..
make -j `nproc`
make install
popd
popd
```
gRPC:
```
pushd grpc
git submodule update --init
mkdir build
pushd build
cmake -DCMAKE_PREFIX_PATH=`pwd`/../../protobuf/cmake/install -DgRPC_INSTALL=ON -DgRPC_BUILD_TESTS=OFF \
      -DgRPC_PROTOBUF_PROVIDER=package -DgRPC_ZLIB_PROVIDER=package -DgRPC_CARES_PROVIDER=module -DgRPC_SSL_PROVIDER=package \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=`pwd`/install \
      ../
make
make install
popd
popd
```
Please reset `PROTO_INSTALL_DIR` and `GRPC_INSTALL_DIR` in `src/CMakeLists.txt` by the actual installation position. They are marked as # grpc_path


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
