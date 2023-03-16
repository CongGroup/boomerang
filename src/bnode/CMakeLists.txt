set(Untrusted_Executable_Name BNode)
set(Enclave_Library_Name BNodeEnclaveLib)
set(OBL_Enclave_Library_Name BNodeOBLEnclaveLib)
set(Cryptopp_Enclave_Library_Name BNodeCryptoppEnclaveLib)

set(SGX_HW ON)  # default: ON
# set(SGX_MODE Release)  # default: PreRelease  Relase would not generate signed.so and metadata error occur
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})

set(EDL_SEARCH_PATHS Enclave /home/ember/Git/linux-sgx/linux-sgx/external/dcap_source/QuoteVerification/sgxssl/Linux/package/include/)

add_compile_options(-fpermissive)

if(SGX_HW AND SGX_MODE STREQUAL "Release")
    set(LDS Enclave/Enclave.lds)
else()
    set(LDS Enclave/Enclave_debug.lds)
endif()

# OBL lib in enclave
file(GLOB_RECURSE OBL_SRCS ${CMAKE_SOURCE_DIR}/thirdparty/rise/*.h ${CMAKE_SOURCE_DIR}/thirdparty/rise/*.cpp ${CMAKE_SOURCE_DIR}/thirdparty/rise/*.hpp)  # for obl lib
add_trusted_library(${OBL_Enclave_Library_Name} USE_SGXSSL SRCS ${OBL_SRCS} EDL Enclave/Enclave.edl EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}) 

# Cryptopp lib in enclave
file(GLOB_RECURSE CRYPTOPP_SRCS ${CMAKE_SOURCE_DIR}/thirdparty/cryptopp/*.h ${CMAKE_SOURCE_DIR}/thirdparty/cryptopp/*.cpp ${CMAKE_SOURCE_DIR}/thirdparty/cryptopp/*.c)
add_trusted_library(${Cryptopp_Enclave_Library_Name} USE_SGXSSL SRCS ${CRYPTOPP_SRCS} EDL Enclave/Enclave.edl EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}) 

# Enclave lib
file(GLOB_RECURSE E_SRCS Enclave/*.h Enclave/*.cpp Enclave/*.hpp Enclave/*.cc)
add_enclave_library(${Enclave_Library_Name} USE_SGXSSL SRCS ${E_SRCS} TRUSTED_LIBS ${OBL_Enclave_Library_Name} ${Cryptopp_Enclave_Library_Name} EDL Enclave/Enclave.edl EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS} LDSCRIPT ${LDS})
enclave_sign(${Enclave_Library_Name} KEY Enclave/Enclave_private.pem CONFIG Enclave/Enclave.config.xml)

target_include_directories(${Enclave_Library_Name} PRIVATE /opt/intel/sgxssl/include)
target_link_directories(${Enclave_Library_Name} PRIVATE /opt/intel/sgxssl/lib64/)
target_link_options(${Enclave_Library_Name} PRIVATE -Wl,--whole-archive -lsgx_tsgxssl -Wl,--no-whole-archive -lsgx_tsgxssl_crypto -lsgx_pthread -include "tsgxsslio.h")

# App execute
file(GLOB_RECURSE SRCS App/*.h App/*.cpp App/*.hpp App/*.cc)
add_untrusted_executable(${Untrusted_Executable_Name} SRCS ${SRCS} EDL Enclave/Enclave.edl EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})
add_dependencies(${Untrusted_Executable_Name} ${Enclave_Library_Name}-sign)

# target_link_libraries(${Untrusted_Executable_Name} -lfmt)

include_directories(${DOCOPT_INCLUDE_DIRS})
target_link_libraries(${Untrusted_Executable_Name} docopt)

# target_link_libraries(${Untrusted_Executable_Name} Seastar::seastar)

include_directories(${PROTOBUF_INCLUDE_DIRS} ${PROTO_GRPC_DIR})  # ${PROTO_GRPC_DIR} is dir of generated *grpc.pb.h
target_link_libraries(${Untrusted_Executable_Name} boomerang_grpc_proto ${_REFLECTION} ${_GRPC_GRPCPP} ${_PROTOBUF_LIBPROTOBUF})

target_link_libraries(${Untrusted_Executable_Name} lambert)

target_link_libraries(${Untrusted_Executable_Name} mycryptopp)
