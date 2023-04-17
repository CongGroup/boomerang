# SGX library location and finding
list(APPEND CMAKE_MODULE_PATH /opt/intel/sgxsdk)  # the search path of find_package TODO
find_package(SGX REQUIRED)

# Use OpenSSL?
add_compile_options(-D USE_OpenSSLCryptoLib)

# Decopt finding
find_package(docopt COMPONENTS CXX REQUIRED)  # docopt_DIR: /usr/local/lib/cmake/docopt

# Seastar finding
# find_package(Seastar REQUIRED)  # Seastar_DIR: /usr/local/lib/cmake/Seastar

# GRPC and Protocol Buffers libraries location and finding
set(PROTO_INSTALL_DIR "/home/ksolive/code/boomerang/thirdparty/protobuf/cmake/install")  # grpc_path
set(GRPC_INSTALL_DIR "/home/ksolive/code/boomerang/thirdparty/grpc/build/install") # grpc_path
list(APPEND CMAKE_PREFIX_PATH ${PROTO_INSTALL_DIR} ${GRPC_INSTALL_DIR})
find_package(Protobuf REQUIRED)
find_package(gRPC CONFIG REQUIRED)
# GRPC settings
set(_PROTOBUF_PROTOC $<TARGET_FILE:protobuf::protoc>)
set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:gRPC::grpc_cpp_plugin>)
set(_GRPC_GRPCPP gRPC::grpc++)
set(_REFLECTION gRPC::grpc++_reflection)

# lambert lib in app
file(GLOB_RECURSE LAMBERT_SRCS ${CMAKE_SOURCE_DIR}/thirdparty/lambertW/*.h ${CMAKE_SOURCE_DIR}/thirdparty/lambertW/*.cc)  # for lambert lib
add_library(lambert STATIC ${LAMBERT_SRCS})

# crypto lib in app
file(GLOB_RECURSE CRYPTOPP_SRCS ${CMAKE_SOURCE_DIR}/thirdparty/cryptopp/*.h ${CMAKE_SOURCE_DIR}/thirdparty/cryptopp/*.cpp ${CMAKE_SOURCE_DIR}/thirdparty/cryptopp/*.c)
add_library(mycryptopp STATIC ${CRYPTOPP_SRCS})


add_subdirectory(common)
add_subdirectory(client)
add_subdirectory(enode)
add_subdirectory(bnode)
add_subdirectory(test_client)
add_subdirectory(test_bnode)
