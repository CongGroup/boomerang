set(Executable_Name TestClient)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})

add_compile_options(-fpermissive)

file(GLOB_RECURSE SRCS App/*.h App/*.cpp App/*.hpp App/*.cc)

add_executable(${Executable_Name} ${SRCS})

# target_link_libraries(${Executable_Name} -lfmt)

include_directories(${DOCOPT_INCLUDE_DIRS})
target_link_libraries(${Executable_Name} docopt)

# target_link_libraries(${Executable_Name} Seastar::seastar)

include_directories(${PROTOBUF_INCLUDE_DIRS} ${PROTO_GRPC_DIR})  # ${PROTO_GRPC_DIR} is dir of generated *grpc.pb.h
target_link_libraries(${Executable_Name} boomerang_grpc_proto ${_REFLECTION} ${_GRPC_GRPCPP} ${_PROTOBUF_LIBPROTOBUF})

target_link_libraries(${Executable_Name} lambert)

target_link_libraries(${Executable_Name} mycryptopp)

target_include_directories(${Executable_Name} PRIVATE /opt/intel/sgxssl/include)
target_link_directories(${Executable_Name} PRIVATE /opt/intel/sgxssl/lib64/)
target_link_libraries(${Executable_Name} sgx_usgxssl)