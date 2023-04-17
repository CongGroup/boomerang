# Proto file
get_filename_component(PROTOS "${CMAKE_CURRENT_SOURCE_DIR}/boomerang.proto" ABSOLUTE)
get_filename_component(PROTOS_PATH "${PROTOS}" PATH)

# Generated sources
set(PROTO_HDRS "${CMAKE_CURRENT_BINARY_DIR}/boomerang.pb.h")
set(PROTO_SRCS "${CMAKE_CURRENT_BINARY_DIR}/boomerang.pb.cc")
set(GRPC_SRCS "${CMAKE_CURRENT_BINARY_DIR}/boomerang.grpc.pb.cc")
set(GRPC_HDRS "${CMAKE_CURRENT_BINARY_DIR}/boomerang.grpc.pb.h")
add_custom_command(
      OUTPUT "${PROTO_SRCS}" "${PROTO_HDRS}" "${GRPC_SRCS}" "${GRPC_HDRS}"
      COMMAND ${_PROTOBUF_PROTOC}
      ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
        --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${PROTOS_PATH}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${PROTOS}"
      DEPENDS "${PROTOS}")
# set(PROTO_SRCS ${PROTO_SRCS} PARENT_SCOPE)
# set(PROTO_HDRS ${PROTO_HDRS} PARENT_SCOPE)
# set(GRPC_SRCS ${GRPC_SRCS} PARENT_SCOPE)
# set(GRPC_HDRS ${GRPC_HDRS} PARENT_SCOPE)
set(PROTO_GRPC_DIR "${CMAKE_CURRENT_BINARY_DIR}" PARENT_SCOPE)  # PARENT_SCOPE for delivering the variable to the parent layer
add_custom_target(protos DEPENDS ${PROTO_SRCS} ${PROTO_HDRS} ${GRPC_HDRS} ${GRPC_SRCS})

# Include generated *.pb.h files
include_directories("${CMAKE_CURRENT_BINARY_DIR}")

add_library(boomerang_grpc_proto
    ${PROTO_SRCS}
    ${PROTO_HDRS}
    ${GRPC_HDRS}
    ${GRPC_SRCS})

target_link_libraries(boomerang_grpc_proto
    ${_REFLECTION}
    ${_GRPC_GRPCPP}
    ${_PROTOBUF_LIBPROTOBUF})

# # Targets route_guide_(client|server)
# foreach(_target
#   route_guide_client route_guide_server)
#   add_executable(${_target}
#     "${_target}.cc")
#   target_link_libraries(${_target}
#     boomerang_grpc_proto
#     route_guide_helper
#     ${_REFLECTION}
#     ${_GRPC_GRPCPP}
#     ${_PROTOBUF_LIBPROTOBUF})
# endforeach()