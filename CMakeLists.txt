cmake_minimum_required(VERSION 3.11)
project(Boomerang)

SET(CMAKE_BUILD_TYPE "Release")
# SET(CMAKE_BUILD_TYPE "Debug")

set(CMAKE_VERBOSE_MAKEFILEON ON)  # print cmd

# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")  # No std==11
# set(CMAKE_CXX_STANDARD 11)  # No std==11
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")  # necessary!
# set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")  # ???
# set(CMAKE_CXX_FLAGS_DEBUG "-gstabs -gstabs+")  # for debugging program
# add_definitions( -DUSE_AVX2=1 )
# include_directories(thirdparty/rise)

add_subdirectory(src)
