cmake_minimum_required(VERSION 3.0)
set(CMAKE_VERBOSE_MAKEFILE ON)
project(sprav-vrac)

# Paths for liboqs
include(ExternalProject)
set(liboqs_root_dir    "${CMAKE_CURRENT_LIST_DIR}/liboqs")
set(liboqs_build_dir   "${liboqs_root_dir}/build")

set(liboqs_lib_dir     "${liboqs_root_dir}/build/lib")
set(liboqs_include_dir "${liboqs_root_dir}/build/include")

# Create build folder for liboqs
file(MAKE_DIRECTORY ${liboqs_include_dir})

# Build liboqs
execute_process(COMMAND cmake ../ -GNinja -DOQS_BUILD_ONLY_LIB=ON -DOQS_ALGS_ENABLED="STD" -DOQS_USE_OPENSSL=OFF WORKING_DIRECTORY ${liboqs_build_dir})
execute_process(COMMAND ninja WORKING_DIRECTORY ${liboqs_build_dir})

# Add liboqs as library
add_library(liboqs STATIC IMPORTED)
set_target_properties(liboqs PROPERTIES IMPORTED_LOCATION ${liboqs_lib_dir}/liboqs.a)

# Add main executable
add_executable(sprav-vrac vrac.c)
target_include_directories(sprav-vrac PRIVATE ${liboqs_include_dir})
target_link_libraries(sprav-vrac PRIVATE liboqs)
