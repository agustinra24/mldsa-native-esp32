# ML-DSA-87 basic sign/verify example for ESP32
cmake_minimum_required(VERSION 3.16)

# The component root is two levels up from this example directory.
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../..")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(ml_dsa_example)
