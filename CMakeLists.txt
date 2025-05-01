cmake_minimum_required(VERSION 3.15)
project(5g_traffic_generator)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic")

# Enable export of compile commands for clangd
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find and configure libpcap
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(${PCAP_INCLUDE_DIRS})
link_directories(${PCAP_LIBRARY_DIRS})

# Source files
set(SOURCES
    src/gtpu_cbr_generator.c
    src/gtpu_encapsulator.c
    src/gtpu_sender_test.c
    src/pcap_analyzer.c
)

# Executable for gtpu_cbr_generator
add_executable(gtpu_cbr_generator src/gtpu_cbr_generator.c)
target_link_libraries(gtpu_cbr_generator ${PCAP_LIBRARIES} pthread)
install(TARGETS gtpu_cbr_generator DESTINATION bin)

# Executable for gtpu_encapsulator
add_executable(gtpu_encapsulator src/gtpu_encapsulator.c)
target_link_libraries(gtpu_encapsulator ${PCAP_LIBRARIES})
install(TARGETS gtpu_encapsulator DESTINATION bin)

# Executable for gtpu_sender_test
add_executable(gtpu_sender_test src/gtpu_sender_test.c)
target_link_libraries(gtpu_sender_test)
install(TARGETS gtpu_sender_test DESTINATION bin)

# Executable for pcap_analyzer
add_executable(pcap_analyzer src/pcap_analyzer.c)
target_link_libraries(pcap_analyzer ${PCAP_LIBRARIES})
install(TARGETS pcap_analyzer DESTINATION bin)

# Executable for gtpu_replay
add_executable(gtpu_replay src/gtpu_replay.c)
target_link_libraries(gtpu_replay ${PCAP_LIBRARIES})
install(TARGETS gtpu_replay DESTINATION bin)
