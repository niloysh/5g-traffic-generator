# Output all binaries to top-level build/ folder
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

set(SOURCES
  gtpu_cbr_generator.c
  gtpu_encapsulator.c
  gtpu_sender_test.c
  pcap_analyzer.c
  gtpu_replay.c
  gtpu_anomaly_injector.c
  gtpu_traffic_generator.c
)

foreach(source_file ${SOURCES})
  get_filename_component(exe ${source_file} NAME_WE)
  add_executable(${exe} ${source_file})
  
  # Default link libraries
  target_link_libraries(${exe} ${PCAP_LIBRARIES})

  if(${exe} MATCHES "gtpu_traffic_generator.*")
    target_link_libraries(${exe} ${JANSSON_LIBRARIES} pthread m)
  elseif(${exe} STREQUAL "gtpu_cbr_generator")
    target_link_libraries(${exe} pthread)
  endif()

  install(TARGETS ${exe} DESTINATION bin)
endforeach()
