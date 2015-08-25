ADD_DEFINITIONS(-D_GNU_SOURCE)

list(APPEND CMAKE_REQUIRED_DEFINITIONS '-D_GNU_SOURCE')

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${L3ROAMD_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR})

add_executable(l3roamd main.c intercom.c tun.c icmp6.c routes.c vector.c linkedlist.c)

set_target_properties(l3roamd PROPERTIES COMPILE_FLAGS "-std=c99 -Wall" LINK_FLAGS "")

install(TARGETS l3roamd RUNTIME DESTINATION bin)
