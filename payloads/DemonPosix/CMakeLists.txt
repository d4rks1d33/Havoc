cmake_minimum_required(VERSION 3.15)
project(DemonPosix C)

# ── CMakeLists.txt for IDE support (CLion/VSCode) ───────────────────────
# NOTE: The actual build used by the Havoc teamserver goes through the
#       Go builder (builder_posix.go) which invokes gcc/clang directly.
#       This CMakeLists.txt exists purely for IDE indexing and
#       code navigation.

set(CMAKE_C_STANDARD 11)

# ── Platform detection ───────────────────────────────────────────────────
if(APPLE)
    add_definitions(-D__APPLE__)
else()
    add_definitions(-D__linux__)
endif()

# ── C2 config (can be overridden: cmake -DCONFIG_HOST=1.2.3.4 ..) ───────
set(CONFIG_HOST "127.0.0.1" CACHE STRING "C2 listener host")
set(CONFIG_PORT 80           CACHE STRING "C2 listener port")
set(CONFIG_URI  "/"          CACHE STRING "C2 listener URI")
set(CONFIG_SSL  0            CACHE STRING "C2 SSL (0 or 1)")

add_definitions(
    -DCONFIG_HOST=\"${CONFIG_HOST}\"
    -DCONFIG_PORT=${CONFIG_PORT}
    -DCONFIG_URI=\"${CONFIG_URI}\"
    -DCONFIG_SSL=${CONFIG_SSL}
    -DDEBUG
)

# ── Source files ─────────────────────────────────────────────────────────
file(GLOB_RECURSE SOURCES
    "src/core/*.c"
    "src/crypt/*.c"
    "src/inject/*.c"
    "src/main/*.c"
)

include_directories(include)

# ── Find libcurl ─────────────────────────────────────────────────────────
find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIRS})

# ── Executable target ────────────────────────────────────────────────────
add_executable(DemonPosix ${SOURCES})

target_link_libraries(DemonPosix
    ${CURL_LIBRARIES}
    pthread
)

if(APPLE)
    target_link_libraries(DemonPosix "-framework CoreFoundation")
endif()

# ── Compiler flags ───────────────────────────────────────────────────────
target_compile_options(DemonPosix PRIVATE
    -Wall
    -Wno-unused-result
    -Wno-format
    -fPIE
)

set_target_properties(DemonPosix PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
)
