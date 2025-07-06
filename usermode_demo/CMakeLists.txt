# CMakeList.txt : CMake project for usermode, include source and define
# project specific logic here.
#

# Add source to this project's executable.
add_executable (usermode_demo "main.cpp")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET usermode_demo PROPERTY CXX_STANDARD 20)
endif()

# make the target require administrator priveliges
if(MSVC)
    # Embed the manifest file during linking
    set_target_properties(usermode_demo PROPERTIES
        LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
    )
endif()

target_include_directories(usermode_demo
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/csgo_offsets
)

# embed all the dependencies in the target with multi threaded debug runtime.
target_compile_options(usermode_demo PRIVATE /MTd)

# TODO: Add tests and install targets if needed.
