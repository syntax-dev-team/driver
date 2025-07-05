# CMakeList.txt : CMake project for usermode, include source and define
# project specific logic here.
#

# Add source to this project's executable.
add_executable (usermode "main.cpp")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET usermode PROPERTY CXX_STANDARD 20)
endif()

# make the target require administrator priveliges
if(MSVC)
    # Embed the manifest file during linking
    set_target_properties(usermode PROPERTIES
        LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
    )
endif()

# embed all the dependencies in the target with multi threaded debug runtime.
target_compile_options(usermode PRIVATE /MTd)

# TODO: Add tests and install targets if needed.
