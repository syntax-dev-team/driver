# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.8)


# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("syntax_open_source_driver")

# sort out build configurations
foreach(OUTPUTCONFIG rebug release relwithdebinfo minsizerel)
    string(TOUPPER "${OUTPUTCONFIG}" OUTPUTCONFIG_UPPER)


    if (NOT DEFINED ARCHITECTURE)
        if (CMAKE_SIZEOF_VOID_P GREATER 4)
            set(ARCHITECTURE x64)
        else()
            set(ARCHITECTURE x32)
        endif()
    endif()
    
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${OUTPUTCONFIG_UPPER} "${CMAKE_SOURCE_DIR}/bin/${OUTPUTCONFIG}_${ARCHITECTURE}")
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${OUTPUTCONFIG_UPPER} "${CMAKE_SOURCE_DIR}/bin/${OUTPUTCONFIG}_${ARCHITECTURE}")
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${OUTPUTCONFIG_UPPER} "${CMAKE_SOURCE_DIR}/lib/${OUTPUTCONFIG}_${ARCHITECTURE}")
endforeach()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")


# Include sub-projects.
add_subdirectory("kernelmode")
add_subdirectory ("usermode_demo")
