# CMakeList.txt : CMake project for usermode, include source and define
# project specific logic here.
#



# find findwdk
find_package(Wdk REQUIRED)

# create a driver using source
wdk_add_driver(
	syntaxdriver
	KMDF 1.15
	main.cpp
)

target_compile_options(your_target PRIVATE "/GS-")


# settings language standard
set_target_properties(syntaxdriver PROPERTIES
    CXX_STANDARD 20
    LINK_FLAGS "/ENTRY:DriverEntry"
)



