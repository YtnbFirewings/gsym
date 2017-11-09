cmake_minimum_required(VERSION 3.2)
set (CMAKE_CXX_STANDARD 11)
project(gsym)

add_library(
  gsym_common
  STATIC
  gsym/DataDecoder.cpp
  gsym/FileTableCreator.cpp
  gsym/FileWriter.cpp
  gsym/MemoryMappedFile.cpp
  gsym/gsym.cpp
  gsym/gsym_elf.cpp
  gsym/gsym_macho.cpp)


#----------------------------------------------------------------------
# gsymutil executable
#----------------------------------------------------------------------
add_executable(
  gsymutil
  gsym/main.cpp)

target_link_libraries(
	gsymutil
  gsym_common)

#----------------------------------------------------------------------
# bpad2gsym executable
#----------------------------------------------------------------------
add_executable(
	bpad2gsym
  bpadtogsym/main.cpp)

target_include_directories(
  bpad2gsym
  SYSTEM
  PUBLIC gsym)

target_link_libraries(
	bpad2gsym
  gsym_common)

