PROJECT(avir_clam)
cmake_minimum_required(VERSION 2.8)
set(Boost_DETAILED_FAILURE_MSG TRUE)
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
set(Boost_ADDITIONAL_VERSIONS "1.48.0")

find_package(Boost ${Boost_ADDITIONAL_VERSIONS} COMPONENTS thread filesystem system date_time regex chrono REQUIRED)

IF (WIN32)
  ADD_DEFINITIONS(-D_WIN32_WINNT=0x0501 -D_CRT_SECURE_NO_WARNINGS)
ENDIF(WIN32)

if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
	INCLUDE_DIRECTORIES("." "../api/")
	ADD_LIBRARY(avir_clam SHARED avPlugin.cpp ClamPlugin.cpp ClamPlugin.hpp avName.h ../api/avPlugin.h ../api/avCommon.h ../api/avCommon.c ../api/avApi.h)
	SET_TARGET_PROPERTIES(avir_clam PROPERTIES PREFIX "" COMPILE_FLAGS "-Wall")
    target_link_libraries(avir_clam ${Boost_LIBRARIES})
endif()

SET_TARGET_PROPERTIES(avir_clam PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
