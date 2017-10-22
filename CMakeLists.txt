cmake_minimum_required(VERSION 2.8) 

set(CMAKE_VERBOSE_MAKEFILE OFF)
set(CMAKE_COLOR_MAKEFILE   ON)

project(myfilter C) # Название проекта
ADD_DEFINITIONS(-O2 -ggdb -Wall -Werror -pedantic --std=gnu99 -Wmissing-declarations)

set(SOURCE_ELF myfilter.c) # Установка переменной со списком исходников для исполняемого файла
add_executable(myfilter ${SOURCE_ELF}) # Создает исполняемый файл с именем main
set_property(TARGET myfilter PROPERTY C_STANDARD 11)

find_library(ubus_library NAMES ubus)
find_library(ubox_library NAMES ubox)
target_link_libraries(myfilter pthread ${ubus_library} ${ubox_library}) # Линковка программы с библиотекой
