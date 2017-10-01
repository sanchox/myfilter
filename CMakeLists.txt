cmake_minimum_required(VERSION 2.8) 

project(myfilter)			# Название проекта

#set(SOURCE_LIB foo.cpp)			# Тоже самое, но для библиотеки
#add_library(foo STATIC ${SOURCE_LIB})	# Создание статической библиотеки с именем foo

set(SOURCE_ELF myfilter.c)		# Установка переменной со списком исходников для исполняемого файла
add_executable(myfilter ${SOURCE_ELF})	# Создает исполняемый файл с именем main
set_property(TARGET myfilter PROPERTY C_STANDARD 11)

#target_link_libraries(main foo)		# Линковка программы с библиотекой