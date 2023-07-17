#
# Copyright (C) 2023 The Falco Authors.
#
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

NAME    := $(notdir $(CURDIR))
OUTPUT  := $(NAME).out

PLUGIN_EXTRACT_DIR := ../plugin_extract
PLUGIN_SOURCE_DIR := ../plugin_source

SDK_DIR := ../..
SDK_INCLUDE := $(SDK_DIR)/include/
CXX_FLAGS := -std=c++0x -Wall -Wl,-s -fPIC -I$(SDK_INCLUDE)

all: $(OUTPUT)

clean:
	+rm -rf $(OUTPUT) *.a *.o

$(OUTPUT): libplugin-source.a libplugin-extract.a *.cpp
	+$(CXX) $(CXX_FLAGS) -o $(OUTPUT) ./main.cpp ./libplugin-extract.a ./libplugin-source.a 

libplugin-source.a: $(PLUGIN_SOURCE_DIR)/*.cpp
	+$(CXX) -c $(CXX_FLAGS) -static -DFALCOSECURITY_STATIC=source_ -o ./libplugin-source.o $(CXX_FLAGS) $(PLUGIN_SOURCE_DIR)/*.cpp
	+$(AR) rcs ./libplugin-source.a ./libplugin-source.o

libplugin-extract.a: $(PLUGIN_EXTRACT_DIR)/*.cpp
	+$(CXX) -c $(CXX_FLAGS) -static -DFALCOSECURITY_STATIC=extract_ -o ./libplugin-extract.o $(CXX_FLAGS) $(PLUGIN_EXTRACT_DIR)/*.cpp
	+$(AR) rcs ./libplugin-extract.a ./libplugin-extract.o


