#!/usr/bin/make -f
SHELL = bash

SOURCES  := src
INCLUDES := src/elfio src
OUTPUT   := elf2dll

FLAGS    := -O3 -Wall
CFLAGS    = $(FLAGS) -std=gnu11
CXXFLAGS  = $(FLAGS) -std=gnu++11

ifeq ($(OS),Windows_NT)
	OUTBIN := $(OUTPUT).exe
else
	OUTBIN := $(OUTPUT)
endif

CFILES   := $(foreach dir,$(SOURCES),$(wildcard $(dir)/*.c))
CXXFILES := $(foreach dir,$(SOURCES),$(wildcard $(dir)/*.cpp))


OFILES   := $(foreach file,$(CFILES),$(file:.c=.o)) \
            $(foreach file,$(CXXFILES),$(file:.cpp=.o))

INCLUDE_FLAGS := $(foreach dir,$(INCLUDES),-I"$(dir)")
CFLAGS        += $(INCLUDE_FLAGS)
CXXFLAGS      += $(INCLUDE_FLAGS)

.DEFAULT_GOAL := all
.PHONY: all
all: $(OUTBIN)

.PHONY: clean
clean:
	@rm -rf $(OUTBIN) $(OFILES)

$(OUTBIN): $(OFILES)
	@echo -e "LD\t$@"
	@$(CXX) -o $(OUTPUT) $(OFILES) $(LIBS)

%.o: %.c
	@echo -e "CC\t$<"
	@$(COMPILE.c) $(OUTPUT_OPTION) $<

%.o: %.cpp
	@echo -e "CXX\t$<"
	@$(COMPILE.cpp) $(OUTPUT_OPTION) $<
