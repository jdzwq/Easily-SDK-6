#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order for release version:
# 1. make test
# 2. make clean
# 3. make all
# 4. make install
#-----------------------------------------------------------------------------
CC = clang
CFLAGS = -g -Wall

MODULE = gen_glyph
ARCH = aarch64

FT_PATH = /opt/homebrew/opt/freetype/include/freetype2
FT_LIBS = /opt/homebrew/opt/freetype/lib -lfreetype

LIB_PATH = /usr/local/lib
CLI_PATH = /usr/local/Easily/bin

INC_PATH = ../../../include
SRC_PATH = ../../../client

OBJ_PATH = ~/工程/Easily-temp/macos/$(MODULE)/$(ARCH)

DIRS = $(wildcard $(SRC_PATH)/gen_glyph/gen_freetype.cc)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.cc, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/gen_glyph/%.cc
	$(CC) $(CFLAGS) -c $< -o $@ -I $(FT_PATH) -I $(INC_PATH)

all : $(OBJS)
	rm -f $@
	$(CC) -o $(OUT_PATH)/$(MODULE) $(OBJS) -L $(LIB_PATH) -lxdk -lxdg -L $(FT_LIBS) \
	-Wl,-rpath $(LIB_PATH)

test:
	if ! test -d $(OBJ_PATH); then \
	mkdir -p $(OBJ_PATH); \
	chmod 755 $(OBJ_PATH); \
	fi
	@echo $(DIRS)
	@echo $(SRCS)
	@echo $(OBJS)

install:
	if ! test -d $(CLI_PATH); then \
	sudo mkdir $(CLI_PATH); \
	fi

	sudo cp -f $(OBJ_PATH)/$(MODULE) $(CLI_PATH);
	sudo chmod +x $(CLI_PATH)/$(MODULE);

uninstall:
	sudo rm -f $(CLI_PATH)/$(MODULE)

.PHONY : clean
clean:
	rm -f $(OBJS)
	rm -f $(OUT_PATH)/$(MODULE)
