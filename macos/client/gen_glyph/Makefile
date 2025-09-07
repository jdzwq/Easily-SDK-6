CC = clang
CFLAGS = -g -Wall

MODULE = gen_glyph
ARCH = aarch64

FT_PATH = /opt/homebrew/opt/freetype/include/freetype2
FT_LIBS = /opt/homebrew/opt/freetype/lib -lfreetype
LIB_PATH = /usr/local/lib

INC_PATH = ~/工程/Easily-sdk-6/include
SRC_PATH = ~/工程/Easily-sdk-6/client/gen_glyph
OBJ_PATH = ~/工程/Easily-tmp/macos/$(MODULE)/$(ARCH)
OUT_PATH = ~/工程/Easily-app-6/macos/bin

DIRS = $(wildcard $(SRC_PATH)/gen_freetype.cc)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.cc, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/%.cc
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

.PHONY : clean
clean:
	rm -f $(OBJS)
	rm -f $(OUT_PATH)/$(MODULE)
