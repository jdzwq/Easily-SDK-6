CC = g++
CFLAGS = -g -Wall

FT_PATH = -I /usr/include/freetype2 -I /usr/include/libpng16
LIB_PATH = /usr/local/lib

XDK_PATH = ~/Easily-sdk-6/xdk
INC_PATH = ~/Easily-sdk-6/include
SRC_PATH = ~/Easily-sdk-6/tools/gen_freetype_glyph
OUT_PATH = ~/Easily-app-6/linux/bin

SRCS = $(SRC_PATH)/main.cpp
OBJS = $(patsubst %.cpp, %.o, $(SRCS))
TARGET = $(OUT_PATH)/gen_freetype_glyph

$(SRC_PATH)%.o : $(SRC_PATH)/%.cpp
	$(CC) $(CFLAGS) -c $< -o $@ $(FT_PATH) -I $(INC_PATH) -I $(XDK_PATH)

all : $(OBJS)
	rm -f $@
	$(CC) -o $(TARGET) $(OBJS) -L $(LIB_PATH) -lxdk -lxdg -lfontconfig -lfreetype
	rm -f $(OBJS)

test:
	@echo $(DIRS)
	@echo $(SRCS)
	@echo $(OBJS)

.PHONY : clean
clean:
	-rm -f $(OBJS)
