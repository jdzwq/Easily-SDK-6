CC = clang
CFLAGS = -g -Wall

FT_PATH = -I /opt/homebrew/opt/freetype/include/freetype2
FT_LIBS = -L /opt/homebrew/opt/freetype/lib -lfreetype
LIB_PATH = -L /usr/local/lib -lxdk -lxgc

INC_PATH = -I ~/工程/Easily-sdk-6/include
SRC_PATH = ~/工程/Easily-sdk-6/tools/gen_freetype_glyph
OUT_PATH = ~/工程/Easily-app-6/macos/bin

SRCS = $(SRC_PATH)/main.cpp
OBJS = $(patsubst %.cpp, %.o, $(SRCS))
TARGET = $(OUT_PATH)/gen_freetype_glyph

$(SRC_PATH)%.o : $(SRC_PATH)/%.cpp
	$(CC) $(CFLAGS) -c $< -o $@ $(FT_PATH) $(INC_PATH)

all : $(OBJS)
	rm -f $@
	$(CC) -o $(TARGET) $(OBJS) $(LIB_PATH)  $(FT_LIBS)
#	rm -f $(OBJS)

test:
	@echo $(DIRS)
	@echo $(SRCS)
	@echo $(OBJS)

.PHONY : clean
clean:
	-rm -f $(OBJS)
