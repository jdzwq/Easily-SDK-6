CC = g++
CFLAGS = -g -Wall

LIB_PATH = /usr/local/lib
INC_PATH = ~/Easily-sdk-6/include
SRC_PATH = ~/Easily-sdk-6/test/xdb_lib_test
OBJ_PATH = ~/Easily-sdk-6/test/xdb_lib_test
OUT_PATH = ~/Easily-app-6/linux/bin

SRCS = $(SRC_PATH)/main.cpp
OBJS = $(patsubst %.cpp, %.o, $(SRCS))
TARGET = $(OUT_PATH)/xdb_lib_test

$(OBJ_PATH)/%.o : $(SRC_PATH)/%.cpp
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

all : $(OBJS)
	rm -f $@
	$(CC) -o $(TARGET) $(OBJS) -L $(LIB_PATH) -lxdk -lxdl
	rm -f $(OBJS)

test:
	@echo $(SRCS)
	@echo $(OBJS)

.PHONY : clean
clean:
	-rm -f $(OBJS)
