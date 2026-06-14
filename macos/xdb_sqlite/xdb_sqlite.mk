#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order for debug version:
# 1. make -f xdb_sqlite.mk test --if need to creating some directory or file-list
# 2. make -f xdb_sqlite.mk clean
# 3. make -f xdb_sqlite.mk
# 4. make -f xdb_sqlite.mk install
#-----------------------------------------------------------------------------
CC = clang
CFLAGS = -g -Wall -fPIC -D _DEBUG

MODULE = xdb_sqlite
ARCH = aarch64
CUR_VER = 6
MAX_VER = 1
MIN_VER = 0

INC_SQLITE = /opt/homebrew/opt/sqlite/include
LIB_SQLITE = /opt/homebrew/opt/sqlite/lib

LIB_PATH = /usr/local/lib

INC_PATH = ../../include
SRC_PATH = ../../xdb

OBJ_PATH = ~/工程/Easily-temp/macos/$(MODULE)/$(ARCH)
OUT_PATH = ~/工程/Easily-app-6/macos/lib/$(ARCH)

TARGET = lib$(MODULE).dylib.$(CUR_VER).$(MAX_VER).$(MIN_VER).$(ARCH)
LINKIT = lib$(MODULE).dylib

LIBS = -lxdk -lxdg -lxdl -L $(LIB_SQLITE) -lsqlite3
DIRS = $(wildcard $(SRC_PATH)/sqlite/*.c)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.c, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/sqlite/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH) -I $(INC_SQLITE)

all : $(OBJS)
	rm -f $@
	$(CC) -dynamiclib -fPIC -pthread \
	-o $(OBJ_PATH)/$(TARGET) $(OBJS) $(LIBS) \
	-Wl,-install_name,@rpath/$(LINKIT) \
	-current_version $(CUR_VER) \
	-compatibility_version $(MAX_VER)

test:
	if ! test -d $(OBJ_PATH); then \
	mkdir -p $(OBJ_PATH); \
	chmod 755 $(OBJ_PATH); \
	fi

	@echo $(DIRS)
	@echo $(SRCS)
	@echo $(OBJS)

install:
	if ! test -d $(OUT_PATH); then \
	sudo mkdir -p $(OUT_PATH); \
	fi

	sudo cp -f $(OBJ_PATH)/$(TARGET) $(OUT_PATH);
	sudo chmod 755 $(OUT_PATH)/$(TARGET);
	sudo rm -f $(LIB_PATH)/$(LINKIT);
	sudo ln -s $(OUT_PATH)/$(TARGET) $(LIB_PATH)/$(LINKIT);

uninstall:
	sudo rm -r $(LIB_PATH)/$(LINKIT);
	sudo rm -f $(OUT_PATH)/$(TARGET)
	
.PHONY : clean
clean:
	rm -f $(OBJS)
	rm -f $(OBJ_PATH)/$(TARGET)
#-----------------------------------------------------------------------------
# end GNU MAKE file
#-----------------------------------------------------------------------------