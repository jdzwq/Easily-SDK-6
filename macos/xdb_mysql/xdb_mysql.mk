#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order for debug version:
# 1. make -f xdb_mysql.mk test --if need to creating some directory or file-list
# 2. make -f xdb_mysql.mk clean
# 3. make -f xdb_mysql.mk
# 4. make -f xdb_mysql.mk install
#-----------------------------------------------------------------------------
CC = clang
CFLAGS = -g -Wall -fPIC -D _DEBUG

MODULE = xdb_mysql
ARCH = aarch64
MAJ_VER = 6
CUR_VER = 6

INC_MYSQL = /opt/homebrew/opt/mysql-client/include/mysql
LIB_MYSQL = /opt/homebrew/opt/mysql-client/lib

LIB_PATH = /usr/local/lib

INC_PATH = ../../include
SRC_PATH = ../../xdb

OBJ_PATH = ~/工程/Easily-temp/macos/$(MODULE)/$(ARCH)
OUT_PATH = ~/工程/Easily-app-6/macos/lib

TARGET = lib$(MODULE).$(CUR_VER).dylib
LINKIT = lib$(MODULE).dylib

LIBS = -lxdk -lxdg -lxdl -L $(LIB_MYSQL) -lmysqlclient
DIRS = $(wildcard $(SRC_PATH)/mysql/*.c)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.c, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/mysql/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH) -I $(INC_MYSQL)

all : $(OBJS)
	rm -f $@
	$(CC) -dynamiclib -fPIC -pthread \
	-o $(OBJ_PATH)/$(TARGET) $(OBJS) $(LIBS) \
	-Wl,-install_name,@rpath/$(LINKIT) \
	-current_version $(CUR_VER) \
	-compatibility_version $(MAJ_VER)

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