#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order:
# 1. make -f xdb_mysql.so.mk test --if need to creating some directory or file-list
# 2. make -f xdb_mysql.so.mk clean
# 3. make -f xdb_mysql.so.mk
# 4. make -f xdb_mysql.so.mk install
#-----------------------------------------------------------------------------
CC = clang
CFLAGS = -g -Wall -fPIC -D _DEBUG

MODULE = xdb_mysql
ARCH = aarch64
MAJ_VER = 6.0.0
CUR_VER = 6.0.0

SRV_PATH = /usr/local/xService
LNK_PATH = /usr/local/lib

INC_MYSQL = /opt/homebrew/opt/mysql-client/include/mysql
LIB_MYSQL = /opt/homebrew/opt/mysql-client/lib

INC_PATH = ../../include
SRC_PATH = ../../xdb
OUT_PATH = ../../../Easily-app-6/macos/sbin/api
OBJ_PATH = ../../../Easily-tmp/macos/$(MODULE)/$(ARCH)

TARGET = lib$(MODULE).$(CUR_VER).dylib
LINKIT = lib$(MODULE).dylib

LIBS = -lxdk -lxdg -lxdl -L $(LIB_MYSQL) -lmysqlclient
DIRS = $(wildcard $(SRC_PATH)/xdb_mysql.c)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.c, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/xdb_mysql.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH) -I $(INC_MYSQL)

all : $(OBJS)
	rm -f $@
	$(CC) -dynamiclib -fPIC -pthread \
	-o $(OUT_PATH)/$(TARGET) $(OBJS) $(LIBS) \
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
	if ! test -d $(SRV_PATH)/api; then \
	sudo mkdir -p $(SRV_PATH)/api; \
	fi
	if ! test -d $(LNK_PATH); then \
	sudo mkdir $(LNK_PATH); \
	fi

	sudo cp -f $(OUT_PATH)/$(TARGET) $(SRV_PATH)/api;
	sudo chmod 755 $(SRV_PATH)/api/$(TARGET);
	sudo rm -f $(LNK_PATH)/$(LINKIT);
	sudo ln -s $(SRV_PATH)/api/$(TARGET) $(LNK_PATH)/$(LINKIT);

uninstall:
	sudo rm -r $(LNK_PATH)/$(LINKIT);
	sudo rm -f $(SRV_PATH)/api/$(TARGET)
	
.PHONY : clean
clean:
	rm -f $(OBJS)
	rm -f $(OUT_PATH)/$(TARGET)
#-----------------------------------------------------------------------------
# end GNU MAKE file
#-----------------------------------------------------------------------------