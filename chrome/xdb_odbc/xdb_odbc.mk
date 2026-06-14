#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order:
# 1. nmake /f xdb_odbc.mk test --if need to creating some directory or file-list
# 2. nmake /f xdb_odbc.mk clean
# 3. nmake /f xdb_odbc.mk
# 4. nmake /f xdb_odbc.mk install
#-----------------------------------------------------------------------------
CC = gcc
CFLAGS = -g -Wall -fPIC -D _DEBUG
LFLAGS = -shared -fPIC -pthread

MODULE = xdb_odbc
ARCH = x86_64
MAX_VER = 6
MIN_VER = 1

LIB_PATH = /usr/local/lib

INC_ODBC = /usr/include
LIB_ODBC = /usr/lib64

INC_PATH = ../../include
SRC_PATH = ../../xdb

OBJ_PATH = ~/Easily-temp/chrome/$(MODULE)/$(ARCH)
OUT_PATH = ~/Easily-app-6/chrome/lib/$(ARCH)

TARGET = lib$(MODULE).so.$(MAX_VER).$(MIN_VER).$(ARCH)
LINKIT = lib$(MODULE).so

LIBS = -L $(LIB_PATH) -lxdk -lxdl -L $(LIB_ODBC) -lodbc
DIRS = $(wildcard $(SRC_PATH)/xdb_odbc.c)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.c, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/xdb_odbc.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH) -I $(INC_ODBC)

all : $(OBJS)
	$(CC) $(LFLAGS) -o $(OBJ_PATH)/$(TARGET) $(OBJS) $(LIBS)

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
# end microsoft NMAKE file
#-----------------------------------------------------------------------------