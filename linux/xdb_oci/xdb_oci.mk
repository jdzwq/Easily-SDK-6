#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order for debug version:
# 1. make -f xdb_oci.mk test --if need to creating some directory or file-list
# 2. make -f xdb_oci.mk clean
# 3. make -f xdb_oci.mk
# 4. make -f xdb_oci.mk install
#-----------------------------------------------------------------------------
CC = gcc
CFLAGS = -g -Wall -fPIC -D _DEBUG
LFLAGS = -shared -fPIC -pthread

MODULE = xdb_oci
ARCH = aarch64
MAX_VER = 6
MIN_VER = 1

#INC_OCI = /usr/local/oracle/instantclient_19c/sdk/include
INC_OCI = /usr/local/oracle/instantclient_19c/rdbms/public
LIB_OCI = /usr/local/oracle/instantclient_19c/lib

LIB_PATH = /usr/local/lib

INC_PATH = ../../include
SRC_PATH = ../../xdb

OBJ_PATH = ~/Easily-temp/linux/$(MODULE)/$(ARCH)
OUT_PATH = ~/Easily-app-6/linux/lib/$(ARCH)

TARGET = lib$(MODULE).so.$(MAX_VER).$(MIN_VER).$(ARCH)
LINKIT = lib$(MODULE).so

LIBS = -L $(LIB_PATH) -lxdk -lxdl -L $(LIB_OCI) -locci -lclntsh
DIRS = $(wildcard $(SRC_PATH)/oci/*.c)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.c, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/oci/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH) -I $(INC_OCI)

all : $(OBJS)
	rm -f $@
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