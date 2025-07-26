#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order:
# 1. make -f Makefile.mk test --if need to creating some directory or file-list
# 2. make -f Makefile.mk clean
# 3. make -f Makefile.mk
# 4. make -f Makefile.mk install
#-----------------------------------------------------------------------------
CC = clang
CFLAGS = -g -Wall -D _DEBUG

MODULE = oem_rtf_test
ARCH = aarch64

LIB_PATH = /usr/local/lib

INC_PATH = ~/工程/Easily-sdk-6/include
SRC_PATH = ~/工程/Easily-sdk-6/test/oem_rtf_test
OBJ_PATH = ~/工程/Easily-tmp/macos/$(MODULE)/$(ARCH)
OUT_PATH = ~/工程/Easily-app-6/macos/bin

DIRS = $(wildcard $(SRC_PATH)/*.cc)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.cc, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)%.o : $(SRC_PATH)/%.cc
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

all : $(OBJS)
	rm -f $@
	$(CC) -o $(OUT_PATH)/$(MODULE) $(OBJS) -L $(LIB_PATH) -lrtf
#	rm -f $(OBJS)

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
	-rm -f $(OBJS)
#-----------------------------------------------------------------------------
# end GNU MAKE file
#-----------------------------------------------------------------------------
