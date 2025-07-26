#-----------------------------------------------------------------------------
# begin microsoft NMAKE file
# making order:
# 1. nmake /f zlib.ar.mk test --if need to creating some directory or file-list
# 2. nmake /f zlib.ar.mk clean
# 3. nmake /f zlib.ar.mk
# 4. nmake /f zlib.ar.mk install
#-----------------------------------------------------------------------------
!if EXIST("zlib.txt")
!include zlib.txt
!endif

ARCH = x64
MODULE = zlib

INC_PATH = ../../include
SRC_PATH = ../../third-party
LIB_PATH = ../../windows/lib/$(ARCH)
OBJ_PATH = ../../../Easily-tmp/windows/$(MODULE)/$(ARCH)/Debug
PDB_PATH = ../../../Easily-tmp/windows/$(ARCH)

TARGET = $(LIB_PATH)/$(MODULE).lib

CC = cl.exe
CFLAGS = /c /GL /TC /W3 /Zc:wchar_t /Zi /Od /Fd"$(PDB_PATH)/vc140.pdb" /fp:precise \
	/D "WIN32" /D "_DEBUG" /D "_LIB" /D "_UNICODE" /D "UNICODE" \
	/errorReport:prompt /WX- /Zc:forScope /RTC1 /Gd /MDd \
	/Fa"$(OBJ_PATH)/" /nologo /Fo"$(OBJ_PATH)/" /Fp"$(OBJ_PATH)/$(MODULE)_$(ARCH).pch"

LK = lib.exe
LFLAGS = /OUT:"$(TARGET)" /MACHINE:$(ARCH) /NOLOGO

DIRS = $(strip $(SOURCES))
COBS = $(patsubsti %.cc,%.c,$(DIRS))
OBJS = $(patsubsti %.c,%.obj,$(COBS))

{$(SRC_PATH)/zlib}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

all : $(OBJS)
	del $(subst /,\, $@)
	$(LK) $(LFLAGS) @<<
	$(OBJS)
<<
	del $(subst /,\, $(OBJ_PATH)/*.obj)

test:
 	echo SOURCES= \>$(MODULE).txt
 	for %i in ($(SRC_PATH)/zlib/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt

	@echo $(SOURCES)
	@echo $(OBJS)

	if not exist $(abspath $(subst /,\, $(OBJ_PATH))) mkdir $(abspath $(subst /,\, $(OBJ_PATH)))

install:
	copy /y $(subst /,\, $(TARGET)) $(INS_PATH)\api\

uninstall:
	del $(INS_PATH)/api/$(MODULE)_$(ARCH).dll

.PHONY : clean
clean:
	del $(subst /,\, $(TARGET))
	del $(subst /,\, $(OBJ_PATH)/*.obj)

#-----------------------------------------------------------------------------
# end microsoft NMAKE file
#-----------------------------------------------------------------------------