#-----------------------------------------------------------------------------
# begin microsoft NMAKE file
# making order for release version:
# 1. nmake clean
# 2. nmake
# 3. nmake install
#-----------------------------------------------------------------------------
!if EXIST("zlib.txt")
!include zlib.txt
!endif

ARCH = x64
MODULE = zlib

INC_PATH = ../../include
SRC_PATH = ../../third-party
LIB_PATH = ../lib/$(ARCH)

OBJ_PATH = D:\Easily-temp\windows\$(MODULE)\$(ARCH)\Release
PDB_PATH = D:\Easily-temp\windows\$(ARCH)

TARGET = $(LIB_PATH)/$(MODULE).lib

CC = cl.exe
CFLAGS = /c /GL /TC /W3 /Zc:wchar_t /Zi /Od /Fd"$(PDB_PATH)/vc140.pdb" /fp:precise \
	/D "WIN32" /D "_LIB" /D "_UNICODE" /D "UNICODE" \
	/errorReport:prompt /WX- /Zc:forScope /RTC1 /Gd /MT \
	/Fa"$(OBJ_PATH)/" /nologo /Fo"$(OBJ_PATH)/" /Fp"$(OBJ_PATH)/$(MODULE)_$(ARCH).pch"

LK = lib.exe
LFLAGS = /OUT:"$(TARGET)" /MACHINE:$(ARCH) /NOLOGO

DIRS = $(strip $(SOURCES))
COBS = $(patsubsti %.cc,%.c,$(DIRS))
OBJS = $(patsubsti %.c,%.obj,$(COBS))

{$(SRC_PATH)/zlib}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

all : $(OBJS)
	$(LK) $(LFLAGS) @<<
	$(OBJS)
<<
	del $(subst /,\, $(OBJ_PATH)/*.obj)

test:
	if not exist $(abspath $(subst /,\, $(PDB_PATH))) mkdir $(abspath $(subst /,\, $(PDB_PATH)))
	if not exist $(abspath $(subst /,\, $(OBJ_PATH))) mkdir $(abspath $(subst /,\, $(OBJ_PATH)))

 	echo SOURCES= \>$(MODULE).txt
 	for %i in ($(SRC_PATH)/zlib/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt

	@echo $(SOURCES)
	@echo $(OBJS)

install:

uninstall:

.PHONY : clean
clean:
	del $(subst /,\, $(TARGET))
	del $(subst /,\, $(OBJ_PATH)/*.obj)
	del $(subst /,\, $(OBJ_PATH)/*.asm)

#-----------------------------------------------------------------------------
# end microsoft NMAKE file
#-----------------------------------------------------------------------------