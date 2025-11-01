#-----------------------------------------------------------------------------
# begin microsoft NMAKE file
# making order for debug version:
# 1. nmake /f xdb_sqlite.mk test --if need to creating some directory or file-list
# 2. nmake /f xdb_sqlite.mk clean --if no longer debuging
# 3. nmake /f xdb_sqlite.mk
# 4. nmake /f xdb_sqlite.mk install
#-----------------------------------------------------------------------------
!if EXIST("xdb_sqlite.txt")
!include xdb_sqlite.txt
!endif

ARCH = x64
MODULE = xdb_sqlite

INC_sqlite = "D:/sqlite/include"
LIB_sqlite = "D:/sqlite/lib"

INC_PATH = ../../include
SRC_PATH = ../../xdb

LIB_PATH = ../lib/$(ARCH)

OBJ_PATH = D:\Easily-temp\windows\$(MODULE)\$(ARCH)\Debug
PDB_PATH = D:\Easily-temp\windows\$(ARCH)
OUT_PATH = Z:\Easily-app-6\windows\lib

TARGET = $(OBJ_PATH)/$(MODULE).dll
LIBRARY = $(LIB_PATH)/$(MODULE).lib
MANIFEST = $(OBJ_PATH)/$(MODULE)_$(ARCH).dll.manifest
EXPORT = $(LIB_PATH)/$(MODULE)_$(ARCH).exp
DATABASE = $(OBJ_PATH)/$(MODULE)_$(ARCH).pdb
INSTRUMENT = $(OBJ_PATH)/$(MODULE)_$(ARCH).pgd

CC = cl.exe
CFLAGS = /c /GL /W3 /Zc:wchar_t /Zi /Od /Fd"$(PDB_PATH)/vc140.pdb" /fp:precise \
	/D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "_USRDLL" /D "_WINDLL" /D "_UNICODE" /D "UNICODE" /D _CRT_SECURE_NO_WARNINGS \
	/errorReport:prompt /WX- /Zc:forScope /RTC1 /Gd /MTd \
	/Fa"$(OBJ_PATH)/" /EHsc /nologo /Fo"$(OBJ_PATH)/" /Fp"$(OBJ_PATH)/$(MODULE)_$(ARCH).pch"

LK = link.exe
LFLAGS = /OUT:"$(TARGET)" /MANIFEST /NXCOMPAT /PDB:"$(DATABASE)" \
	/DEBUG /DYNAMICBASE "kernel32.lib" "user32.lib" "advapi32.lib" /DLL /MACHINE:$(ARCH) \
	/LTCG:PGINSTRUMENT /PGD:"$(INSTRUMENT)" /SUBSYSTEM:WINDOWS \
	/DEF:"$(MODULE)_$(ARCH).def" /IMPLIB:"$(LIBRARY)" \
	/LIBPATH:"$(LIB_PATH)" /LIBPATH:$(LIB_sqlite) \
	/ERRORREPORT:PROMPT /NOLOGO /TLBID:1

DIRS = $(strip $(SOURCES))
COBS = $(patsubsti %.cc,%.c,$(DIRS))
OBJS = $(patsubsti %.c,%.obj,$(COBS))
ASMS = $(patsubsti %.obj,%.asm,$(OBJS))

{$(SRC_PATH)/sqlite}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) /I $(INC_sqlite) $<

all : $(OBJS)
	$(LK) $(LFLAGS) @<<
$(OBJS)
<<
	del $(subst /,\, $(MANIFEST))
	del $(subst /,\, $(OBJ_PATH)/*.obj)
	del $(subst /,\, $(OBJ_PATH)/*.asm)

test:
 	echo SOURCES= \>$(MODULE).txt
 	for %i in ($(SRC_PATH)/sqlite/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt

	@echo $(SOURCES)
	@echo $(OBJS)
	@echo $(ASMS)

	if not exist $(abspath $(subst /,\, $(PDB_PATH))) mkdir $(abspath $(subst /,\, $(PDB_PATH)))
	if not exist $(abspath $(subst /,\, $(OBJ_PATH))) mkdir $(abspath $(subst /,\, $(OBJ_PATH)))

install:
	if not exist $(OUT_PATH) mkdir $(OUT_PATH)
	copy /y $(subst /,\, $(TARGET)) $(OUT_PATH)

uninstall:
	del $(OUT_PATH)/$(MODULE).dll

.PHONY : clean
clean:
	del $(subst /,\, $(DATABASE))
	del $(subst /,\, $(INSTRUMENT))
	del $(subst /,\, $(MANIFEST))
	del $(subst /,\, $(TARGET))
	del $(subst /,\, $(LIBRARY))
	del $(subst /,\, $(EXPORT))
	del $(subst /,\, $(OBJ_PATH)/*.obj)
	del $(subst /,\, $(OBJ_PATH)/*.asm)

#-----------------------------------------------------------------------------
# end microsoft NMAKE file
#-----------------------------------------------------------------------------