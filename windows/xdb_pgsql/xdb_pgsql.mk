#-----------------------------------------------------------------------------
# begin microsoft NMAKE file
# making order for debug version:
# 1. nmake /f xdb_pgsql.mk test --if need to creating some directory or file-list
# 2. nmake /f xdb_pgsql.mk clean --if no longer debuging
# 3. nmake /f xdb_pgsql.mk
# 4. nmake /f xdb_pgsql.mk install
#-----------------------------------------------------------------------------
!if EXIST("xdb_pgsql.txt")
!include xdb_pgsql.txt
!endif

ARCH = x86
MODULE = xdb_pgsql

INC_pgsql = "E:/pgsql/include"
LIB_pgsql = "E:/pgsql/lib"

INC_PATH = ../../include
SRC_PATH = ../../xdb

LIB_PATH = ../lib/$(ARCH)

OBJ_PATH = E:\Easily-temp\windows\$(MODULE)\$(ARCH)\Debug
PDB_PATH = E:\Easily-temp\windows\$(ARCH)
OUT_PATH = Z:\Easily-app-6\windows\lib\$(ARCH)

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
	/LTCG:PGINSTRUMENT /PGE:"$(INSTRUMENT)" /SUBSYSTEM:WINDOWS \
	/DEF:"$(MODULE)_$(ARCH).def" /IMPLIB:"$(LIBRARY)" \
	/LIBPATH:"$(LIB_PATH)" /LIBPATH:$(LIB_pgsql) \
	/ERRORREPORT:PROMPT /NOLOGO /TLBIE:1

DIRS = $(strip $(SOURCES))
COBS = $(patsubsti %.cc,%.c,$(DIRS))
OBJS = $(patsubsti %.c,%.obj,$(COBS))
ASMS = $(patsubsti %.obj,%.asm,$(OBJS))

{$(SRC_PATH)/pgsql}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) /I $(INC_pgsql) $<

all : $(OBJS)
	$(LK) $(LFLAGS) @<<
$(OBJS)
<<
	del $(subst /,\, $(MANIFEST))
	del $(subst /,\, $(OBJ_PATH)/*.obj)
	del $(subst /,\, $(OBJ_PATH)/*.asm)

test:
 	echo SOURCES= \>$(MODULE).txt
 	for %i in ($(SRC_PATH)/pgsql/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt

	@echo $(SOURCES)
	@echo $(OBJS)
	@echo $(ASMS)

	if not exist $(abspath $(subst /,\, $(PDB_PATH))) mkdir $(abspath $(subst /,\, $(PDB_PATH)))
	if not exist $(abspath $(subst /,\, $(OBJ_PATH))) mkdir $(abspath $(subst /,\, $(OBJ_PATH)))

install:
	if not exist $(OUT_PATH) mkdir $(OUT_PATH)
	copy /y $(subst /,\, $(TARGET)) $(OUT_PATH)

uninstall:
	del $(subst /,\, $(OUT_PATH)/$(MODULE).dll)

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