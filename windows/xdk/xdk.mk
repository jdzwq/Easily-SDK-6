#-----------------------------------------------------------------------------
# begin microsoft nmake file
# making order for debug version:
# 1. nmake /f xdk.mk test --if need to creating some directory or file-list
# 2. nmake /f xdk.mk clean
# 3. nmake /f xdk.mk
# 4. nmake /f xdk.mk install
#-----------------------------------------------------------------------------
!if EXIST("xdk.txt")
!include xdk.txt
!endif

ARCH = x64
MODULE = xdk

INC_PATH = ../../include
SRC_PATH = ../../xdk

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
CFLAGS = /c /GL /TC /W3 /Zc:wchar_t /Zi /Od /Fd"$(PDB_PATH)/vc140.pdb" /fp:precise \
	/D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "_USRDLL" /D "_WINDLL" /D "_UNICODE" /D "UNICODE" /D _CRT_SECURE_NO_WARNINGS \
	/errorReport:prompt /WX- /Zc:forScope /RTC1 /Gd /MTd \
	/Fa"$(OBJ_PATH)/" /nologo /Fo"$(OBJ_PATH)/" /Fp"$(OBJ_PATH)/$(MODULE)_$(ARCH).pch"

LK = link.exe
LFLAGS = /OUT:"$(TARGET)" /MANIFEST /NXCOMPAT /PDB:"$(DATABASE)" \
	/DEBUG /DYNAMICBASE "kernel32.lib" "user32.lib" "Advapi32.lib" /IMPLIB:"$(LIBRARY)" /DLL /MACHINE:$(ARCH) \
	/LTCG:PGINSTRUMENT /PGD:"$(INSTRUMENT)" /SUBSYSTEM:WINDOWS \
	/LIBPATH:"$(LIB_PATH)" \
	/ERRORREPORT:PROMPT /NOLOGO /TLBID:1

DIRS = $(strip $(SOURCES))
COBS = $(patsubsti %.cc,%.c,$(DIRS))
OBJS = $(patsubsti %.c,%.obj,$(COBS))
ASMS = $(patsubsti %.obj,%.asm,$(OBJS))

{$(SRC_PATH)/windows}.cc{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/imp}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/acp}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/str}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/enc}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/maa}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/util}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/bar}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/zip}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/mob}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/dob}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/net}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/stm}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/expr}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/math}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

all : $(OBJS)
	$(LK) $(LFLAGS) @<<
$(OBJS)
<<
	del $(subst /,\, $(MANIFEST))
	del $(subst /,\, $(OBJ_PATH)/*.obj)
	del $(subst /,\, $(OBJ_PATH)/*.asm)

test:
	if not exist $(abspath $(subst /,\, $(PDB_PATH))) mkdir $(abspath $(subst /,\, $(PDB_PATH)))
	if not exist $(abspath $(subst /,\, $(OBJ_PATH))) mkdir $(abspath $(subst /,\, $(OBJ_PATH)))

 	echo SOURCES= \>$(MODULE).txt
 	for %i in ($(SRC_PATH)/windows/*.cc) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/imp/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/acp/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/str/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/enc/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/maa/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/util/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/bar/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/zip/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/mob/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/dob/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/net/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/stm/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/expr/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/math/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt

	@echo $(SOURCES)
	@echo $(OBJS)
	@echo $(ASMS)

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
# end microsoft nmake file
#-----------------------------------------------------------------------------