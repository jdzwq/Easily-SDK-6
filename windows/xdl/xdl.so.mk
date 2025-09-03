#-----------------------------------------------------------------------------
# begin microsoft NMAKE file
# making order:
# 1. nmake /f xdl.so.mk test --if need to creating some directory or file-list
# 2. nmake /f xdl.so.mk clean --if no longer debuging
# 3. nmake /f xdl.so.mk
# 4. nmake /f xdl.so.mk install
#-----------------------------------------------------------------------------
!if EXIST("xdl.txt")
!include xdl.txt
!endif

ARCH = x64
MODULE = xdl

INC_PATH = ../../include
SRC_PATH = ../../xdl
LIB_PATH = ../../windows/lib/$(ARCH)
OBJ_PATH = ../../../Easily-tmp/windows/$(MODULE)/$(ARCH)/Debug
OUT_PATH = ../../../Easily-app-6/windows/sbin64/api
PDB_PATH = ../../../Easily-tmp/windows/$(ARCH)
INS_PATH = C:\xService

TARGET = $(OUT_PATH)/$(MODULE).dll
LIBRARY = $(LIB_PATH)/$(MODULE).lib
MANIFEST = $(OUT_PATH)/$(MODULE)_$(ARCH).dll.manifest
EXPORT = $(LIB_PATH)/$(MODULE)_$(ARCH).exp
DATABASE = $(OBJ_PATH)/$(MODULE)_$(ARCH).pdb
INSTRUMENT = $(OBJ_PATH)/$(MODULE)_$(ARCH).pgd

CC = cl.exe
CFLAGS = /c /GL /W3 /Zc:wchar_t /Zi /Od /Fd"$(PDB_PATH)/vc140.pdb" /fp:precise \
	/D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_USRDLL" /D "_WINDLL" /D "_UNICODE" /D "UNICODE" /D _CRT_SECURE_NO_WARNINGS \
	/errorReport:prompt /WX- /Zc:forScope /RTC1 /Gd /MDd \
	/Fa"$(OBJ_PATH)/" /EHsc /nologo /Fo"$(OBJ_PATH)/" /Fp"$(OBJ_PATH)/$(MODULE)_$(ARCH).pch"

LK = link.exe
LFLAGS = /OUT:"$(TARGET)" /MANIFEST /NXCOMPAT /PDB:"$(DATABASE)" \
	/DYNAMICBASE "kernel32.lib" "user32.lib" /IMPLIB:"$(LIBRARY)" /DEBUG /DLL /MACHINE:$(ARCH) \
	/LTCG:PGINSTRUMENT /PGD:"$(INSTRUMENT)" /SUBSYSTEM:WINDOWS \
	/LIBPATH:"$(LIB_PATH)" \
	/ERRORREPORT:PROMPT /NOLOGO /TLBID:1

DIRS = $(strip $(SOURCES))
COBS = $(patsubsti %.cc,%.c,$(DIRS))
OBJS = $(patsubsti %.c,%.obj,$(COBS))
ASMS = $(patsubsti %.obj,%.asm,$(OBJS))

{$(SRC_PATH)/bag}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/bio}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/doc}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/gdi}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/hint}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/ing}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/mis}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/par}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/scan}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/tio}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/view}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/xdb}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)}.c{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

all : $(OBJS)
	del $(subst /,\, $@)
	$(LK) $(LFLAGS) @<<
$(OBJS)
<<
	del $(subst /,\, $(MANIFEST))
	del $(subst /,\, $(OBJ_PATH)/*.obj)
	del $(subst /,\, $(OBJ_PATH)/*.asm)

test:
 	echo SOURCES= \>$(MODULE).txt
 	for %i in ($(SRC_PATH)/bag/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/bio/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/doc/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/gdi/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/hint/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/ing/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/mis/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/par/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/scan/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/tio/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/view/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/xdb/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt
	for %i in ($(SRC_PATH)/*.c) do @echo $(OBJ_PATH)/%i \>>$(MODULE).txt

	@echo $(SOURCES)
	@echo $(OBJS)
	@echo $(ASMS)

	if not exist $(abspath $(subst /,\, $(OBJ_PATH))) mkdir $(abspath $(subst /,\, $(OBJ_PATH)))

install:
	copy /y $(subst /,\, $(TARGET)) $(INS_PATH)\api\

uninstall:
	del $(INS_PATH)/api/$(MODULE)_$(ARCH).dll

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