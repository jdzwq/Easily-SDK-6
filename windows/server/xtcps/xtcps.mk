#-----------------------------------------------------------------------------
# begin microsoft NMAKE file
# making order for debug version:
# 1. nmake /f xtcps.mk test --if need to creating some directory or file-list
# 2. nmake /f xtcps.mk clean
# 3. nmake /f xtcps.mk
# 4. nmake /f xtcps.mk install
#-----------------------------------------------------------------------------
!if EXIST("xtcps.txt")
!include xtcps.txt
!endif

ARCH = x64
MODULE = xtcps

INC_PATH = ../../../include
SRC_PATH = ../../../server

LIB_PATH = ../../lib/$(ARCH)

OBJ_PATH = D:/Easily-temp/windows/$(MODULE)/$(ARCH)/Debug
PDB_PATH = D:/Easily-temp/windows/$(ARCH)
OUT_PATH = Z:\Easily-app-6\windows\sbin

TARGET = $(OBJ_PATH)/$(MODULE).exe
DATABASE = $(OBJ_PATH)/$(MODULE).pdb
INSTRUMENT = $(OBJ_PATH)/$(MODULE).pgd

CC = cl.exe
CFLAGS = /c /GL /W3 /Zc:wchar_t /Zi /Od /Fd"$(PDB_PATH)/vc140.pdb" /fp:precise \
	/D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "_UNICODE" /D "UNICODE" \
	/errorReport:prompt /WX- /Zc:forScope /RTC1 /Gd /MTd \
	/Fa"$(OBJ_PATH)/" /EHsc /nologo /Fo"$(OBJ_PATH)/" /Fp"$(OBJ_PATH)/$(MODULE).pch"

LK = link.exe
LFLAGS = /OUT:"$(TARGET)" /NXCOMPAT /PDB:"$(DATABASE)" \
	/DYNAMICBASE "kernel32.lib" "advapi32.lib" \
	/DEBUG /MACHINE:$(ARCH) /LTCG:PGINSTRUMENT /PGD:"$(INSTRUMENT)" /SUBSYSTEM:CONSOLE \
	/LIBPATH:"$(LIB_PATH)" \
	/ERRORREPORT:PROMPT /NOLOGO /TLBID:1

DIRS = $(strip $(SOURCES))
OBJS = $(patsubsti %.cc,%.obj,$(DIRS))
ASMS = $(patsubsti %.obj,%.asm,$(OBJS))

{$(SRC_PATH)/xtcps}.cc{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)}.cc{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

all : $(OBJS)
	del $(subst /,\, $(TARGET))
	$(LK) $(LFLAGS) $(OBJS)
	del $(subst /,\, $(OBJ_PATH)/*.obj)
	del $(subst /,\, $(OBJ_PATH)/*.asm)

test:
	echo SOURCES= \>$(MODULE).txt
 	for %%i in ($(SRC_PATH)/xtcps/*.cc) do @echo $(OBJ_PATH)/%%~nxi \>>$(MODULE).txt
	for %%i in ($(SRC_PATH)/*.cc) do @echo $(OBJ_PATH)/%%~nxi \>>$(MODULE).txt

	@echo $(DIRS)
	@echo $(OBJS)
	@echo $(ASMS)
	
	if not exist $(abspath $(subst /,\, $(OBJ_PATH))) mkdir $(abspath $(subst /,\, $(OBJ_PATH)))

install:
	if not exist $(OUT_PATH) mkdir $(OUT_PATH)
	copy /y $(subst /,\, $(TARGET)) $(OUT_PATH)

uninstall:
	del $(OUT_PATH)/$(MODULE).exe

.PHONY : clean
clean:
	del $(subst /,\, $(DATABASE))
	del $(subst /,\, $(INSTRUMENT))
	del $(subst /,\, $(TARGET))
	del $(subst /,\, $(OBJ_PATH)/*.obj)
	del $(subst /,\, $(OBJ_PATH)/*.asm)

#-----------------------------------------------------------------------------
# end microsoft NMAKE file
#-----------------------------------------------------------------------------