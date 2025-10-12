#-----------------------------------------------------------------------------
# begin microsoft NMAKE file
# making order for release version:
# 1. nmake test
# 2. nmake clean
# 3. nmake all
# 4. nmake install
#-----------------------------------------------------------------------------
!if EXIST("xtimers.txt")
!include xtimers.txt
!endif

ARCH = x64
MODULE = xtimers

INC_PATH = ../../../include
SRC_PATH = ../../../server

LIB_PATH = ../../lib/$(ARCH)
INS_PATH = C:\Easily\sbin64

OBJ_PATH = D:/Easily-temp/windows/$(MODULE)/$(ARCH)/Debug
PDB_PATH = D:/Easily-temp/windows/$(ARCH)

TARGET = $(OBJ_PATH)/$(MODULE).exe
DATABASE = $(OBJ_PATH)/$(MODULE).pdb
INSTRUMENT = $(OBJ_PATH)/$(MODULE).pgd

CC = cl.exe
CFLAGS = /c /GL /W3 /Zc:wchar_t /Zi /Od /Fd"$(PDB_PATH)/vc140.pdb" /fp:precise \
	/D "WIN32" /D "_WINDOWS" /D "_UNICODE" /D "UNICODE" \
	/errorReport:prompt /WX- /Zc:forScope /RTC1 /Gd /MT \
	/Fa"$(OBJ_PATH)/" /EHsc /nologo /Fo"$(OBJ_PATH)/" /Fp"$(OBJ_PATH)/$(MODULE).pch"

LK = link.exe
LFLAGS = /OUT:"$(TARGET)" /NXCOMPAT /PDB:"$(DATABASE)" \
	/DYNAMICBASE "kernel32.lib" "advapi32.lib" \
	/MACHINE:$(ARCH) /LTCG:PGINSTRUMENT /PGD:"$(INSTRUMENT)" /SUBSYSTEM:CONSOLE \
	/LIBPATH:"$(LIB_PATH)" \
	/ERRORREPORT:PROMPT /NOLOGO /TLBID:1

DIRS = $(strip $(SOURCES))
OBJS = $(patsubsti %.cc,%.obj,$(DIRS))
ASMS = $(patsubsti %.obj,%.asm,$(OBJS))

{$(SRC_PATH)/xtimers}.cc{$(OBJ_PATH)}.obj::
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
 	for %%i in ($(SRC_PATH)/xtimers/*.cc) do @echo $(OBJ_PATH)/%%~nxi \>>$(MODULE).txt
	for %%i in ($(SRC_PATH)/*.cc) do @echo $(OBJ_PATH)/%%~nxi \>>$(MODULE).txt

	@echo $(DIRS)
	@echo $(OBJS)
	@echo $(ASMS)
	
	if not exist $(abspath $(subst /,\, $(OBJ_PATH))) mkdir $(abspath $(subst /,\, $(OBJ_PATH)))

install:
	if not exist $(INS_PATH) mkdir $(INS_PATH)
	copy /y $(subst /,\, $(TARGET)) $(INS_PATH)

uninstall:
	del $(INS_PATH)/$(MODULE).exe

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