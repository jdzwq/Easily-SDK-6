#-----------------------------------------------------------------------------
# begin microsoft NMAKE file
# making order for debug version:
# 1. nmake /f xtimerd.mk test --if need to creating some directory or file-list
# 2. nmake /f xtimerd.mk clean
# 3. nmake /f xtimerd.mk
# 4. nmake /f xtimerd.mk install
#-----------------------------------------------------------------------------
!if EXIST("xtimerd.txt")
!include xtimerd.txt
!endif

ARCH = x64
MODULE = xtimerd

INC_PATH = ../../../include
SRC_PATH = ../../../server

LIB_PATH = ../../lib/$(ARCH)

OBJ_PATH = E:/Easily-temp/windows/$(MODULE)/$(ARCH)/Debug
PDB_PATH = E:/Easily-temp/windows/$(ARCH)
OUT_PATH = Z:\Easily-app-6\windows\sbin

TARGET = $(OBJ_PATH)/$(MODULE).exe
DATABASE = $(OBJ_PATH)/$(MODULE).pdb
INSTRUMENT = $(OBJ_PATH)/$(MODULE).pgd
RESS = $(OBJ_PATH)/$(MODULE).res

RC = rc.exe
RFLAGS = /nologo /D "_DEBUG" /D "_UNICODE" /Fo"$(OBJ_PATH)/$(MODULE)/"

CC = cl.exe
CFLAGS = /c /GL /W3 /Zc:wchar_t /Zi /Od /Fd"$(PDB_PATH)/vc140.pdb" /fp:precise \
	/D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "_UNICODE" /D "UNICODE" \
	/errorReport:prompt /WX- /Zc:forScope /RTC1 /Gd /MTd \
	/Fa"$(OBJ_PATH)/" /EHsc /nologo /Fo"$(OBJ_PATH)/" /Fp"$(OBJ_PATH)/$(MODULE).pch"

LK = link.exe
LFLAGS = /OUT:"$(TARGET)" /NXCOMPAT /PDB:"$(DATABASE)" \
	/DYNAMICBASE "kernel32.lib" "advapi32.lib" "user32.lib" "shell32.lib" "Gdi32.lib" \
	/DEBUG /MACHINE:$(ARCH) /LTCG:PGINSTRUMENT /PGD:"$(INSTRUMENT)" /SUBSYSTEM:WINDOWS \
	/LIBPATH:"$(LIB_PATH)" \
	/ERRORREPORT:PROMPT /NOLOGO /TLBID:1

DIRS = $(strip $(SOURCES))
OBJS = $(patsubsti %.cc,%.obj,$(DIRS))
ASMS = $(patsubsti %.obj,%.asm,$(OBJS))

{$(SRC_PATH)/xtimers}.cc{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/xtimerd}.cc{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/xtimerd/windows}.cc{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)}.cc{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $< 

all : $(OBJS)
	del $(subst /,\, $(TARGET))
	$(RC) $(RFLAGS) /fo $(RESS) $(SRC_PATH)/xtimerd/windows/$(MODULE).rc
	$(LK) $(LFLAGS) $(OBJS) $(RESS)
	del $(subst /,\, $(OBJ_PATH)/*.obj)
	del $(subst /,\, $(OBJ_PATH)/*.asm)

test:
	echo SOURCES= \>$(MODULE).txt
	for %%i in ($(SRC_PATH)/xtimers/xtimers.cc) do @echo $(OBJ_PATH)/%%~nxi \>>$(MODULE).txt
 	for %%i in ($(SRC_PATH)/xtimerd/*.cc) do @echo $(OBJ_PATH)/%%~nxi \>>$(MODULE).txt
	for %%i in ($(SRC_PATH)/xtimerd/windows/*.cc) do @echo $(OBJ_PATH)/%%~nxi \>>$(MODULE).txt
	for %%i in ($(SRC_PATH)/*.cc) do @echo $(OBJ_PATH)/%%~nxi \>>$(MODULE).txt

	@echo $(DIRS)
	@echo $(OBJS)
	@echo $(ASMS)
	@echo $(RESS)
	
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