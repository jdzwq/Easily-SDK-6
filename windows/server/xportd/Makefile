#-----------------------------------------------------------------------------
# begin microsoft NMAKE file
# making order:
# 1. nmake /f Makefile.mk test --if need to creating some directory or file-list
# 2. nmake /f Makefile.mk clean
# 3. nmake /f Makefile.mk
#-----------------------------------------------------------------------------
!if EXIST("xportd.txt")
!include xportd.txt
!endif

ARCH = x64
MODULE = xportd

INC_PATH = Z:/Easily-sdk-6/include
SRC_PATH = Z:/Easily-sdk-6/server
LIB_PATH = Z:/Easily-sdk-6/windows/lib/$(ARCH)
OBJ_PATH = Z:/Easily-tmp/windows/$(MODULE)/$(ARCH)/Debug
PDB_PATH = Z:/Easily-tmp/windows/$(ARCH)
OUT_PATH = Z:/Easily-app-6/windows/sbin64

TARGET = $(OUT_PATH)/$(MODULE).exe
DATABASE = $(OBJ_PATH)/$(MODULE).pdb
INSTRUMENT = $(OBJ_PATH)/$(MODULE).pgd
RESS = $(OBJ_PATH)/$(MODULE).res

RC = rc.exe
RFLAGS = /nologo /D "_DEBUG" /D "_UNICODE" /Fo"$(OBJ_PATH)/$(MODULE)/"

CC = cl.exe
CFLAGS = /c /GL /W3 /Zc:wchar_t /Zi /Od /Fd"$(PDB_PATH)/vc140.pdb" /fp:precise \
	/D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_UNICODE" /D "UNICODE" \
	/errorReport:prompt /WX- /Zc:forScope /RTC1 /Gd /MDd \
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

{$(SRC_PATH)/xhttps}.cc{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/xtcps}.cc{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/xudps}.cc{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/xportd}.cc{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)/xportd/windows}.cc{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

{$(SRC_PATH)}.cc{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

all : $(OBJS)
	del $(subst /,\, $(TARGET))
	$(RC) $(RFLAGS) /fo $(RESS) $(SRC_PATH)/xportd/windows/$(MODULE).rc
	$(LK) $(LFLAGS) $(OBJS) $(RESS)
	del $(subst /,\, $(OBJ_PATH)/*.obj)
	del $(subst /,\, $(OBJ_PATH)/*.asm)

test:
	echo SOURCES= \>$(MODULE).txt
	for %%i in ($(SRC_PATH)/xhttps/xhttps.cc) do @echo $(OBJ_PATH)/%%~nxi \>>$(MODULE).txt
	for %%i in ($(SRC_PATH)/xtcps/xtcps.cc) do @echo $(OBJ_PATH)/%%~nxi \>>$(MODULE).txt
	for %%i in ($(SRC_PATH)/xudps/xudps.cc) do @echo $(OBJ_PATH)/%%~nxi \>>$(MODULE).txt
 	for %%i in ($(SRC_PATH)/xportd/*.cc) do @echo $(OBJ_PATH)/%%~nxi \>>$(MODULE).txt
	for %%i in ($(SRC_PATH)/xportd/windows/*.cc) do @echo $(OBJ_PATH)/%%~nxi \>>$(MODULE).txt
	for %%i in ($(SRC_PATH)/*.cc) do @echo $(OBJ_PATH)/%%~nxi \>>$(MODULE).txt

	@echo $(DIRS)
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
	del $(subst /,\, $(TARGET))
	del $(subst /,\, $(OBJ_PATH)/*.obj)
	del $(subst /,\, $(OBJ_PATH)/*.asm)

#-----------------------------------------------------------------------------
# end microsoft NMAKE file
#-----------------------------------------------------------------------------