#-----------------------------------------------------------------------------
# begin microsoft NMAKE file
# making order:
# 1. nmake /f Makefile.mk test --if need to creating some directory or file-list
# 2. nmake /f Makefile.mk clean
# 3. nmake /f Makefile.mk
#-----------------------------------------------------------------------------
ARCH = x86
MODULE = xdc_editor_test

INC_PATH = Z:/Easily-sdk-6/include
SRC_PATH = Z:/Easily-sdk-6/test/xdc_editor_test
LIB_PATH = Z:/Easily-sdk-6/windows/lib/$(ARCH)
OBJ_PATH = D:/Easily-temp/windows/$(MODULE)/$(ARCH)/Debug
PDB_PATH = D:/Easily-temp/windows/$(ARCH)
OUT_PATH = Z:/Easily-app-6/windows/bin

TARGET = $(OUT_PATH)/$(MODULE).exe
DATABASE = $(OBJ_PATH)/$(MODULE).pdb
INSTRUMENT = $(OBJ_PATH)/$(MODULE).pgd

CC = cl.exe
CFLAGS = /c /GL /W3 /Zc:wchar_t /Zi /Od /Fd"$(PDB_PATH)/vc140.pdb" /fp:precise \
	/D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_UNICODE" /D "UNICODE" \
	/errorReport:prompt /WX- /Zc:forScope /RTC1 /Gd /MDd \
	/Fa"$(OBJ_PATH)/" /EHsc /nologo /Fo"$(OBJ_PATH)/" /Fp"$(OBJ_PATH)/$(MODULE).pch"

LK = link.exe
LFLAGS = /OUT:"$(TARGET)" /NXCOMPAT /PDB:"$(DATABASE)" \
	/DYNAMICBASE "kernel32.lib" "user32.lib" "advapi32.lib" "shell32.lib" \
	/DEBUG /MACHINE:$(ARCH) /LTCG:PGINSTRUMENT /PGD:"$(INSTRUMENT)" /SUBSYSTEM:WINDOWS \
	/LIBPATH:"$(LIB_PATH)" \
	/ERRORREPORT:PROMPT /NOLOGO /TLBID:1

DIRS = $(strip $(OBJ_PATH)/main.cc)
OBJS = $(patsubsti %.cc,%.obj,$(DIRS))
ASMS = $(patsubsti %.obj,%.asm,$(OBJS))

{$(SRC_PATH)}.cc{$(OBJ_PATH)}.obj::
	$(CC) $(CFLAGS) /I $(INC_PATH) $<

all : $(OBJS)
	del $(subst /,\, $(TARGET))
	$(LK) $(LFLAGS) $(OBJS)
	del $(subst /,\, $(OBJ_PATH)/*.obj)
	del $(subst /,\, $(OBJ_PATH)/*.asm)

test:
	@echo $(DIRS)
	@echo $(OBJS)
	@echo $(ASMS)

	if not exist $(abspath $(subst /,\, $(OBJ_PATH))) mkdir $(abspath $(subst /,\, $(OBJ_PATH)))

install:
	copy /y $(subst /,\, $(TARGET)) $(OUT_PATH)\api\

uninstall:
	del $(OUT_PATH)/api/$(MODULE)_$(ARCH).dll

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