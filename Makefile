WINDOWS_VER := 10

CC_x64 		:= x86_64-w64-mingw32-gcc
CC_x86 		:= i686-w64-mingw32-gcc
LD_x64 		:= x86_64-w64-mingw32-ld
STR_x64 	:= x86_64-w64-mingw32-strip

NAME 		:= dcomhijack
EXPORTS 	:= dll/exports/$(WINDOWS_VER)
OUT 		:= bin
DLL_x64		:= XmlLite UxTheme bcrypt USERENV DUI70 wbemcomn MFPlat
DLL_x86		:= PROPSYS ATL

.PHONY: bof dll

default: clean bof dll
release: default zip

bof:
	@ $(CC_x64) -o $(OUT)/tmp.x64.o -c $@/*.c -Os -s -Qn -nostdlib -Wl,-s,--exclude-all-symbols,--no-leading-underscore
	@ $(STR_x64) -N $@/*.c $(OUT)/tmp.x64.o
	@ $(LD_x64) -x -r $(OUT)/tmp.x64.o -o $(OUT)/$(NAME).x64.o
	@ rm $(OUT)/tmp.x64.o

dll:
	@ for d in $(DLL_x64); do \
		if [ -f $(EXPORTS)/$$d.def ]; then \
			$(CC_x64) -shared -o $(OUT)/$$d.dll $(EXPORTS)/$$d.def $@/*.c ; \
		fi \
	done
	@ for d in $(DLL_x86); do \
		if [ -f $(EXPORTS)/$$d.def ]; then \
			$(CC_x86) -shared -o $(OUT)/$$d.dll $(EXPORTS)/$$d.def $@/*.c ; \
		fi \
	done

clean:
	@ rm -rf $(OUT)/*.dll
	@ rm -rf $(OUT)/*.o
	@ rm -rf $(OUT)/*.zip

zip:
	@ zip -j $(OUT)/$(NAME).zip $(OUT)/*.o $(OUT)/*.dll $(OUT)/$(NAME).py $(OUT)/$(NAME).cna 1>/dev/null
