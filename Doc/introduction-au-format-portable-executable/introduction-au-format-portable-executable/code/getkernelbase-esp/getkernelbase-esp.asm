; getkernelbase-esp.asm
	
.386
.model flat, stdcall
option casemap:none

      include \masm32\include\windows.inc
      include \masm32\include\user32.inc
      include \masm32\include\kernel32.inc

      includelib \masm32\lib\user32.lib
      includelib \masm32\lib\kernel32.lib

.data
	
        WndTextOut1	db	"Kernel32 base address: 0x"
	WndTextOut2	db	8 dup (66), 13, 10
	WndTextFmt      db	"%x"
	
.code

start:

        mov	esi,[esp]
        and	esi,0FFFF0000h

l1:	
	sub	esi,1000h
	cmp	word ptr [esi],"ZM"
	jne	l1

	mov	eax,[esi+3Ch]
	cmp     word ptr [esi+eax],"EP"
	jne	exit

	push    esi
	push    offset WndTextFmt
	push    offset WndTextOut2
	call    wsprintfA

	push    STD_OUTPUT_HANDLE 
	call    GetStdHandle

	push	NULL
	push	NULL
	push	SIZEOF WndTextOut1 + SIZEOF WndTextOut2
	push	offset WndTextOut1
	push	eax
	call	WriteFile

exit:	
	push	0
	call	ExitProcess

end	start