; msgbox.asm
	
.386
.model flat, stdcall
option casemap:none

      include \masm32\include\windows.inc
      include \masm32\include\user32.inc
      include \masm32\include\kernel32.inc

      includelib \masm32\lib\user32.lib
      includelib \masm32\lib\kernel32.lib

.data
	szWndTitle	db	"[msgbox]",0
	szWndText	db	"msgbox",0

.code

start:

	push	MB_OK
	push	offset szWndTitle
	push	offset szWndText
	push	0
	call	MessageBoxA
	
	push	0
	call	ExitProcess

end	start