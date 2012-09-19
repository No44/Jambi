; donothing.asm
	
.386
.model flat, stdcall
option casemap:none

.data
	dd	012345678h
.code

start:
	ret

end	start