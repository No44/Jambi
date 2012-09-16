.386
.model flat, stdcall
option casemap:none

	include windows.inc
	include kernel32.inc

.data

_pattern			db	"*.exe",0
_searchHandle		dd	0

.code

getNextFile proc

	sub esp, sizeof WIN32_FIND_DATA			;; WIN32_FIND_DATA buffer
	mov ebx, esp							;; ebx points to the buffer

	cmp _searchHandle, 0					;; if this is not our first search
	jne nextfile

first:
	push esp								;; WIN32_FIND_DATA buffer
	push offset _pattern					;; Executable files pattern
	call FindFirstFile
	mov _searchHandle, eax
	cmp eax, INVALID_HANDLE_VALUE			;; if the result is invalid
	jne getfilehandle
	jmp nullify								;; move to cleanup

nextfile:
	push esp
	push _searchHandle
	call FindNextFile
	cmp  eax, 0
	je closefind

getfilehandle:
	
	push 0
	push 0
	push OPEN_EXISTING						;; creation disposition
	push 0									;; security attributes
	push 0									;; sharing settings
	push GENERIC_READ or GENERIC_WRITE		;; flags
	;push ebx								;; location of WIN32_FIND_DATA's  first byte
	;add	dword ptr[esp], 2Ch				;; 2CH is offset to filename
	;; higher level
	assume ebx:	ptr WIN32_FIND_DATA			;; consider ebx as a pointer to WIN32_FIND_DATA
	lea esi, [ebx].cFileName				;; lea : Load Effective Address (== push &(ebx->cFileName))
	push esi
	assume ebx:	nothing
	call CreateFile
	add esp, sizeof WIN32_FIND_DATA			;; clean WIN32_FIND_DATA buffer
	jmp finished							;; eax contains the file handle or 0

closefind:
	push _searchHandle
	call FindClose

nullify:
	xor eax, eax							;; sets eax to 0
	mov _searchHandle, 0					;; sets _searchHandle to 0
	add esp, sizeof WIN32_FIND_DATA

finished:
	ret
getNextFile endp

end