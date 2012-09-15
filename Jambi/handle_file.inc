IFNDEF HANDLE_FILE_INC__
HANDLE_FILE_INC__ equ <1>

	getNextFile proto stdcall
	getFileMapping proto stdcall 

ELSE
	echo ------------------
	echo Duplicate include __FILE__
	echo ------------------
ENDIF