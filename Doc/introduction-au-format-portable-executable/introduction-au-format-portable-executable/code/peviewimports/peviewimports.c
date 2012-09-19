/**
 ** peviewimports.c
 */

#include <windows.h>
#include <stdio.h>

DWORD RvaToOffset(PIMAGE_NT_HEADERS pImageNtHeaders, DWORD dwRva);

int	main(int argc, char **argv) 
{
  PIMAGE_DOS_HEADER		pImageDosHeader;
  PIMAGE_NT_HEADERS		pImageNtHeaders;
  PIMAGE_IMPORT_DESCRIPTOR	pImageImportDescriptor;
  PIMAGE_IMPORT_BY_NAME		pImageImportByName;	
  DWORD				dwCount;
  DWORD				dwCount2;
  DWORD				*Thunks;
  DWORD				dwFileOffset;
  HANDLE		        hFile;
  HANDLE			hMapObject;
  PUCHAR			uFileMap;

  if (argc < 2)
    return (-1);

  if (!(hFile = CreateFile(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0)))
    return (-1);

  if (!(hMapObject = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL)))
    return (-1);

  if (!(uFileMap = MapViewOfFile(hMapObject, FILE_MAP_READ, 0, 0, 0)))
    return (-1);

  pImageDosHeader = (PIMAGE_DOS_HEADER) uFileMap ;
  if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    return (-1);

  pImageNtHeaders = (PIMAGE_NT_HEADERS) ((PUCHAR) uFileMap + pImageDosHeader->e_lfanew);
  if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    return (-1);

  dwFileOffset = RvaToOffset(pImageNtHeaders, pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
  pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) ((PUCHAR) uFileMap + dwFileOffset);

  dwCount = 0;
  while (pImageImportDescriptor[dwCount].FirstThunk) {
    printf("Module Name: %s\n", ((PUCHAR) uFileMap + RvaToOffset(pImageNtHeaders, pImageImportDescriptor[dwCount].Name)));
    Thunks = (DWORD *) ((PUCHAR) uFileMap + RvaToOffset(pImageNtHeaders, pImageImportDescriptor[dwCount].OriginalFirstThunk));
    dwCount2 = 0;
    while (Thunks[dwCount2]) {
      pImageImportByName = (PIMAGE_IMPORT_BY_NAME) ((PUCHAR) uFileMap + RvaToOffset(pImageNtHeaders, Thunks[dwCount2]));
      printf("Name: %s\n", pImageImportByName->Name);
      dwCount2++;
    }
    dwCount++;
  }	

  return (0);
}

DWORD	RvaToOffset(PIMAGE_NT_HEADERS pImageNtHeaders, DWORD dwRva)
{
  PIMAGE_SECTION_HEADER	pImageSectionHeader;
  DWORD			dwCount;
  DWORD			dwFileOffset;

  pImageSectionHeader = IMAGE_FIRST_SECTION(pImageNtHeaders);
  dwFileOffset = dwRva;
  for (dwCount = 0; dwCount < pImageNtHeaders->FileHeader.NumberOfSections; dwCount++) {
    if (dwRva >= pImageSectionHeader[dwCount].VirtualAddress &&
	dwRva < (pImageSectionHeader[dwCount].VirtualAddress + pImageSectionHeader[dwCount].SizeOfRawData)) {
      dwFileOffset -= pImageSectionHeader[dwCount].VirtualAddress;
      dwFileOffset += pImageSectionHeader[dwCount].PointerToRawData;
      return (dwFileOffset);
    }
  }
  return (0);
}


