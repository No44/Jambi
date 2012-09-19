/**
 ** peviewimagesectionheaders.c
 */

#include <windows.h>
#include <stdio.h>

void viewImageSectionHeaderCharacteristics(DWORD);

int	main(int argc, char **argv) 
{
  PIMAGE_DOS_HEADER	pImageDosHeader;
  PIMAGE_NT_HEADERS	pImageNtHeaders;
  PIMAGE_SECTION_HEADER	pImageSectionHeader;
  HANDLE                hFile;
  HANDLE                hMapObject;
  PUCHAR                uFileMap;
  DWORD			dwCount;

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

  pImageSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pImageNtHeaders + sizeof (IMAGE_NT_HEADERS));
  for (dwCount = 0; dwCount != pImageNtHeaders->FileHeader.NumberOfSections; dwCount++) {
    printf("Name:                   %s\n", pImageSectionHeader->Name);
    printf("Misc:                   %08X\n", pImageSectionHeader->Misc);
    printf("VirtualAddress:         %08X\n", pImageSectionHeader->VirtualAddress);
    printf("SizeOfRawData:          %08X\n", pImageSectionHeader->SizeOfRawData);
    printf("PointerToRawData:       %08X\n", pImageSectionHeader->PointerToRawData);
    printf("PointerToRelocations:   %08X\n", pImageSectionHeader->PointerToRelocations);
    printf("PointerToLinenumbers:   %08X\n", pImageSectionHeader->PointerToLinenumbers);
    printf("NumberOfRelocations:    %04X\n", pImageSectionHeader->NumberOfRelocations);
    printf("NumberOfLinenumbers:    %04X\n", pImageSectionHeader->NumberOfLinenumbers);
    printf("Characteristics:        %08X", pImageSectionHeader->Characteristics);
    viewImageSectionHeaderCharacteristics(pImageSectionHeader->Characteristics);
    printf("\n");
    pImageSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pImageSectionHeader + sizeof (IMAGE_SECTION_HEADER));
  }

  return (0);
}

void	viewImageSectionHeaderCharacteristics(DWORD dwCharacteristics)
{
  BYTE	szCharacteristics[100];
  
  memset(szCharacteristics, 0, 100);
  szCharacteristics[0] = '(';
  if (dwCharacteristics & IMAGE_SCN_CNT_CODE)
    strcat(szCharacteristics, "CODE|");
  if (dwCharacteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
    strcat(szCharacteristics, "INITIALIZED_DATA|");
  if (dwCharacteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
    strcat(szCharacteristics, "UNINITIALIZED_DATA|");
  if (dwCharacteristics & IMAGE_SCN_LNK_OTHER)
    strcat(szCharacteristics, "LNK_OTHER|");
  if (dwCharacteristics & IMAGE_SCN_LNK_INFO)
    strcat(szCharacteristics, "LNK_INFO|");
  if (dwCharacteristics & IMAGE_SCN_LNK_REMOVE)
    strcat(szCharacteristics, "LNK_REMOVE|");
  if (dwCharacteristics & IMAGE_SCN_LNK_COMDAT)
    strcat(szCharacteristics, "LNK_COMDAT|");
  if (dwCharacteristics & IMAGE_SCN_MEM_FARDATA)
    strcat(szCharacteristics, "MEM_FARDATA|");
  if (dwCharacteristics & IMAGE_SCN_MEM_PURGEABLE)
    strcat(szCharacteristics, "MEM_PURGEABLE|");
  if (dwCharacteristics & IMAGE_SCN_MEM_16BIT)
    strcat(szCharacteristics, "MEM_16BIT|");
  if (dwCharacteristics & IMAGE_SCN_MEM_LOCKED)
    strcat(szCharacteristics, "MEM_LOCKED|");
  if (dwCharacteristics & IMAGE_SCN_MEM_PRELOAD)
    strcat(szCharacteristics, "MEM_PRELOAD|");
  if (dwCharacteristics & IMAGE_SCN_LNK_NRELOC_OVFL)
    strcat(szCharacteristics, "LNK_NRELOC_OVFL|");  
  if (dwCharacteristics & IMAGE_SCN_MEM_DISCARDABLE)
    strcat(szCharacteristics, "MEM_DISCARDABLE|");  
  if (dwCharacteristics & IMAGE_SCN_MEM_NOT_CACHED)
    strcat(szCharacteristics, "MEM_NOT_CACHED|");  
  if (dwCharacteristics & IMAGE_SCN_MEM_NOT_PAGED)
    strcat(szCharacteristics, "MEM_NOT_PAGED|");  
  if (dwCharacteristics & IMAGE_SCN_MEM_SHARED)
    strcat(szCharacteristics, "MEM_SHARED|");  
  if (dwCharacteristics & IMAGE_SCN_MEM_EXECUTE)
    strcat(szCharacteristics, "MEM_EXECUTE|");  
  if (dwCharacteristics & IMAGE_SCN_MEM_READ)
    strcat(szCharacteristics, "MEM_READ|");  
  if (dwCharacteristics & IMAGE_SCN_MEM_WRITE)
    strcat(szCharacteristics, "MEM_WRITE|");    
  szCharacteristics[strlen(szCharacteristics) - 1] = ')';
  szCharacteristics[strlen(szCharacteristics)] = '\0';
  printf(" %s\n", szCharacteristics);
}
