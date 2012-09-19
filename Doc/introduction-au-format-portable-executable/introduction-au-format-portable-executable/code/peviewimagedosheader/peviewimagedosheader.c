/**
 ** peviewimagedosheader.c
 */

#include <windows.h>
#include <stdio.h>

int			main(int argc, char **argv) 
{
  PIMAGE_DOS_HEADER	pImageDosHeader;
  HANDLE		hFile;
  HANDLE		hMapObject;
  PUCHAR	       	uFileMap;

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
  
  printf("e_magic:    0x%04X (%c%c)\n", pImageDosHeader->e_magic, *uFileMap, *(uFileMap + 1));
  printf("e_lfanew:   0x%08X\n", pImageDosHeader->e_lfanew);
  
  return (0);
}

