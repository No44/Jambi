/**
 ** peviewimageoptionalheader.c
 */

#include <windows.h>
#include <stdio.h>

void viewOptionalHeaderDirectoryEntries(PIMAGE_DATA_DIRECTORY);
void viewOptionalHeaderSubsystem(WORD);

int				main(int argc, char **argv) 
{
  PIMAGE_DOS_HEADER		pImageDosHeader;
  PIMAGE_NT_HEADERS		pImageNtHeaders;
  PIMAGE_OPTIONAL_HEADER	pImageOptionalHeader;
  PIMAGE_DATA_DIRECTORY		pImageDataDirectory;
  HANDLE			hFile;
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
  
  pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER) &(pImageNtHeaders->OptionalHeader);
  printf("Magic:                        0x%04x", pImageOptionalHeader->Magic);
  ((pImageOptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC) 
   ? printf(" (HDR32)\n")
   : printf(" (HDR64)\n"));
  printf("MajorLinkerVersion:           0x%02x\n", pImageOptionalHeader->MajorLinkerVersion);
  printf("MinorLinkerVersion:           0x%02x\n", pImageOptionalHeader->MinorLinkerVersion);
  printf("SizeOfCode:                   0x%08x\n", pImageOptionalHeader->SizeOfCode);
  printf("SizeOfInitializedData:        0x%08x\n", pImageOptionalHeader->SizeOfInitializedData);
  printf("SizeOfUninitializedData:      0x%08x\n", pImageOptionalHeader->SizeOfUninitializedData);
  printf("AddressOfEntryPoint:          0x%08x\n", pImageOptionalHeader->AddressOfEntryPoint);
  printf("BaseOfCode:                   0x%08x\n", pImageOptionalHeader->BaseOfCode);
  printf("BaseOfData:                   0x%08x\n", pImageOptionalHeader->BaseOfData);
  printf("ImageBase:                    0x%08x\n", pImageOptionalHeader->ImageBase);
  printf("SectionAlignment:             0x%08x\n", pImageOptionalHeader->SectionAlignment);
  printf("FileAlignment:                0x%08x\n", pImageOptionalHeader->FileAlignment);
  printf("MajorOperatingSystemVersion:  0x%04x\n", pImageOptionalHeader->MajorOperatingSystemVersion);
  printf("MinorOperatingSystemVersion:  0x%04x\n", pImageOptionalHeader->MinorOperatingSystemVersion);
  printf("MajorImageVersion:            0x%04x\n", pImageOptionalHeader->MajorImageVersion);
  printf("MinorImageVersion:            0x%04x\n", pImageOptionalHeader->MinorImageVersion);
  printf("MajorSubsystemVersion:        0x%04x\n", pImageOptionalHeader->MajorSubsystemVersion);
  printf("MinorSubsystemVersion:        0x%04x\n", pImageOptionalHeader->MinorSubsystemVersion);
  printf("SizeOfImage:                  0x%08x\n", pImageOptionalHeader->SizeOfImage);
  printf("SizeOfHeaders:                0x%08x\n", pImageOptionalHeader->SizeOfHeaders);
  printf("CheckSum:                     0x%08x\n", pImageOptionalHeader->CheckSum);
  printf("Subsystem:                    0x%04x", pImageOptionalHeader->Subsystem);
  viewOptionalHeaderSubsystem(pImageOptionalHeader->Subsystem);
  printf("DllCharacteristics:           0x%08x\n", pImageOptionalHeader->DllCharacteristics);
  printf("SizeOfStackReserve:           0x%08x\n", pImageOptionalHeader->SizeOfStackReserve);
  printf("SizeOfStackCommit:            0x%08x\n", pImageOptionalHeader->SizeOfStackCommit);
  printf("SizeOfHeapReserve:            0x%08x\n", pImageOptionalHeader->SizeOfHeapReserve);
  printf("SizeOfHeapCommit:             0x%08x\n", pImageOptionalHeader->SizeOfHeapCommit);
  printf("LoaderFlags:                  0x%08x\n", pImageOptionalHeader->LoaderFlags);
  printf("NumberOfRvaAndSizes:          0x%08x\n", pImageOptionalHeader->NumberOfRvaAndSizes);
  viewOptionalHeaderDirectoryEntries(pImageOptionalHeader->DataDirectory);  
  
  return (0);
}

void	viewOptionalHeaderDirectoryEntries(PIMAGE_DATA_DIRECTORY pImageDataDirectory)
{
  char	*DirectoryNames[] = {
    "EXPORT        ",
    "IMPORT        ",
    "RESOURCE      ", 
    "EXCEPTION     ",
    "SECURITY      ",     
    "BASERELOC     ",    
    "DEBUG         ",         
    "ARCHITECTURE  ",  
    "GLOBALPTR     ",     
    "TLS           ",           
    "LOAD_CONFIG   ",   
    "BOUND_IMPORT  ",  
    "IAT           ",           
    "IMPORT        ",  
    "COM_DESCRIPTOR",
    "?             ",
    "?             "
  };
  DWORD	dwCount;

  printf("\nDIRECTORY ENTRIES   VirtualAddress    Size\n");
  for (dwCount = 0; dwCount < 16; dwCount++) {
    if (pImageDataDirectory[dwCount].Size)
      printf("   %s   0x%08x  0x%08x\n", DirectoryNames[dwCount], 
	     pImageDataDirectory[dwCount].VirtualAddress, 
	     pImageDataDirectory[dwCount].Size);
  }
}

void	viewOptionalHeaderSubsystem(WORD Subsystem)
{
  char	*Subsystems[] = {
    "UNKNOWN",
    "NATIVE",
    "WINDOWS_GUI",
    "WINDOWS_CUI",
    "?",  
    "OS2_CUI",
    "?",  
    "POSIX_CUI"
    "NATIVE_WINDOWS",    
    "WINDOWS_CE_GUI",      
    "EFI_APPLICATION",     
    "EFI_BOOT_SERVICE_DRIVER",    
    "EFI_RUNTIME_DRIVER",   
    "EFI_ROM",              
    "XBOX",                
    "?",  
    "WINDOWS_BOOT_APPLICATION",
  };

  printf(" (%s)\n", Subsystems[Subsystem]);
}
