/**
 ** gewifa.c
 ** Get win32 function address
 */

#include <windows.h>
#include <stdio.h>

int		main(int argc, char **argv)
{
  HMODULE	hLib;
  DWORD		FuncAddress;
  
  printf("Gewifa - Get win32 function address\n");
  if (argc < 3) {
    printf("%s <DLL Name> <Function Name>\n", argv[0]);
    return (-1);
  }
  if (!(hLib = LoadLibrary(argv[1]))) {
    printf("Error from LoadLibrary!\n");
    return (-1);
  }
  if (!(FuncAddress = (DWORD) GetProcAddress(hLib, argv[2]))) {
    printf("Error from GetProcAddress\n");
    return (-1);
  }
  printf("%s - %s [0x%08x]\n", argv[1], argv[2], (unsigned int) FuncAddress);
  return (0);
}
