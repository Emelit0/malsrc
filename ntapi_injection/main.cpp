// An example of injecting a DLL into a process using the NT API

int main(int argc, char* argv[]) 
{		

	// Get the process ID from the command line
	DWORD processId = atoi(argv[1]);

	// Get the DLL path from the command line
	char* dllPath = argv[2];

	// Open the target process
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	// Allocate memory in the target process for the DLL path
	LPVOID dllPathAddress = VirtualAllocEx(process, NULL, strlen(dllPath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Write the DLL path to the target process
	WriteProcessMemory(process, dllPathAddress, dllPath, strlen(dllPath), NULL);
			
	// Get the address of the LoadLibraryA function
	LPVOID loadLibraryAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
		
	// Create a remote thread in the target process to load the DLL
	HANDLE thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, dllPathAddress, 0, NULL);

	// Wait for the remote thread to finish
	WaitForSingleObject(thread, INFINITE);

	// Clean up
	CloseHandle(thread);
	CloseHandle(process);
	VirtualFreeEx(process, dllPathAddress, 0, MEM_RELEASE);

	return 0;

}