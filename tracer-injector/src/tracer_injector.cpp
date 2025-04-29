#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <tlhelp32.h>
#include <psapi.h>


DWORD   get_process_id_from_name(LPCSTR process_name);
int     load_dll_to_remote(HANDLE process_handle, LPCSTR dll_path);
HMODULE get_remote_dll_base(HANDLE process_handle, LPCSTR dll_name);
int     write_commandfile_to_remote(HANDLE process_handle, LPCSTR dll_commandfile);
int     remote_control_loop(HANDLE process_handle, DWORD64 remote_init_function, DWORD64 remote_start_function, DWORD64 remote_stop_function);
int     get_remote_exports(HANDLE process_handle, LPCSTR dll_path, DWORD64& remote_init_function, DWORD64& remote_start_function, DWORD64& remote_stop_function);

int main(int argc, char* argv[])
{
    if (argc < 4 || argc > 5)
    {
        printf("Usage: %s <process_name> <tracer_dll_absolute_path> <commandfile_absolute_path> [<process_id>]\n", argv[0]);
        return 1;
    }

    LPCSTR process_name = argv[1];
    LPCSTR dll_path = argv[2];
    LPCSTR dll_commandfile = argv[3];
    DWORD process_id = 0;    
    if (argc == 5)
    {
        // Just use the process id specified by user.
        process_id = atoi(argv[4]);
    }
    else
    {
        process_id = get_process_id_from_name(process_name);
    }

    // Open process handle from process id 1234.
    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if (process_handle == NULL) {
        printf("Failed to open process handle. Error: %d\n", GetLastError());
        return 1;
    }

    if (write_commandfile_to_remote(process_handle, dll_commandfile))
    {
        printf("Failed to write commandfile to remote process.\n");
        return 1;
    }

    if (load_dll_to_remote(process_handle, dll_path))
    {
        printf("Failed to write commandfile to remote process.\n");
        return 1;
    }

    DWORD64 remote_init_function;
    DWORD64 remote_start_function;
    DWORD64 remote_stop_function;
    if (get_remote_exports(process_handle, dll_path, remote_init_function, remote_start_function, remote_stop_function))
    {
        printf("Failed to get remote exports.\n");
        return 1;
    }

    if (remote_control_loop(process_handle, remote_init_function, remote_start_function, remote_stop_function))
    {
        printf("Failed in remote control loop.\n");
        return 1;
    }

    CloseHandle(process_handle);

    return 0;
}


int remote_control_loop(HANDLE process_handle, DWORD64 remote_init_function, DWORD64 remote_start_function, DWORD64 remote_stop_function)
{
    HANDLE init_thread = CreateRemoteThread(process_handle, NULL, 0, 
        (LPTHREAD_START_ROUTINE)remote_init_function, NULL, 0, NULL);
    if (init_thread == NULL) {
        printf("Profiler init failed.\n");
        return 1;
    }

    WaitForSingleObject(init_thread, INFINITE);
    CloseHandle(init_thread);

    // Create a loop that will take user input. If user just presses enter, it will call the start/stop profiler functions.
    // If user would enter exit and then press enter, then we exit the loop.
    printf("Profiler ready. Press Enter to start/stop profiling or type 'exit' to quit.\n");

    bool profiler_running = false;
    char input[256];
    while (true) {
        printf(profiler_running ? "Profiler running > " : "Profiler stopped > ");
        fgets(input, sizeof(input), stdin);

        // Remove newline character if present
        size_t len = strlen(input);
        if (len > 0 && input[len - 1] == '\n') {
            input[len - 1] = '\0';
        }

        if (strcmp(input, "exit") == 0) {
            // Exit loop if user entered 'exit'
            printf("Exiting profiler control...\n");
            break;
        } else if (input[0] == '\0') {
            // Toggle profiler state when user presses Enter
            DWORD64 remote_function = profiler_running ? remote_stop_function : remote_start_function;

            HANDLE toggle_thread = CreateRemoteThread(process_handle, NULL, 0, 
                (LPTHREAD_START_ROUTINE)remote_function, NULL, 0, NULL);

            if (toggle_thread == NULL) {
                printf("Failed to create remote thread to %s profiler. Error: %d\n", 
                    profiler_running ? "stop" : "start", GetLastError());
                continue;
            }

            // Wait for thread to complete
            WaitForSingleObject(toggle_thread, INFINITE);
            CloseHandle(toggle_thread);

            profiler_running = !profiler_running;
            printf("\tProfiler %s.\n", profiler_running ? "started" : "stopped");
        } else {
            printf("Invalid command. Press Enter to toggle profiling or type 'exit' to quit.\n");
        }
    }

    // Ensure profiler is stopped when exiting
    if (profiler_running) {
        HANDLE stop_thread = CreateRemoteThread(process_handle, NULL, 0, 
            (LPTHREAD_START_ROUTINE)remote_stop_function, NULL, 0, NULL);
        if (stop_thread != NULL) {
            WaitForSingleObject(stop_thread, INFINITE);
            CloseHandle(stop_thread);
            printf("Profiler stopped before exit.\n");
        }
    }  

    return 0;
}

DWORD get_process_id_from_name(LPCSTR process_name)
{
    DWORD process_id = 0;
    // Get process id for specified process name.
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("Failed to create process snapshot. Error: %d\n", GetLastError());
        return 1;
    }

    PROCESSENTRY32 process_entry = { 0 };
    process_entry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &process_entry)) {
        do {
            char exeFileName[MAX_PATH];
            wcstombs_s(nullptr, exeFileName, process_entry.szExeFile, MAX_PATH);
            if (strncmp(exeFileName, process_name, strlen(process_name)) == 0) {
                process_id = process_entry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &process_entry));
    }

    CloseHandle(snapshot);

    if (process_id == 0) {
        printf("Failed to find process.\n");
    }
    else {
        printf("Found process with PID: %d\n", process_id);
    }

    return process_id;
}

int load_dll_to_remote(HANDLE process_handle, LPCSTR dll_path)
{
    // Allocate memory for the buffer in the target process.
    LPVOID dll_path_buffer = VirtualAllocEx(process_handle, NULL, strlen(dll_path) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (dll_path_buffer == NULL) {
        printf("Failed to allocate memory in target process. Error: %d\n", GetLastError());
        return 1;
    }

    // Write the dll path string to target process memory.
    SIZE_T bytes_written;
    if (!WriteProcessMemory(process_handle, dll_path_buffer, dll_path, strlen(dll_path) + 1, &bytes_written)) {
        printf("Failed to write memory in target process. Error: %d\n", GetLastError());
        return 1;
    }

    HANDLE thread_handle = CreateRemoteThread(process_handle, 0, 0, 
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA"), dll_path_buffer, 0, 0);
    if (thread_handle == NULL) {
        printf("Failed to create remote thread. Error: %d\n", GetLastError());
        return 1;
    }

    WaitForSingleObject(thread_handle, INFINITE);

    printf("DLL injected successfully.\n");

    CloseHandle(thread_handle);
    VirtualFreeEx(process_handle, dll_path_buffer, 0, MEM_RELEASE);

    return 0;
}

int write_commandfile_to_remote(HANDLE process_handle, LPCSTR dll_commandfile)
{
    // Allocate memory for the commandfile parameter.
    LPVOID param_buffer = VirtualAllocEx(process_handle, NULL, strlen(dll_commandfile) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (param_buffer == NULL) {
        printf("Failed to allocate memory for commandfile parameter. Error: %d\n", GetLastError());
        return 1;
    }

    // Write the commandfile parameter string to target process memory.
    SIZE_T bytes_written;
    if (!WriteProcessMemory(process_handle, param_buffer, dll_commandfile, strlen(dll_commandfile) + 1, &bytes_written)) {
        printf("Failed to write commandfile parameter to target process. Error: %d\n", GetLastError());
        return 1;
    }

    // Create file mapping for sharing commandfile parameter's address.
    HANDLE shared_file_map = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(LPVOID), "TracerDLL_CommandsFile");
    if (shared_file_map == NULL) {
        printf("Failed to create file mapping. Error: %d\n", GetLastError());
        return 1;
    }

    LPVOID shared_map_view = MapViewOfFile(shared_file_map, FILE_MAP_WRITE, 0, 0, sizeof(LPVOID));
    if (shared_map_view == NULL) {
        printf("Failed to map view of file. Error: %d\n", GetLastError());
        return 1;
    }

    // Store the pointer to the parameter in shared memory
    memcpy(shared_map_view, &param_buffer, sizeof(LPVOID));
    UnmapViewOfFile(shared_map_view);

    return 0;
}

HMODULE get_remote_dll_base(HANDLE process_handle, LPCSTR dll_name)
{
    DWORD capacity_needed;
    HMODULE handle_list[1024];
    BOOL ret = EnumProcessModules(process_handle, handle_list, sizeof(handle_list), &capacity_needed);
    if (!ret) {
        printf("Failed to enum process modules.\n");
        return NULL;
    }
    if (capacity_needed > sizeof(handle_list)) {
        printf("Too many modules Increase the variable size.\n");
        return NULL;
    }
    char module_name[1024];
    for (DWORD i = 0; i < capacity_needed / sizeof(HMODULE); i++) {
        GetModuleBaseNameA(process_handle, handle_list[i], module_name, 1024);
        if (strncmp(dll_name, module_name, strlen(dll_name)) == 0) {
            return handle_list[i];
        }
    }
    return NULL;
}

int get_remote_exports(HANDLE process_handle, LPCSTR dll_path, DWORD64& remote_init_function, DWORD64& remote_start_function, DWORD64& remote_stop_function)
{
    // Get the address of the "start_profiler" function in the loaded DLL
    HMODULE local_dll = LoadLibraryA(dll_path);
    if (local_dll == NULL) {
        printf("Failed to load DLL locally to get function address. Error: %d\n", GetLastError());
        return 1;
    }

    // Get local address of functions controling the remote profiler.
    FARPROC local_init_profiler = GetProcAddress(local_dll, "init_profiler");
    if (local_init_profiler == NULL) {
        printf("Failed to find 'init_profiler' function in DLL. Error: %d\n", GetLastError());
        return 1;
    }
    FARPROC local_start_profiler = GetProcAddress(local_dll, "start_profiler");
    if (local_start_profiler == NULL) {
        printf("Failed to find 'start_profiler' function in DLL. Error: %d\n", GetLastError());
        return 1;
    }
    FARPROC local_stop_profiler = GetProcAddress(local_dll, "stop_profiler");
    if (local_stop_profiler == NULL) {
        printf("Failed to find 'stop_profiler' function in DLL. Error: %d\n", GetLastError());
        return 1;
    }

    // Calculate the relative offset of the function from the DLL base
    DWORD64 function_init_offset  = (DWORD64)local_init_profiler  - (DWORD64)local_dll;
    DWORD64 function_start_offset = (DWORD64)local_start_profiler - (DWORD64)local_dll;
    DWORD64 function_stop_offset  = (DWORD64)local_stop_profiler  - (DWORD64)local_dll;

    // Calculate the actual address in the target process
    // Get file name from path.
    HMODULE remote_dll = get_remote_dll_base(process_handle, strrchr(dll_path, '\\') + 1);
    remote_init_function  = (DWORD64)remote_dll + function_init_offset;
    remote_start_function = (DWORD64)remote_dll + function_start_offset;
    remote_stop_function  = (DWORD64)remote_dll + function_stop_offset;

    return 0;
}
