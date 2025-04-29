#define _CRT_SECURE_NO_DEPRECATE

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string>
#include "profiler.h"

enum PATCH_MODE {
    PATCH_MODE_PATTERN_RELATIVE_CALLSITE,
    PATCH_MODE_PATTERN_ENTRY,
    PATCH_MODE_SYMBOL_ENTRY, // not implemented
    NUM_PATCH_MODES
};

struct CustomTracerTLS {
    uint64_t ret_stack[256];
    uint64_t ret_stack_idx = 0;
};

#define CUSTOM_TLS_SIZE 0x10000
inline CustomTracerTLS* g_tls[CUSTOM_TLS_SIZE];

extern "C" void* allocate_tracer_tls()
{
    return new CustomTracerTLS;
}

extern "C" void ret_stack_push(void* tls, uint64_t ret);
extern "C" uint64_t ret_stack_pop(void* tls);

std::string get_tracer_commandfile();
void tracer_init(std::string command_file);
char* get_allocation_near_preferred(void* preferred_address, uint64_t size);
int trace_relative_call(const char* found_pattern_ptr, uint32_t pattern_call_instruction_offset, const char* event_name);
int trace_entry(const char* found_pattern_ptr, uint32_t pattern_call_instruction_offset, const char* event_name);
int trace_patterns(const char* pattern_to_find, uint64_t pattern_length, uint32_t pattern_aux_offset, const char* event_name, PATCH_MODE mode);
int trace_symbols(const char* symbol_to_find, uint64_t pattern_length, uint32_t pattern_aux_offset, const char* event_name);

// Export functions to allow external control of the profiler
extern "C" __declspec(dllexport) void init_profiler()
{
    tracer_init(get_tracer_commandfile());
    OutputDebugStringA("Profiler Initialized.\n");
    char out_dir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, out_dir);
    OutputDebugStringA("Current process working directory:\n");
    OutputDebugStringA(out_dir);
}

extern "C" __declspec(dllexport) void start_profiler()
{
    LOP::profiler_enable();
    OutputDebugStringA("Profiler started.\n");
}

extern "C" __declspec(dllexport) void stop_profiler()
{
    LOP::profiler_disable();
    LOP::profiler_flush();
    OutputDebugStringA("Profiler stopped and data flushed.\n");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    return TRUE;
}

std::string get_tracer_commandfile()
{
    // Open the file mapping
    HANDLE shared_file_map = OpenFileMappingA(FILE_MAP_READ, FALSE, "TracerDLL_CommandsFile");
    if (shared_file_map == NULL) {
        OutputDebugStringA("No commandfile string provided to TracerDLL.\n");
        return "";
    }

    // Map view of the file
    LPVOID shared_map_view = MapViewOfFile(shared_file_map, FILE_MAP_READ, 0, 0, sizeof(LPVOID));
    if (shared_map_view == NULL) {
        OutputDebugStringA("Couldn't map view of commandfile string.\n");
        CloseHandle(shared_file_map);
        return "";
    }

    // Get the pointer to the parameter
    char command_file[1024] = {0};
    LPVOID param_ptr = *((LPVOID*)shared_map_view);
    if (param_ptr != NULL) {
        // Read the string parameter
        if (ReadProcessMemory(GetCurrentProcess(), param_ptr, command_file, sizeof(command_file)-1, NULL)) {
            OutputDebugStringA("TracerDLL received parameter:\n");
            OutputDebugStringA(command_file);
        }
    }

    // Clean up
    UnmapViewOfFile(shared_map_view);
    CloseHandle(shared_file_map);

    return std::string(command_file);
}

char* get_allocation_near_preferred(void* preferred_address, uint64_t size)
{
    preferred_address = (void*)((uintptr_t)preferred_address & ~0xFFFULL); // Align to page boundary
    char* new_trampoline = nullptr;

    // Try a few locations around the target address
    for (int attempt = 0; attempt < 1024 && new_trampoline == nullptr; attempt++) {
        // Try different offsets in both directions
        intptr_t offset = (attempt / 2) * 0x10000 * (attempt % 2 == 0 ? 1 : -1);
        void* try_address = (void*)((uintptr_t)preferred_address + offset);

        new_trampoline = (char*)VirtualAlloc(
            try_address,                    // Try to allocate at or near this address
            size,                           // Size to allocate
            MEM_COMMIT | MEM_RESERVE,       // Allocation type
            PAGE_EXECUTE_READWRITE          // Memory protection
        );

        if (new_trampoline != nullptr) {
            break; // Allocation succeeded
        }
    }

    // Fallback to any available location if all attempts failed
    if (new_trampoline == nullptr) {
        OutputDebugStringA("Failed to allocate memory for trampoline.");// Error: %d\n", GetLastError());
        return nullptr;
    }

    return new_trampoline;
}

int trace_relative_call(const char* found_pattern_ptr, uint32_t pattern_call_instruction_offset, const char* event_name)
{
    static char trampoline_string[] =
        "\x50"                                      // push        rax  
        "\x51"                                      // push        rcx  
        "\x52"                                      // push        rdx  
        "\x41\x50"                                  // push        r8  
        "\x41\x51"                                  // push        r9  
        "\x41\x52"                                  // push        r10  
        "\x41\x53"                                  // push        r11  
        "\x48\xB9\x00\x00\x00\x00\x00\x00\x00\x00"  // mov         rcx, <64bit patch> 
        "\x48\xBA\x00\x00\x00\x00\x00\x00\x00\x00"  // mov         rdx, <64bit patch>
        "\xFF\xD2"                                  // call        rdx  
        "\x41\x5B"                                  // pop         r11  
        "\x41\x5A"                                  // pop         r10  
        "\x41\x59"                                  // pop         r9  
        "\x41\x58"                                  // pop         r8  
        "\x5A"                                      // pop         rdx  
        "\x59"                                      // pop         rcx  
        "\x58"                                      // pop         rax  
        "\x48\xBA\x00\x00\x00\x00\x00\x00\x00\x00"  // mov         rdx, <64bit patch>
        "\xFF\xD2"                                  // call        rdx   
        "\x50"                                      // push        rax  
        "\x51"                                      // push        rcx  
        "\x52"                                      // push        rdx  
        "\x41\x50"                                  // push        r8  
        "\x41\x51"                                  // push        r9  
        "\x41\x52"                                  // push        r10  
        "\x41\x53"                                  // push        r11  
        "\x48\xB9\x00\x00\x00\x00\x00\x00\x00\x00"  // mov         rcx, <64bit patch>
        "\x48\xBA\x00\x00\x00\x00\x00\x00\x00\x00"  // mov         rdx, <64bit patch>
        "\xFF\xD2"                                  // call        rdx  
        "\x41\x5B"                                  // pop         r11  
        "\x41\x5A"                                  // pop         r10  
        "\x41\x59"                                  // pop         r9  
        "\x41\x58"                                  // pop         r8  
        "\x5A"                                      // pop         rdx  
        "\x59"                                      // pop         rcx  
        "\x58"                                      // pop         rax  
        "\x48\xBA\x00\x00\x00\x00\x00\x00\x00\x00"  // mov         rdx, <64bit patch>
        "\xFF\xE2";                                 // jmp         rdx  

    DWORD oldProtection;
    VirtualProtect((void*)found_pattern_ptr, 1, PAGE_EXECUTE_READWRITE, &oldProtection);

    const uint64_t trampoline_source_size = sizeof(trampoline_string);

    int32_t original_call_offset = *(int32_t*) (found_pattern_ptr + pattern_call_instruction_offset + 1);

    char* new_trampoline = get_allocation_near_preferred((void*)found_pattern_ptr, trampoline_source_size);
    if (new_trampoline == nullptr)
    {
        OutputDebugStringA("Failed to allocate memory for trampoline.");// Error: %d\n", GetLastError());
        return 1;
    }

    memcpy(new_trampoline, trampoline_string, trampoline_source_size);

    *(uint64_t*)(new_trampoline + 13) = (uint64_t) event_name;
    *(uint64_t*)(new_trampoline + 23) = (uint64_t) LOP::emit_begin_event;
    *(uint64_t*)(new_trampoline + 46) = (uint64_t)(found_pattern_ptr + pattern_call_instruction_offset + original_call_offset + 5);
    *(uint64_t*)(new_trampoline + 69) = (uint64_t) event_name;
    *(uint64_t*)(new_trampoline + 79) = (uint64_t) LOP::emit_end_event;
    *(uint64_t*)(new_trampoline + 102) = (uint64_t) (found_pattern_ptr + pattern_call_instruction_offset + 5);

    // This is final call address switch. We need to do that in one instruction.
    uint64_t overwrite_value = 
          (*(uint64_t*)(found_pattern_ptr + pattern_call_instruction_offset - 3))       & 0x00000000000000FF
        | (*(uint64_t*)(found_pattern_ptr + pattern_call_instruction_offset - 2) << 8)  & 0x000000000000FF00
        | (*(uint64_t*)(found_pattern_ptr + pattern_call_instruction_offset - 1) << 16) & 0x0000000000FF0000
        | 0xE9000000
        | ((uint64_t)(new_trampoline - found_pattern_ptr - pattern_call_instruction_offset - 5) << 32) & 0xFFFFFFFF00000000;

    *(uint64_t*)(found_pattern_ptr + pattern_call_instruction_offset - 3) = overwrite_value;

    return 0;
}

int trace_entry(const char* found_pattern_ptr, uint32_t prolog_copy_size, const char* event_name)
{

    static char trampoline_string_emit_begin[] =
        "\x50"                                      // push        rax  
        "\x51"                                      // push        rcx  
        "\x52"                                      // push        rdx  
        "\x41\x50"                                  // push        r8  
        "\x41\x51"                                  // push        r9  
        "\x41\x52"                                  // push        r10  
        "\x41\x53"                                  // push        r11  

        "\x48\xB9\x00\x00\x00\x00\x00\x00\x00\x00"  // mov         rcx, <64bit patch> 
        "\x48\x8B\x54\x24\x38"                      // mov         rdx, qword ptr [rsp+38h]  
        "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00"  // mov         rax, <64bit patch> 
        "\xFF\xD0"                                  // call        rax 
        "\x48\xB9\x00\x00\x00\x00\x00\x00\x00\x00"  // mov         rcx, <64bit patch> 
        "\x48\x89\x4C\x24\x38"                      // mov         [rsp+38h], rcx

        "\x48\xB9\x00\x00\x00\x00\x00\x00\x00\x00"  // mov         rcx, <64bit patch> 
        "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00"  // mov         rax, <64bit patch> 
        "\xFF\xD0"                                  // call        rax 

        "\x41\x5B"                                  // pop         r11  
        "\x41\x5A"                                  // pop         r10  
        "\x41\x59"                                  // pop         r9  
        "\x41\x58"                                  // pop         r8  
        "\x5A"                                      // pop         rdx  
        "\x59"                                      // pop         rcx  
        "\x58";                                     // pop         rax

    static char trampoline_string_call_original_target[] =
        "\xE9\x00\x00\x00\x00";                     // jmp         <32bit patch> 
    
    static char trampoline_string_emit_end_and_return_to_caller[] =
        "\x50"                                      // push        rax  
        "\x51"                                      // push        rcx  
        "\x52"                                      // push        rdx  
        "\x41\x50"                                  // push        r8  
        "\x41\x51"                                  // push        r9  
        "\x41\x52"                                  // push        r10  
        "\x41\x53"                                  // push        r11  

        "\x48\xB9\x00\x00\x00\x00\x00\x00\x00\x00"  // mov         rcx, <64bit patch>
        "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00"  // mov         rax, <64bit patch> 
        "\xFF\xD0"                                  // call        rax  

        "\x48\xB9\x00\x00\x00\x00\x00\x00\x00\x00"  // mov         rcx, <64bit patch> 
        "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00"  // mov         rax, <64bit patch> 
        "\xFF\xD0"                                  // call        rax 
        "\x48\x89\x44\x24\xF8"                      // mov         [rsp-8], rax

        "\x41\x5B"                                  // pop         r11  
        "\x41\x5A"                                  // pop         r10  
        "\x41\x59"                                  // pop         r9  
        "\x41\x58"                                  // pop         r8  
        "\x5A"                                      // pop         rdx  
        "\x59"                                      // pop         rcx  
        "\x58"                                      // pop         rax  
        "\xFF\x64\x24\xC0";                         // jmp         [rsp-64]  

    DWORD oldProtection;
    VirtualProtect((void*)found_pattern_ptr, 1, PAGE_EXECUTE_READWRITE, &oldProtection);

    const uint64_t trampoline_source_size = sizeof(trampoline_string_emit_begin) +
        sizeof(trampoline_string_call_original_target) +
        sizeof(trampoline_string_emit_end_and_return_to_caller) +
        prolog_copy_size;

    char* new_trampoline = get_allocation_near_preferred((void*)found_pattern_ptr, trampoline_source_size);
    if (new_trampoline == nullptr)
    {
        OutputDebugStringA("Failed to allocate memory for trampoline.");// Error: %d\n", GetLastError());
        return 1;
    }

    char* jump_to_original_offset = new_trampoline + sizeof(trampoline_string_emit_begin) - 1 + prolog_copy_size;
    char* return_trampoline_offset = new_trampoline + sizeof(trampoline_string_emit_begin) - 1 + prolog_copy_size + sizeof(trampoline_string_call_original_target) - 1;

    memcpy(new_trampoline, trampoline_string_emit_begin, sizeof(trampoline_string_emit_begin));
    memcpy(new_trampoline + sizeof(trampoline_string_emit_begin) - 1, found_pattern_ptr, prolog_copy_size);
    memcpy(jump_to_original_offset,
           trampoline_string_call_original_target, 
           sizeof(trampoline_string_call_original_target));
    memcpy(return_trampoline_offset,
           trampoline_string_emit_end_and_return_to_caller,
           sizeof(trampoline_string_emit_end_and_return_to_caller));

    *(uint64_t*)(new_trampoline + 13) = (uint64_t) &g_tls;
    *(uint64_t*)(new_trampoline + 28) = (uint64_t) ret_stack_push;
    *(uint64_t*)(new_trampoline + 40) = (uint64_t) return_trampoline_offset;

    *(uint64_t*)(new_trampoline + 55) = (uint64_t) event_name;
    *(uint64_t*)(new_trampoline + 65) = (uint64_t) LOP::emit_begin_event;

    *(int32_t*)(jump_to_original_offset + 1) = (int32_t) (found_pattern_ptr + prolog_copy_size - jump_to_original_offset - 5);

    *(uint64_t*)(return_trampoline_offset + 13) = (uint64_t) event_name;
    *(uint64_t*)(return_trampoline_offset + 23) = (uint64_t) LOP::emit_end_event;

    *(uint64_t*)(return_trampoline_offset + 35) = (uint64_t) &g_tls;
    *(uint64_t*)(return_trampoline_offset + 45) = (uint64_t) ret_stack_pop;

    // This is final call address switch. We need to do that in one instruction.
    uint64_t overwrite_value = 
          0x00000000000000E9
        | ((uint64_t)(new_trampoline - found_pattern_ptr - 5) << 8) & 0x000000FFFFFFFF00
        | (*(uint64_t*)(found_pattern_ptr + 5) << 40) & 0x0000FF0000000000
        | (*(uint64_t*)(found_pattern_ptr + 6) << 48) & 0x00FF000000000000
        | (*(uint64_t*)(found_pattern_ptr + 7) << 56) & 0xFF00000000000000;

    *(uint64_t*)(found_pattern_ptr) = overwrite_value;

    return 0;
}

int trace_patterns(const char* pattern_to_find, uint64_t pattern_length, uint32_t pattern_aux_offset, const char* event_name, PATCH_MODE mode)
{
    const char* found_pattern_ptr = nullptr;

    // Search through all executable memory regions in current process
    MEMORY_BASIC_INFORMATION mbi;
    LPCVOID address = nullptr;
    uint32_t successful_patterns = 0;
    uint32_t failed_patterns = 0;
    while (VirtualQuery(address, &mbi, sizeof(mbi)) != 0 && found_pattern_ptr == nullptr)
    {
        // Move to next region for next iteration
        address = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);

        // Skip non-committed or non-executable memory
        if (mbi.State != MEM_COMMIT || 
            !(mbi.Protect & (PAGE_EXECUTE | 
                PAGE_EXECUTE_READ | 
                PAGE_EXECUTE_READWRITE | 
                PAGE_EXECUTE_WRITECOPY)))
        {
            continue;
        }

        // Search for pattern in this memory region
        const char* region_start = (const char*)mbi.BaseAddress;
        SIZE_T region_size = mbi.RegionSize;

        // Don't search past the end of the region
        for (SIZE_T i = 0; i + pattern_length <= region_size; i++)
        {
            if (memcmp(region_start + i, pattern_to_find, pattern_length) == 0)
            {
                found_pattern_ptr = region_start + i;

                std::string event_name_str = event_name;
                event_name_str += "#";
                event_name_str += std::to_string(failed_patterns+successful_patterns);

                // Allocate dynamically as this string needs to
                // be alive potentially till the process exit.
                std::string* event_name_str_dyn = new std::string(event_name_str);

                uint64_t ret = 0;
                switch (mode)
                {
                case PATCH_MODE_PATTERN_RELATIVE_CALLSITE:
                    ret = trace_relative_call(found_pattern_ptr, pattern_aux_offset, event_name_str_dyn->c_str());
                    break;
                case PATCH_MODE_PATTERN_ENTRY:
                    ret = trace_entry(found_pattern_ptr, pattern_aux_offset, event_name_str_dyn->c_str());
                    break;
                }

                if (ret) failed_patterns++;
                else successful_patterns++;
            }
        }
    }

    if (found_pattern_ptr == nullptr) {
        OutputDebugStringA("Failed to find the pattern for event name:\n");
        OutputDebugStringA(event_name);
        return 1;
    }



    OutputDebugStringA("Patterns stats for event");
    OutputDebugStringA(event_name);

    char tmpval[128];
    OutputDebugStringA("Failed:\n");
    OutputDebugStringA(_itoa(failed_patterns, tmpval, 10));
    OutputDebugStringA("Successful:\n");
    OutputDebugStringA(_itoa(successful_patterns, tmpval, 10));
    return 0;
}

int trace_symbols(const char* symbol_to_find, uint64_t pattern_length, uint32_t pattern_aux_offset, const char* event_name)
{
    OutputDebugStringA("Failed to find the symbol for event name:\n");
    OutputDebugStringA(event_name);
    return 1;
}

void tracer_init(std::string command_file)
{
    // Open file to get commands.
    FILE* file = fopen(command_file.c_str(), "r");
    if (file == NULL) {
        OutputDebugStringA("Failed to open command file:\n");
        OutputDebugStringA(command_file.c_str());
        return;
    }

    // The file has following format:
    // <pattern> <length> <offset> <event_name>
    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        char pattern[64];
        uint64_t length;
        uint32_t offset;
        PATCH_MODE mode;
        char event_name[64];
        // Parse the line
        if (sscanf(line, "%u %s %u %s", &mode, pattern, &offset, event_name) == 4) {
            uint64_t length = strlen(pattern);
            if (mode >= NUM_PATCH_MODES) {
                OutputDebugStringA("Unknown patch mode for event:\n");
                OutputDebugStringA(event_name);
                continue;
            }
            // Allocate the event name dynamically as it needs to be alive when process wraps.
            auto event_name_dyn = new std::string(event_name);

            switch (mode)
            {
            case PATCH_MODE_PATTERN_RELATIVE_CALLSITE:
            case PATCH_MODE_PATTERN_ENTRY:
                {
                    // Convert hex string to binary.
                    char binary_pattern[64];
                    size_t binary_length = 0;
                    for (size_t i = 0; i < length; i += 2) {
                        sscanf(pattern + i, "%2hhx", &binary_pattern[binary_length++]);
                    }
                    trace_patterns(binary_pattern, binary_length, offset, event_name_dyn->c_str(), mode);
                }
                break;
            case PATCH_MODE_SYMBOL_ENTRY:
                trace_symbols(pattern, length, offset, event_name_dyn->c_str());
                break;
            }
        }
    }
}

