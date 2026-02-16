<div align="center">

# mono-runtime-injector

![C](https://img.shields.io/badge/C-A8B9CC?style=flat-square&logo=c&logoColor=black)
![C++](https://img.shields.io/badge/C++-00599C?style=flat-square&logo=cplusplus&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows_x64-0078D4?style=flat-square&logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

**Windows DLL that injects .NET assemblies into Mono runtime processes.**

Hooks into the Mono JIT pipeline to load and execute managed code from an embedded byte buffer at runtime using reconstructed internal functions, PEB module spoofing, and pattern-scanned method resolution.

</div>

---

## Architecture

```
DllMain (DLL_PROCESS_ATTACH)
   |
   +-- CreateThread --> start()
                          |
                          +-- PEB walk: spoof module entry as ntdll.dll
                          +-- MinHook: hook NtCreateFile (block file enumeration)
                          +-- Locate mono-2.0-bdwgc.dll base address
                          +-- JIT hook: patch PreloaderUI.Update call site
                                |
                                +-- PreloaderUIUpdate (payload)
                                      |
                                      +-- mono_image_open_from_data (embedded DLL buffer)
                                      +-- mono_assembly_load_from
                                      +-- mono_class_from_name --> MonoCheat.Entry
                                      +-- mono_compile_method --> Entry.Init
                                      +-- invoke Entry.Init()
                                      +-- unhook and restore original
```

## How It Works

### 1. Module Spoofing

On entry, the injector walks the PEB `InMemoryOrderModuleList` to find its own `LDR_DATA_TABLE_ENTRY`. It then copies metadata from `ntdll.dll`'s entry -- `SigningLevel`, `LoadReason`, `BaseNameHashValue`, `LoadTime`, `TimeDateStamp` -- and overwrites its own `BaseDllName` and `FullDllName` to point to `C:\Windows\System32\ntdll.dll`.

### 2. NtCreateFile Hook

Uses [MinHook](https://github.com/TsudaKageworthy/minhook) to intercept `NtCreateFile`. The hook checks `ObjectAttributes->ObjectName` and returns `STATUS_ACCESS_VIOLATION` for requests targeting the host executable, `BugSplat64.dll`, or `ntdll.dll` -- preventing file-based integrity checks from reading the original modules.

### 3. Mono JIT Hooking

The `JitHook` class in `HookLib.h`:

1. Resolves the target method by name using `mono_method_desc_new` + `mono_method_desc_search_in_image`
2. Finds the JIT-compiled code via pattern-scanned `mini_lookup_method`
3. Locates the `call r11` instruction within the compiled method body
4. Overwrites the 8-byte function pointer preceding it with the payload address

### 4. Assembly Loading (Reconstructed Internals)

Core Mono functions are **not called via exports**. Instead, they are reconstructed from reverse-engineered offsets into `mono-2.0-bdwgc.dll`:

| Function | Purpose |
|:---------|:--------|
| `mono_image_open_from_data` | Load a PE image from a raw byte buffer |
| `mono_assembly_load_from` | Create an assembly from a loaded image |
| `mono_compile_method` | JIT-compile a method and return its native address |
| `mono_error_cleanup` | Free Mono error state structures |
| `free_base` | Heap free through Mono's internal allocator |

### 5. Pattern Scanning

`pattern.cpp` implements a byte pattern scanner supporting wildcards (`?`). Used to locate internal Mono functions by signature rather than hardcoded addresses, providing resilience across minor version changes.

## Project Structure

```
MonoInjector/
  dllmain.cpp              Entry point, hooks, reconstructed Mono internals
  HookLib.h                JIT hook class, method resolution, pattern-based lookup
  pattern.h / pattern.cpp  Byte pattern scanner with wildcard support
  Utils/
    Utils.h/
      Utils.h              Helper for calling Mono exports by name at runtime
      lazy_import.h        Lazy import resolution (avoids static IAT entries)
      dll_buffer.h         Embedded .NET assembly as a byte array
    Spoof Call/
      Safe Call.h          Spoofed call frame helpers
      SpoofCall.cpp        Implementation
MonoInjector.sln           Visual Studio solution
```

## Building

### Requirements

- Visual Studio 2019+ with C++ desktop workload
- Windows SDK (x64)
- [MinHook](https://github.com/TsudaKageworthy/minhook)

### Steps

1. Open `MonoInjector.sln` in Visual Studio
2. Configure MinHook include/lib paths (NuGet or manual)
3. Place your compiled .NET assembly bytes in `Utils/Utils.h/dll_buffer.h` as the `dll_array` byte array
4. Build in **Release | x64**

## Key Techniques

| Technique | Implementation |
|:----------|:---------------|
| **PEB spoofing** | Overwrites loader data to disguise module identity |
| **Lazy imports** | All Win32 calls via `LI_FIND` macros -- no static IAT entries |
| **Reconstructed internals** | Core Mono functions rebuilt from offsets, not called via exports |
| **Pattern scanning** | Byte signatures with wildcards for resilient function location |
| **JIT call-site patching** | Overwrites compiled method's indirect call target |

## Disclaimer

This project is provided for **educational and research purposes only**. Use it responsibly and in compliance with applicable laws and terms of service.
