# MonoInjector

A Windows DLL that injects .NET assemblies into processes using the Mono runtime (`mono-2.0-bdwgc.dll`). It hooks into the Mono JIT pipeline to load and execute managed code from an embedded byte buffer at runtime.

## How It Works

1. **DLL Entry** -- On `DLL_PROCESS_ATTACH`, a new thread is spawned to run the main injection logic.

2. **Module Spoofing** -- The injector walks the PEB loader data to locate its own module entry and overwrites the `BaseDllName`, `FullDllName`, `SigningLevel`, `LoadReason`, and other metadata to mimic `ntdll.dll`. This hides the injected DLL from basic module enumeration.

3. **NtCreateFile Hook** -- Uses [MinHook](https://github.com/TsudaKageworthy/minhook) to hook `NtCreateFile`, blocking file access to the host image, `BugSplat64.dll`, and `ntdll.dll` by returning `STATUS_ACCESS_VIOLATION` for matching object names.

4. **Mono JIT Hook** -- Locates the `PreloaderUI.Update` method via Mono's assembly/method descriptor APIs, then patches the JIT-compiled call site to redirect execution to the injector's payload function.

5. **Assembly Loading** -- The payload function calls reconstructed Mono internals (`mono_image_open_from_data`, `mono_assembly_load_from`, `mono_compile_method`) using hardcoded offsets into the Mono module. It loads the embedded DLL buffer as a Mono image, resolves the `MonoCheat.Entry.Init` method, JIT-compiles it, and invokes it.

6. **Cleanup** -- After the managed payload executes, the JIT hook is removed by restoring the original function pointer.

## Project Structure

```
MonoInjector/
  dllmain.cpp            Main entry point, hooks, Mono function recreations
  HookLib.h              JIT hook class, method resolution via pattern scanning
  pattern.h / pattern.cpp  Byte pattern scanner for locating functions in memory
  Utils/
    Utils.h/
      Utils.h            Helper for calling Mono exports by name
      lazy_import.h      Lazy import resolution (LI_FIND / LI_MODULE macros)
      dll_buffer.h       Embedded .NET assembly as a byte array
    Spoof Call/
      Safe Call.h        Spoofed call helpers
      SpoofCall.cpp      Spoof call implementation
MonoInjector.sln         Visual Studio solution
```

## Building

### Requirements

- Visual Studio 2019+ with the C++ desktop workload
- Windows SDK
- [MinHook](https://github.com/TsudaKageworthy/minhook) (linked as a dependency)

### Steps

1. Open `MonoInjector.sln` in Visual Studio.
2. Ensure MinHook headers and library are available (add via NuGet or manually configure include/lib paths).
3. Place your compiled .NET assembly bytes in `Utils/Utils.h/dll_buffer.h` as the `dll_array` byte array.
4. Build the solution in **Release | x64**.

## Key Implementation Details

- **No exported Mono functions for core operations** -- `mono_image_open_from_data`, `mono_assembly_load_from`, and `mono_compile_method` are reconstructed from reverse-engineered Mono internals using hardcoded offsets. This avoids relying on exports that may be monitored.
- **Pattern scanning** -- `HookLib.h` uses byte pattern signatures to locate Mono's JIT lookup functions at runtime, making the hook resilient to minor module rebases.
- **Lazy imports** -- All Win32 API calls go through `LI_FIND` macros to avoid static import table entries.

## Disclaimer

This project is provided for **educational and research purposes only**. Use it responsibly and in compliance with applicable laws and terms of service.
