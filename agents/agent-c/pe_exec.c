/*
 * pe_exec.c — Minimal in-process PE loader for x64 EXEs.
 *
 * Phases:
 *  1. Validate DOS → NT header (PE32+, AMD64 only)
 *  2. VirtualAlloc full image at preferred ImageBase (fallback: any address)
 *  3. Copy PE headers + each section into allocated memory
 *  4. Apply base relocations (IMAGE_REL_BASED_DIR64, type 10)
 *  5. Resolve IAT: walk IMAGE_IMPORT_DESCRIPTOR, LoadLibraryA + GetProcAddress
 *  6. Fix per-section memory protections via VirtualProtect
 *  7. Redirect stdout/stderr to anonymous pipe; create thread at EntryPoint
 *  8. Wait up to 30 s; collect and return captured output
 *
 * NOTE: This file intentionally does NOT include api_resolve.h.  The PE
 * loader needs VirtualAlloc, CreateThread, LoadLibraryA, and GetProcAddress
 * via direct calls — those symbols are not in the resolver table and must be
 * present in the IAT at link time anyway.  Mixing resolved + direct calls for
 * the same PE would also break pointer identity inside the loaded image's IAT.
 */

#include "pe_exec.h"
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Maximum time to wait for the entry point to return (30 seconds). */
#define PE_EXEC_TIMEOUT_MS 30000

/* IMAGE_REL_BASED_DIR64 = type 10 (64-bit absolute fixup).
 * Defined in MSVC / SDK headers; provide fallback for older MinGW. */
#ifndef IMAGE_REL_BASED_DIR64
#define IMAGE_REL_BASED_DIR64 10
#endif

/* ── Section characteristics to VirtualProtect flags ──────────────────────── */

#define SCN_MEM_EXECUTE  0x20000000u
#define SCN_MEM_READ     0x40000000u
#define SCN_MEM_WRITE    0x80000000u

static DWORD section_prot(DWORD chars) {
    int exec  = (chars & SCN_MEM_EXECUTE) != 0;
    int write = (chars & SCN_MEM_WRITE)   != 0;
    if (exec && write) return PAGE_EXECUTE_READWRITE;
    if (exec)          return PAGE_EXECUTE_READ;
    if (write)         return PAGE_READWRITE;
    return PAGE_READONLY;
}

/* ── Drain all available data from a pipe read handle ──────────────────────── */
/* Called after the write end is closed, so ReadFile returns 0 bytes at EOF.    */

static char *drain_pipe(HANDLE pipe_read) {
    size_t cap = 4096, len = 0;
    char *buf = (char*)malloc(cap);
    if (!buf) return NULL;

    char tmp[4096];
    DWORD rd = 0;
    while (ReadFile(pipe_read, tmp, (DWORD)sizeof(tmp), &rd, NULL) && rd > 0) {
        if (len + rd + 1 > cap) {
            cap = len + rd + 4096;
            char *nb = (char*)realloc(buf, cap);
            if (!nb) { free(buf); return NULL; }
            buf = nb;
        }
        memcpy(buf + len, tmp, rd);
        len += rd;
    }
    buf[len] = '\0';
    return buf;
}

/* ── Main PE loader ──────────────────────────────────────────────────────── */

char* exec_pe(const uint8_t *pe_bytes, size_t pe_len) {

    /* ── Phase 1: Parse and validate headers ──────────────────────────────── */

    if (pe_len < 0x40)
        return strdup("[error: payload too small to be a PE]");

    /* DOS header: check MZ signature and e_lfanew */
    if (pe_bytes[0] != 'M' || pe_bytes[1] != 'Z')
        return strdup("[error: missing MZ signature]");

    DWORD pe_off = *(const DWORD *)(pe_bytes + 0x3C);
    if ((size_t)pe_off + sizeof(IMAGE_NT_HEADERS64) > pe_len)
        return strdup("[error: e_lfanew out of bounds]");

    /* NT headers (PE32+) */
    const IMAGE_NT_HEADERS64 *nt =
        (const IMAGE_NT_HEADERS64 *)(pe_bytes + pe_off);

    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return strdup("[error: missing PE signature]");

    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return strdup("[error: not an AMD64 PE; only x64 EXEs supported]");

    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return strdup("[error: not a PE32+ (64-bit) image]");

    DWORD     entry_rva     = nt->OptionalHeader.AddressOfEntryPoint;
    ULONGLONG pref_base     = nt->OptionalHeader.ImageBase;
    DWORD     size_of_image = nt->OptionalHeader.SizeOfImage;
    DWORD     size_of_hdrs  = nt->OptionalHeader.SizeOfHeaders;
    WORD      num_sections  = nt->FileHeader.NumberOfSections;
    WORD      opt_hdr_sz    = nt->FileHeader.SizeOfOptionalHeader;

    IMAGE_DATA_DIRECTORY imp_dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_DATA_DIRECTORY rel_dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    /* Section table: at pe_off + 4 (sig) + 20 (FileHeader) + SizeOfOptionalHeader */
    const IMAGE_SECTION_HEADER *sections =
        (const IMAGE_SECTION_HEADER *)(
            pe_bytes + pe_off + 4 + sizeof(IMAGE_FILE_HEADER) + opt_hdr_sz);

    /* Bounds check: at least one section header must fit */
    if (num_sections > 0) {
        size_t sec_end = (size_t)(
            (const uint8_t *)sections - pe_bytes
        ) + (size_t)num_sections * sizeof(IMAGE_SECTION_HEADER);
        if (sec_end > pe_len)
            return strdup("[error: section table out of bounds]");
    }

    /* ── Phase 2: Allocate image memory ──────────────────────────────────── */

    uint8_t *image_base = (uint8_t *)VirtualAlloc(
        (LPVOID)(uintptr_t)pref_base,
        size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!image_base) {
        /* Preferred base taken; let the OS choose an address */
        image_base = (uint8_t *)VirtualAlloc(
            NULL, size_of_image,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    if (!image_base)
        return strdup("[error: VirtualAlloc failed]");

    /* ── Phase 3a: Copy PE headers ────────────────────────────────────────── */

    size_t hdr_copy = (size_of_hdrs < (DWORD)pe_len) ? size_of_hdrs : (DWORD)pe_len;
    memcpy(image_base, pe_bytes, hdr_copy);

    /* ── Phase 3b: Copy sections ──────────────────────────────────────────── */

    for (int i = 0; i < num_sections; i++) {
        const IMAGE_SECTION_HEADER *sec = &sections[i];
        if (!sec->SizeOfRawData || !sec->PointerToRawData)
            continue;  /* BSS-style section: already zeroed by VirtualAlloc */

        size_t src_end = (size_t)sec->PointerToRawData + sec->SizeOfRawData;
        if (src_end > pe_len)
            continue;  /* truncated file; skip */

        if ((size_t)sec->VirtualAddress + sec->SizeOfRawData > size_of_image)
            continue;  /* would overflow image; skip */

        memcpy(image_base + sec->VirtualAddress,
               pe_bytes  + sec->PointerToRawData,
               sec->SizeOfRawData);
    }

    /* ── Phase 4: Apply base relocations ──────────────────────────────────── */

    int64_t delta = (int64_t)(uintptr_t)image_base - (int64_t)pref_base;

    if (delta != 0 && rel_dir.VirtualAddress && rel_dir.Size) {
        uint8_t *ptr = image_base + rel_dir.VirtualAddress;
        uint8_t *end = ptr + rel_dir.Size;

        while (ptr + 8 <= end) {
            DWORD block_va   = *(DWORD *)ptr;
            DWORD block_sz   = *(DWORD *)(ptr + 4);
            if (block_sz < 8) break;
            if (ptr + block_sz > end) break;  /* corrupt block */

            DWORD count    = (block_sz - 8) / 2;
            WORD *entries  = (WORD *)(ptr + 8);

            for (DWORD j = 0; j < count; j++) {
                int   type = entries[j] >> 12;
                DWORD off  = entries[j] & 0x0FFF;
                if (type == IMAGE_REL_BASED_DIR64) {
                    /* 64-bit absolute address patch */
                    int64_t *patch =
                        (int64_t *)(image_base + block_va + off);
                    *patch += delta;
                }
                /* Other relocation types (ABSOLUTE=0, HIGH=1, LOW=3, …)
                   are not needed for normal 64-bit Windows executables. */
            }
            ptr += block_sz;
        }
    }

    /* ── Phase 5: Resolve import address table ────────────────────────────── */
    /*
     * IMAGE_IMPORT_DESCRIPTOR (20 bytes, null-terminated array):
     *   +0   OriginalFirstThunk — RVA of INT (0 → fall back to FirstThunk)
     *   +12  Name              — RVA of DLL name string
     *   +16  FirstThunk        — RVA of IAT
     *
     * IMAGE_THUNK_DATA64 entries are 8 bytes:
     *   bit 63 set  → ordinal  (bits 0-15 = ordinal number)
     *   bit 63 clear → named   (RVA to IMAGE_IMPORT_BY_NAME { WORD Hint; CHAR Name[]; })
     */

    if (imp_dir.VirtualAddress && imp_dir.Size) {
        IMAGE_IMPORT_DESCRIPTOR *desc =
            (IMAGE_IMPORT_DESCRIPTOR *)(image_base + imp_dir.VirtualAddress);

        while (desc->Name) {
            const char *dll_name = (const char *)(image_base + desc->Name);
            HMODULE hDLL = LoadLibraryA(dll_name);
            /* hDLL may be NULL if the DLL is not found — in that case
               IAT slots are set to 0; calls will AV on first invocation. */

            DWORD int_rva = desc->OriginalFirstThunk;
            if (!int_rva)
                int_rva = desc->FirstThunk;  /* some linkers omit the INT */

            uint64_t *int_ptr = (uint64_t *)(image_base + int_rva);
            uint64_t *iat_ptr = (uint64_t *)(image_base + desc->FirstThunk);

            for (size_t j = 0; int_ptr[j]; j++) {
                uint64_t  thunk   = int_ptr[j];
                uintptr_t fn_addr = 0;

                if (hDLL) {
                    if (thunk >> 63) {
                        /* Ordinal import */
                        fn_addr = (uintptr_t)GetProcAddress(
                            hDLL, (LPCSTR)(uintptr_t)(thunk & 0xFFFF));
                    } else {
                        /* Named import: skip 2-byte Hint field */
                        const char *fn_name =
                            (const char *)(image_base + (DWORD)thunk + 2);
                        fn_addr = (uintptr_t)GetProcAddress(hDLL, fn_name);
                    }
                }
                iat_ptr[j] = (uint64_t)fn_addr;
            }
            desc++;
        }
    }

    /* ── Phase 6: Set per-section memory protections ──────────────────────── */

    for (int i = 0; i < num_sections; i++) {
        const IMAGE_SECTION_HEADER *sec = &sections[i];
        if (!sec->SizeOfRawData) continue;
        DWORD prot = section_prot(sec->Characteristics);
        DWORD old_prot = 0;
        VirtualProtect(image_base + sec->VirtualAddress,
                       sec->SizeOfRawData, prot, &old_prot);
    }

    /* ── Phase 7: Redirect stdout/stderr, run entry point ─────────────────── */

    /* Anonymous pipe for output capture.  Write end is inheritable so the
       loaded PE's CRT will write to it when printf/puts are used.          */
    HANDLE pipe_read  = NULL;
    HANDLE pipe_write = NULL;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };

    if (CreatePipe(&pipe_read, &pipe_write, &sa, 0)) {
        /* Read end must NOT be inherited by child threads */
        SetHandleInformation(pipe_read, HANDLE_FLAG_INHERIT, 0);
    }

    HANDLE old_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE old_stderr = GetStdHandle(STD_ERROR_HANDLE);

    if (pipe_write) {
        SetStdHandle(STD_OUTPUT_HANDLE, pipe_write);
        SetStdHandle(STD_ERROR_HANDLE,  pipe_write);
    }

    LPTHREAD_START_ROUTINE ep =
        (LPTHREAD_START_ROUTINE)(image_base + entry_rva);
    HANDLE hThread = CreateThread(NULL, 0, ep, NULL, 0, NULL);

    if (!hThread) {
        /* Restore standard handles and clean up pipe */
        if (pipe_write) {
            SetStdHandle(STD_OUTPUT_HANDLE, old_stdout);
            SetStdHandle(STD_ERROR_HANDLE,  old_stderr);
            CloseHandle(pipe_write);
            CloseHandle(pipe_read);
        }
        return strdup("[error: CreateThread failed]");
    }

    /* Wait up to PE_EXEC_TIMEOUT_MS for the entry point to return */
    DWORD wait_res = WaitForSingleObject(hThread, PE_EXEC_TIMEOUT_MS);
    CloseHandle(hThread);

    /* Restore handles; close write end so ReadFile returns EOF */
    if (pipe_write) {
        SetStdHandle(STD_OUTPUT_HANDLE, old_stdout);
        SetStdHandle(STD_ERROR_HANDLE,  old_stderr);
        CloseHandle(pipe_write);
        pipe_write = NULL;
    }

    if (wait_res == WAIT_TIMEOUT) {
        if (pipe_read) CloseHandle(pipe_read);
        return strdup(
            "[+] PE executing (async \xe2\x80\x94 entry point did not return within 30 s)");
    }

    /* ── Phase 8: Collect captured output ────────────────────────────────── */

    if (!pipe_read)
        return strdup("[+] PE executed (output not captured)");

    char *output = drain_pipe(pipe_read);
    CloseHandle(pipe_read);

    if (!output || output[0] == '\0') {
        free(output);
        return strdup("[+] PE executed (no output)");
    }
    return output;  /* caller frees */
}
