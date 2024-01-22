.data
jumpAddress dq 0

.code
PUBLIC NtProtectVirtualMemory
PUBLIC NtWriteVirtualMemory
PUBLIC SetJumpAddress               ; Function to set jumpAddress

SetJumpAddress proc
    mov [jumpAddress], rcx          ; Assume the new address is passed in RCX
    ret
SetJumpAddress endp

NtProtectVirtualMemory proc
    mov r11, [jumpAddress]          ; Load indirect syscall address into R11 register
    mov eax, [rsp+30h]              ; Move syscall ID into RAX register
    mov r10, rcx
    jmp r11                         ; Indirect syscall via jump to address stored in R11
NtProtectVirtualMemory endp

NtWriteVirtualMemory proc
    mov r11, [jumpAddress]          ; Load indirect syscall address into R11 register
    mov eax, [rsp+30h]              ; Move syscall ID into RAX register
    mov r10, rcx
    jmp r11                         ; Indirect syscall via jump to address stored in R11
NtWriteVirtualMemory endp

end