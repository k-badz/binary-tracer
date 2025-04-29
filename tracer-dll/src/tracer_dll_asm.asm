PUBLIC allocate_custom_tls_asmcallback
PUBLIC exhaustion_handler_asmcallback
PUBLIC ret_stack_push
PUBLIC ret_stack_pop

EXTERN allocate_custom_tls : PROC 
EXTERN exhaustion_handler : PROC 
EXTERN allocate_tracer_tls : PROC

CustomTracerTLS STRUCT
    ret_stack     dq 256 dup(?)
    ret_stack_idx dq 0
CustomTracerTLS ENDS

MacroSaveContext MACRO
    ; Save all general-purpose registers
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    
    ; We need to allocate space for all XMM registers (XMM0-XMM15)
    sub rsp, 16*16
    
    ; Save all XMM registers
    movdqa [rsp+16*0], xmm0
    movdqa [rsp+16*1], xmm1
    movdqa [rsp+16*2], xmm2
    movdqa [rsp+16*3], xmm3
    movdqa [rsp+16*4], xmm4
    movdqa [rsp+16*5], xmm5
    movdqa [rsp+16*6], xmm6
    movdqa [rsp+16*7], xmm7
    movdqa [rsp+16*8], xmm8
    movdqa [rsp+16*9], xmm9
    movdqa [rsp+16*10], xmm10
    movdqa [rsp+16*11], xmm11
    movdqa [rsp+16*12], xmm12
    movdqa [rsp+16*13], xmm13
    movdqa [rsp+16*14], xmm14
    movdqa [rsp+16*15], xmm15
    
    ; Allocate shadow space (32 bytes) for the function call
    sub rsp, 32
ENDM

MacroRestoreContext MACRO
    ; Deallocate shadow space
    add rsp, 32
    
    ; Restore all XMM registers
    movdqa xmm0, [rsp+16*0]
    movdqa xmm1, [rsp+16*1]
    movdqa xmm2, [rsp+16*2]
    movdqa xmm3, [rsp+16*3]
    movdqa xmm4, [rsp+16*4]
    movdqa xmm5, [rsp+16*5]
    movdqa xmm6, [rsp+16*6]
    movdqa xmm7, [rsp+16*7]
    movdqa xmm8, [rsp+16*8]
    movdqa xmm9, [rsp+16*9]
    movdqa xmm10, [rsp+16*10]
    movdqa xmm11, [rsp+16*11]
    movdqa xmm12, [rsp+16*12]
    movdqa xmm13, [rsp+16*13]
    movdqa xmm14, [rsp+16*14]
    movdqa xmm15, [rsp+16*15]
    
    ; Restore stack pointer for XMM space
    add rsp, 16*16
    
    ; Restore all general-purpose registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
ENDM

MacroTLSCheck MACRO
    mov   r9, gs:[48h] ; tid
    and   r9, 0FFFFh  
    lea  rax, [rcx+r9*8]  
    mov  r11, qword ptr [rax]  
    test r11, r11
    jz   _allocate_custom_tls_and_continue
_custom_tls_ready:
ENDM

MacroTLSAllocate MACRO
_allocate_custom_tls_and_continue:
    ; Align the stack pointer, we might have both aligned and unaligned stack here
    mov r9, rsp
    and rsp, -16         ; Align stack to 16 bytes (clear lower 4 bits)
    push r9              ; Save original stack pointer

    sub rsp, 8     ; Stack is not aligned again at this point, we will align it first.
    sub rsp, 8     ; Allocate space for our return value
    
    MacroSaveContext

    call allocate_tracer_tls

    mov [rsp + 408], rax ; Save the return value to our temporary storage
    
    MacroRestoreContext
    
    mov r11, [rsp] ; Load the return value into RAX
    add rsp, 16 ; Free the space we allocated for the parameter and aligning.

    ; Restore original stack pointer
    pop rcx
    mov rsp, rcx

    mov qword ptr [rax], r11
    jmp _custom_tls_ready
ENDM

.code

OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

ALIGN 16
ret_stack_push PROC ; QWORD tls_list_container, QWORD original_ret
    MacroTLSCheck

    mov  r9, [r11].CustomTracerTLS.ret_stack_idx
    lea  rcx, [r11].CustomTracerTLS.ret_stack
    lea  rcx, [rcx+r9*8]
    mov  [rcx], rdx
    inc [r11].CustomTracerTLS.ret_stack_idx
    ret

    MacroTLSAllocate

ret_stack_push ENDP

ALIGN 16
ret_stack_pop PROC
    MacroTLSCheck

    dec [r11].CustomTracerTLS.ret_stack_idx
    mov  r9, [r11].CustomTracerTLS.ret_stack_idx
    lea  rcx, [r11].CustomTracerTLS.ret_stack
    lea  rcx, [rcx+r9*8]
    mov  rax, [rcx]
    ret

    MacroTLSAllocate

ret_stack_pop ENDP

ALIGN 16
allocate_custom_tls_asmcallback PROC ; QWORD signalling_event_buffer
    ; This function is dynamically called in a body of other function
    ; and it will call complicated C++ function which can override all the registers.
    ; We will save all registers and data that could possibly carry any arguments or
    ; return values and then after that call we will restore them.

    ; Align the stack pointer, we might have both aligned and unaligned stack here
    mov rax, rsp
    and rsp, -16         ; Align stack to 16 bytes (clear lower 4 bits)
    push rax             ; Save original stack pointer

    sub rsp, 8     ; Stack is not aligned again at this point, we will align it first.
    sub rsp, 8     ; Allocate space for our parameter value
    mov [rsp], rcx ; Save our parameter (RCX) to a temporary location
    
    MacroSaveContext
    
    ; Restore our parameter to RCX
    mov rcx, [rsp + 408] ; XMMs take 256, shadow space 32, general purpose registers 120 bytes, and parameter 8
    
    call allocate_custom_tls
    
    mov [rsp + 408], rax ; Save the return value to our temporary storage
    
    MacroRestoreContext
    
    mov rax, [rsp] ; Load the return value into RAX
    add rsp, 16 ; Free the space we allocated for the parameter and aligning.

    ; Restore original stack pointer
    pop rcx
    mov rsp, rcx
    
    ret
allocate_custom_tls_asmcallback ENDP

ALIGN 16
exhaustion_handler_asmcallback PROC
    ; This function is dynamically called in a body of other function
    ; and it will call complicated C++ function which can override all the registers.
    ; We will save all registers and data that could possibly carry any arguments or
    ; return values and then after that call we will restore them.
    
    ; Align the stack pointer, we might have both aligned and unaligned stack here
    mov rax, rsp
    and rsp, -16         ; Align stack to 16 bytes (clear lower 4 bits)
    push rax             ; Save original stack pointer

    ; Stack is not aligned again at this point.
    ; No need to align the stack again here. We have odd number of general purposes registers
    ; and no params here so they will cancel out.

    MacroSaveContext
    
    call exhaustion_handler

    MacroRestoreContext

    ; Restore stack pointer
    pop rcx
    mov rsp, rcx
    
    ret
exhaustion_handler_asmcallback ENDP

OPTION PROLOGUE:PrologueDef
OPTION EPILOGUE:EpilogueDef

END