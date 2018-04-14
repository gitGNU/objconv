; *****************************  u2wstub.asm   ********************************
; Author:        Agner Fog
; Date created:  2008-05-25
; 
; Description:
; Call stub for calling 64-bit Linux, BSD or Mac functions from Windows
;
; (c) 2008 GNU General Public License www.gnu.org/copyleft/gpl.html
; *****************************************************************************
;
; This call stub takes care of the differences between the calling conventions
; of 64-bit Windows and 64-bit Unix systems (Linux, BSD, Mac OS X) when a 
; function compiled for a Unix system is called from Windows. No stub is needed
; in 32-bit systems.
;
; See the manual for instructions
;
; Requirements:
; The converted function must meet the following requirements:
;
; * Must not call any system functions or any library functions or
;   access any data not available on the target system.
;
; * Must have no more than 4 parameters.
;
; * The parameters cannot be a composite type (struct, class), but 
;   pointers and references to composite types are allowed.
;
; * If any parameters are of type float or double then there can be
;   no parameters of any other type than float and double.
;
; * Cannot have a variable number of parameter, such as printf
;
; * The return can be void or any type. If the return is a composite type
;   then this may use a return pointer, counting as one parameter.
;
; * The function should preferably have extern "C" declaration in both
;   systems. If the declaration is not extern "C" then the mangled names
;   must be translated manually.
;
; * The function should preferably not use the red zone. Compile the Unix
;   function with option -mno-red-zone if possible. If the function uses
;   the red zone then it will still work in Windows most of the time, but
;   it may fail with an extremely low frequency in case the system discards
;   the area above the stack when it is low on memory.
;
; If the function has more than four parameters or a mixture of floating
; point and non-floating point parameters then you have to make your own
; stub assembler code to account for the differences in parameter transfer
; methods.
;
; If the converted Unix function calls another converted Unix function then
; no stub is needed for the latter call. If the converted Unix function calls
; a Windows function then the call must go through a reverse stub created
; from w2ustub.
;
; See www.agner.org/optimize/calling_conventions.pdf for further details
; about differences in calling conventions.
; ****************************************************************************

.code

extern  uname: near

wname   proc    ; call from Windows goes here

        ; Make space for 10 xmm registers, 2 G.P. registers, 
        ; and align stack by 16
        sub     rsp, 184;   10*16 + 2*8 + 8
        
        ; Register rsi, rdi and xmm6 - xmm15 have callee-save status
        ; in Windows, but not in Unix:
        mov     [rsp],     rsi
        mov     [rsp+8],   rdi
        movaps  [rsp+10h], xmm6
        movaps  [rsp+20h], xmm7
        movaps  [rsp+30h], xmm8
        movaps  [rsp+40h], xmm9
        movaps  [rsp+50h], xmm10
        movaps  [rsp+60h], xmm11
        movaps  [rsp+70h], xmm12
        movaps  [rsp+80h], xmm13
        movaps  [rsp+90h], xmm14
        movaps  [rsp+0A0h],xmm15

        ; Windows parameters (rcx,rdx,r8,r9) -> Unix parameters (rdi,rsi,rdx,rcx)
        mov     rdi, rcx
        mov     rsi, rdx
        mov     rdx, r8
        mov     rcx, r9        
        
        call    uname      ; Call to Unix function here
        
        ; Restore saved registers
        mov     rsi,   [rsp]
        mov     rdi,   [rsp+8]
        movaps  xmm6,  [rsp+10h]
        movaps  xmm7,  [rsp+20h] 
        movaps  xmm8,  [rsp+30h] 
        movaps  xmm9,  [rsp+40h] 
        movaps  xmm10, [rsp+50h] 
        movaps  xmm11, [rsp+60h] 
        movaps  xmm12, [rsp+70h] 
        movaps  xmm13, [rsp+80h] 
        movaps  xmm14, [rsp+90h] 
        movaps  xmm15, [rsp+0A0h]        
        
        ; restore stack pointer
        add     rsp, 184
        ret
        
wname   endp        

end
