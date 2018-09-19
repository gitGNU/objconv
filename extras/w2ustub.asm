; *****************************  w2ustub.asm   ********************************
; Author:        Agner Fog
; Date created:  2009-05-27
; 
; Description:
; Call stub for calling 64-bit Windows functions from Linux, BSD or Mac
;
; (c) 2009 GNU General Public License www.gnu.org/copyleft/gpl.html
; *****************************************************************************
;
; This call stub takes care of the differences between the calling conventions
; of 64-bit Windows and 64-bit Unix systems (Linux, BSD, Mac OS X) when a 
; function compiled for 64-bit Windows is called in a Unix system. No stub is 
; needed in 32-bit systems.
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
; If the function has more than four parameters or a mixture of floating
; point and non-floating point parameters then you have to make your own
; stub assembler code to account for the differences in parameter transfer
; methods.
;
; If the converted Windows function calls another converted Windows function 
; then no stub is needed for the latter call. If the converted Windows 
; function calls a Unix function then the call must go through a reverse 
; stub created from u2wstub.
;
; See www.agner.org/optimize/calling_conventions.pdf for further details
; about differences in calling conventions.
; ****************************************************************************

.code

extern  wname: near

uname   proc    ; call from Unix goes here

        ; Unix parameters (rdi,rsi,rdx,rcx) -> Windows parameters (rcx,rdx,r8,r9)
        mov     r9,  rcx
        mov     r8,  rdx
        mov     rdx, rsi
        mov     rcx, rdi
        
        ; make 32 bytes shadow space and align by 16
        sub     rsp, 40
        
        call    wname      ; Call to Windows function here
        
        ; restore stack
        add     rsp, 40
        ret
        
uname   endp        

end
