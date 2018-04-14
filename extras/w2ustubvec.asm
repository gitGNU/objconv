; ***************************  w2ustubvec.asm   *******************************
; Author:        Agner Fog
; Date created:  2008-06-03
; 
; Description:
; Call stub for calling 64-bit Windows functions from Linux, BSD or Mac
; with up to four vector parameters.
;
; (c) 2008 GNU General Public License www.gnu.org/copyleft/gpl.html
; *****************************************************************************
;
; This call stub takes care of the differences between the calling conventions
; of 64-bit Windows and 64-bit Unix systems (Linux, BSD, Mac OS X) when a 
; function compiled for 64-bit Windows is called in a Unix system with vector
; type parameters. No stub is needed in 32-bit systems.
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
; * All parameters must be of type __m128, __m128i or __m128d.
;
; * No parameter can be a pointer, reference or any other type than
;   the intrinsic vector types mentioned above.
;
; * The function cannot be member of a class or structure.
;
; * The return can be void or any type, except a composite type
;   requiring a return pointer.
;
; * The function should preferably have extern "C" declaration in both
;   systems. If the declaration is not extern "C" then the mangled names
;   must be translated manually.
;
; If the function has more than four parameters or a mixture of vector
; and non-vector parameters then you have to make your own stub assembler 
; code to account for the differences in parameter transfer methods.
;
; If the converted Windows function calls another converted Windows function 
; then no stub is needed for the latter call. If the converted Windows 
; function calls a Unix function then the call must go through a reverse 
; stub created from u2wstub, u2wstubvec1 or u2wstubvec2.
;
; See www.agner.org/optimize/calling_conventions.pdf for further details
; about differences in calling conventions.
; ****************************************************************************

.code

extern  wname: near

uname   proc    ; call from Unix goes here

        ; make 64 bytes space for parameters, 32 bytes shadow space and align by 16
        sub     rsp, 68H
        
        ; Unix parameters (xmm0, xmm1, xmm2, xmm3) -> Windows parameters ([rcx],[rdx],[r8],[r9])
        lea     rcx, [rsp-30H]
        lea     rdx, [rsp-40H]
        lea     r8,  [rsp-50H]
        lea     r9,  [rsp-60H]
        movaps  [rcx], xmm0
        movaps  [rdx], xmm1
        movaps  [r8],  xmm2
        movaps  [r9],  xmm3
        
        call    wname      ; Call to Windows function here
        
        ; restore stack
        add     rsp, 68H
        ret
        
uname   endp        

end
