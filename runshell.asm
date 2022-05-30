section .data
msg db "Hello,world!",0xa
len equ $-msg

section .text
global  _start


_start:
    mov edx,len
    mov ecx,msg
    mov ebx,1
    mov eax,4
    int 0x80

   	nop
   	nop
   	xor    eax,eax
   	xor    ebx,ebx
   	mov    al,0x17
   	int    0x80
   	jmp    0xffffdfdf
   	pop    esi
   	mov    [esi+0x8],esi
   	xor    eax,eax
   	mov    [esi+0x7],al
   	mov    [esi+0xc],eax
   	mov    al,0xb
   	mov    ebx,esi
   	lea    ecx,[esi+0x8]
   	lea    edx,[esi+0xc]
   	int    0x80
   	sbb    ebx,ebx
   	mov    eax,ebx
   	inc    eax
   	int    0x80


    mov ebx,0
    mov eax,1
    int 0x80
