section .data
    host db "127.0.0.1"
    port dw 443
    timeout dd 10
    chave db 'sua-chave-secreta-de-32-bytes12345678'
    iv_tamanho equ 16    ; AES GCM IV size

section .bss
    buffer resb 1024

section .text
    global _start

_start:
    ; Criando socket TCP
    mov eax, 2         ; sys_socket
    mov ebx, 1         ; AF_INET
    mov ecx, 2         ; SOCK_STREAM
    mov edx, 0         ; protocol (default for TCP)
    int 0x80           ; system call

    ; Configurando estrutura sockaddr_in
    mov ebx, eax
    mov esi, host      ; "127.0.0.1"
    lea edi, [esi]
    mov word [ebx + 2], 8080  ; port
    mov dword [ebx + 6], 0x100007f  ; IP address
    call connect_socket

    ; TLS setup
    mov esi, chave     ; "sua-chave-secreta-de-32-bytes12345678"
    mov ecx, iv_tamanho
    call setup_tls

    ; Dividir, criptografar e enviar pacotes
    mov esi, buffer
    lea edi, [iv_tamanho]
    call send_encrypted_packet

    ; Manter a comunicação aberta e ler resposta do servidor enquanto estiver ativo
    loop_server:
        mov eax, 3         ; sys_read
        lea ebx, [buffer]
        mov ecx, 1024
        mov edx, 0         ; flags (default for read)
        int 0x80           ; system call

        cmp eax, 0
        jle end_program

        call print_response
        jmp loop_server

end_program:
    call close_connection
    mov eax, 1
    int 0x80

connect_socket:
    push ebx           ; Save socket descriptor
    push edi           ; IP address
    mov al, 3          ; sys_connect
    int 0x80           ; system call
    pop ebx            ; Restore socket descriptor
    ret

setup_tls:
    ; Implementação do setup TLS
    ret

send_encrypted_packet:
    ; Criptografa e envia pacotes
    ret

print_response:
    ; Imprime a resposta do servidor
    ret

close_connection:
    ; Fecha a conexão
    ret
