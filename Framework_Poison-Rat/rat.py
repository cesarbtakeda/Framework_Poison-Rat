import socket
import ssl
import os
import base64
import os.path
import struct
import time

# Configurações de conexão
host = '127.0.0.1'
port = 443
timeout = 10

# Criação de um contexto seguro com TLS
context = ssl.create_default_context()
context.check_hostname = True
context.verify_mode = ssl.CERT_REQUIRED
context.minimum_version = ssl.TLSVersion.TLSv1_2

# Criando um socket seguro com TLS
try:
    sock = socket.create_connection((host, port), timeout)
    secure_sock = context.wrap_socket(sock, server_hostname=host)
except Exception as e:
    print(f"Erro ao conectar: {e}")
    exit()

# Configurações de criptografia AES-GCM
chave = b'sua-chave-secreta-de-32-bytes12345678'  # 32 bytes para AES-256
iv_tamanho = 12  # IV tamanho para AES-GCM

def enviar_pacote_criptografado(socket, mensagem, chave, iv_tamanho):
    tamanho_pacote = 512
    pacotes = [mensagem[i:i + tamanho_pacote] for i in range(0, len(mensagem), tamanho_pacote)]

    for contador, pacote in enumerate(pacotes):
        iv = os.urandom(iv_tamanho)  # Gerar IV aleatório para cada pacote

        # Adiciona um contador ao pacote para evitar repetição
        pacote_com_nonce = f"{contador}|{pacote}".encode()

        # Criptografa com AES-256-GCM
        pacote_criptografado, tag = AES_GCM(chave).encrypt(iv, pacote_com_nonce)

        # Anexa IV e Tag de autenticação
        pacote_final = base64.b64encode(iv + tag + pacote_criptografado).decode()

        # Envia o pacote criptografado
        socket.sendall(pacote_final.encode())

# Função para manter a comunicação aberta e ler resposta do servidor enquanto estiver ativo
def manter_comunicacao(secure_sock):
    while True:
        data = secure_sock.recv(1024)
        if not data:
            break
        print(data.decode())

        time.sleep(0.1)  # Aguarda 100ms antes de tentar novamente

# Exemplo de mensagem a ser enviada
mensagem = "."
enviar_pacote_criptografado(secure_sock, mensagem, chave, iv_tamanho)

manter_comunicacao(secure_sock)

# Fechar a conexão
secure_sock.close()
