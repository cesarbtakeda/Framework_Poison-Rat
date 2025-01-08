#!/bin/bash

# Configurações de conexão
host='127.0.0.1'
port=443
timeout=10
chave='sua-chave-secreta-de-32-bytes12345678'
iv_tamanho=16  # AES GCM IV size

# Configuração para criptografia segura (TLS)
exec 3<>/dev/tcp/$host/$port
echo -e "GET / HTTP/1.0\r\n" >&3

# Função para dividir, criptografar e enviar pacotes
enviar_pacote_criptografado() {
    local mensagem="$1"
    local tamanho_pacote=512
    local pacotes=($(echo "$mensagem" | fold -w $tamanho_pacote))

    for contador in "${!pacotes[@]}"; do
        iv=$(head -c $iv_tamanho /dev/urandom)
        pacote_com_nonce="$contador|${pacotes[$contador]}"

        # Criptografa com AES-256-GCM
        pacote_criptografado=$(echo -n "$pacote_com_nonce" | openssl enc -aes-256-gcm -base64 -K $chave -iv $iv -tag)

        # Envia o pacote criptografado
        echo -n "$pacote_criptografado" >&3
    done
}

# Exemplo de mensagem a ser enviada
mensagem="."
enviar_pacote_criptografado "$mensagem"

# Manter a comunicação aberta e ler resposta do servidor enquanto estiver ativo
while :; do
    resposta=$(<>&3)
    if [[ -z "$resposta" ]]; then
        break
    fi
    echo "$resposta"
    sleep 0.1
done

# Fechar a conexão
exec 3>&-
