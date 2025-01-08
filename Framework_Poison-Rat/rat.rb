require 'socket'
require 'openssl'

# Configurações de conexão
host = '127.0.0.1'
port = 443
timeout = 10

# Configuração para criptografia segura (TLS)
context = OpenSSL::SSL::SSLContext.new
context.verify_mode = OpenSSL::SSL::VERIFY_PEER

# Criando um socket seguro com TLS
socket_cliente = TCPSocket.new(host, port)
ssl_socket = OpenSSL::SSL::SSLSocket.new(socket_cliente, context)
ssl_socket.connect

# Configurações de criptografia AES-GCM
chave = 'sua-chave-secreta-de-32-bytes12345678'
iv_tamanho = 16 # AES GCM IV size

# Função para dividir, criptografar e enviar pacotes
def enviar_pacote_criptografado(socket, mensagem, chave, iv_tamanho)
  tamanho_pacote = 512
  pacotes = mensagem.scan(/.{1,#{tamanho_pacote}}/)

  pacotes.each_with_index do |pacote, contador|
    iv = OpenSSL::Random.random_bytes(iv_tamanho)
    pacote_com_nonce = "#{contador}|#{pacote}"

    # Criptografa com AES-256-GCM
    pacote_criptografado = OpenSSL::Cipher.new('aes-256-gcm').encrypt
    pacote_criptografado.key = chave
    pacote_criptografado.iv = iv
    pacote_final = pacote_criptografado.update(pacote_com_nonce) + pacote_criptografado.final

    # Anexa IV e Tag de autenticação
    socket.write("#{iv}#{pacote_final}")
  end
end

# Exemplo de mensagem a ser enviada
mensagem = "Olá, servidor! Esta é uma mensagem longa para testar o envio em pacotes."
enviar_pacote_criptografado(ssl_socket, mensagem, chave, iv_tamanho)

# Manter a comunicação aberta e ler resposta do servidor enquanto estiver ativo
while true
  resposta = ssl_socket.read(1024)
  break if resposta.nil? || resposta.empty?

  puts resposta
  sleep(0.1) # Aguarda 100ms antes de tentar novamente
end

# Fechar a conexão
ssl_socket.close
