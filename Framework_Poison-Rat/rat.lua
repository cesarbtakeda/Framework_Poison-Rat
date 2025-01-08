local socket = require("socket")
local ssl = require("ssl")
local base64 = require("mime")  -- Biblioteca usada para base64
local openssl = require("openssl")
local aes = openssl.cipher.get("aes-256-gcm")

-- Configurações de conexão
local host = "127.0.0.1"
local port = 443
local timeout = 10

-- Configurações de criptografia AES-GCM
local chave = "sua-chave-secreta-de-32-bytes12345678"
local iv_tamanho = 12

-- Função para criar um socket seguro com TLS
local function criar_socket_seguro(host, port)
    local client, err = socket.tcp()
    if not client then
        error("Erro ao criar socket: " .. err)
    end

    client:settimeout(timeout)

    local success, err = client:connect(host, port)
    if not success then
        error("Erro ao conectar: " .. err)
    end

    local params = {
        mode = "client",
        protocol = "tlsv1_2",
        verify = {"peer", "fail_if_no_peer_cert"},
        options = "all",
    }

    local secure_client, err = ssl.wrap(client, params)
    if not secure_client then
        error("Erro ao criar conexão segura: " .. err)
    end

    local success, err = secure_client:dohandshake()
    if not success then
        error("Erro no handshake TLS: " .. err)
    end

    return secure_client
end

-- Função para enviar pacotes criptografados
local function enviar_pacote_criptografado(socket, mensagem, chave, iv_tamanho)
    local tamanho_pacote = 512
    local pacotes = {}

    for i = 1, #mensagem, tamanho_pacote do
        table.insert(pacotes, mensagem:sub(i, i + tamanho_pacote - 1))
    end

    for contador, pacote in ipairs(pacotes) do
        local iv = openssl.random(iv_tamanho)
        local pacote_com_nonce = string.format("%d|%s", contador, pacote)

        local cipher = aes:encrypt(chave, iv)
        local pacote_criptografado = cipher:update(pacote_com_nonce) .. cipher:final()
        local tag = cipher:getTag()

        local pacote_final = base64.b64(iv .. tag .. pacote_criptografado)
        socket:send(pacote_final .. "\n")
    end
end

-- Função para manter comunicação aberta
local function manter_comunicacao(socket)
    while true do
        local data, err = socket:receive()
        if not data then
            if err ~= "timeout" then
                error("Erro ao receber dados: " .. err)
            end
            break
        end
        print(data)
        socket.sleep(0.1) -- Aguarda 100ms antes de tentar novamente
    end
end

-- Execução principal
local secure_sock = criar_socket_seguro(host, port)

local mensagem = "."
enviar_pacote_criptografado(secure_sock, mensagem, chave, iv_tamanho)

manter_comunicacao(secure_sock)

secure_sock:close()
