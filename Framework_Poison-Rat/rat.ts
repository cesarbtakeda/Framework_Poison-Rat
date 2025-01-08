import * as crypto from 'crypto';
import * as net from 'net';

const HOST = '127.0.0.1';
const PORT = 443;

const chave = crypto.createHash('sha256').update('your-secret-key').digest();
const ivSize = 12; // Tamanho do IV para AES-GCM

// Função para gerar um IV aleatório
function gerarIV(): Buffer {
    return crypto.randomBytes(ivSize);
}

// Função para enviar pacotes criptografados
function enviarPacoteCriptografado(socket: net.Socket, mensagem: string) {
    const tamanhoPacote = 512;
    let offset = 0;

    while (offset < mensagem.length) {
        const remaining = mensagem.length - offset;
        const chunkSize = Math.min(tamanhoPacote, remaining);
        const chunk = mensagem.slice(offset, offset + chunkSize);

        // Adiciona um contador ao pacote para evitar repetição
        const pacoteComNonce = `${offset}|${chunk}`;

        // Criptografa com AES-256-GCM
        const iv = gerarIV();
        const cipher = crypto.createCipheriv('aes-256-gcm', chave, iv);
        let pacoteCriptografado = cipher.update(pacoteComNonce, 'utf8', 'base64');
        pacoteCriptografado += cipher.final('base64');

        // Anexa IV e Tag de autenticação
        const pacoteFinal = iv.toString('base64') + cipher.getAuthTag().toString('base64') + pacoteCriptografado;
        socket.write(pacoteFinal);

        offset += chunkSize;
    }
}

// Criar conexão com o servidor
const client = new net.Socket();
client.connect(PORT, HOST, () => {
    console.log('Conectado ao servidor');

    // Exemplo de mensagem a ser enviada
    const mensagem = ".";
    enviarPacoteCriptografado(client, mensagem);

    // Manter a comunicação aberta e ler resposta do servidor enquanto estiver ativo
    client.on('data', (data) => {
        console.log(data.toString());
    });

    client.on('end', () => {
        console.log('Desconectado do servidor');
    });
});
