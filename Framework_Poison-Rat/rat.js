const CryptoJS = require('crypto-js');
const net = require('net');

const HOST = '127.0.0.1';
const PORT = 443;

const chave = CryptoJS.enc.Hex.parse('your-secret-key-in-hex');
const ivSize = 12; // Tamanho do IV para AES-GCM

// Função para gerar um IV aleatório
function gerarIV() {
  return CryptoJS.lib.WordArray.random(ivSize).toString();
}

// Função para enviar pacotes criptografados
function enviarPacoteCriptografado(socket, mensagem) {
  const tamanhoPacote = 512;
  const pacotes = [];

  for (let offset = 0; offset < mensagem.length; offset += tamanhoPacote) {
    const chunk = mensagem.slice(offset, offset + tamanhoPacote);

    // Adiciona um contador ao pacote para evitar repetição
    const pacoteComNonce = offset.toString() + '|' + chunk;

    // Criptografa com AES-256-GCM
    const iv = gerarIV();
    const pacoteCriptografado = CryptoJS.AES.encrypt(pacoteComNonce, chave, {
      iv: CryptoJS.enc.Hex.parse(iv),
      mode: CryptoJS.mode.GCM,
      padding: CryptoJS.pad.NoPadding
    });

    // Anexa IV e Tag de autenticação
    const pacoteFinal = iv + pacoteCriptografado.ciphertext.toString(CryptoJS.enc.Base64);
    socket.write(pacoteFinal);
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
