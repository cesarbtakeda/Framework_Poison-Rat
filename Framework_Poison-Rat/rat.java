import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public class SecureClient {

    private static final String HOST = "127.0.0.1";
    private static final int PORT = 443;
    private static final int TIMEOUT = 10000; // 10 segundos

    public static void main(String[] args) {
        try {
            // Configuração para criação de uma conexão SSL/TLS
            Socket socket = new Socket();
            socket.connect(new java.net.InetSocketAddress(HOST, PORT), TIMEOUT);

            // Configurações de criptografia AES-GCM
            SecretKey chave = gerarChaveAES();
            byte[] iv = gerarIV();

            // Cria um contexto para criptografia
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv); // GCM IV e tamanho do tag de autenticação
            cipher.init(Cipher.ENCRYPT_MODE, chave, spec);

            // Exemplo de mensagem a ser enviada
            String mensagem = ".";
            enviarPacoteCriptografado(socket, mensagem, cipher, iv);

            // Manter a comunicação aberta e ler resposta do servidor enquanto estiver ativo
            // Receber dados do socket
            // ...

            socket.close();

        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    // Função para gerar chave AES de 256 bits
    private static SecretKey gerarChaveAES() throws GeneralSecurityException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // Tamanho da chave AES
        return keyGen.generateKey();
    }

    // Função para gerar IV
    private static byte[] gerarIV() throws GeneralSecurityException {
        byte[] iv = new byte[12]; // IV para AES-GCM
        SecureRandom.getInstanceStrong().nextBytes(iv);
        return iv;
    }

    // Função para enviar pacote criptografado
    private static void enviarPacoteCriptografado(Socket socket, String mensagem, Cipher cipher, byte[] iv) throws IOException, GeneralSecurityException {
        byte[] mensagemBytes = mensagem.getBytes();
        byte[] pacotes = new byte[512];
        int offset = 0;

        while (offset < mensagemBytes.length) {
            int remaining = mensagemBytes.length - offset;
            int chunkSize = Math.min(512, remaining);
            byte[] chunk = Arrays.copyOfRange(mensagemBytes, offset, offset + chunkSize);

            // Adiciona um contador ao pacote para evitar repetição
            byte[] pacoteComNonce = new byte[chunk.length + iv.length + 1];
            pacoteComNonce[0] = (byte) offset; // Contador como byte
            System.arraycopy(iv, 0, pacoteComNonce, 1, iv.length);
            System.arraycopy(chunk, 0, pacoteComNonce, 1 + iv.length, chunk.length);

            // Criptografa com AES-GCM
            byte[] pacoteCriptografado = cipher.doFinal(pacoteComNonce);

            // Envia o pacote criptografado
            socket.getOutputStream().write(pacoteCriptografado);
            offset += chunkSize;
        }
    }
}
