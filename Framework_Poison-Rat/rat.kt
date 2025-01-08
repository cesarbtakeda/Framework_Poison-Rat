import java.io.IOException
import java.net.Socket
import java.security.GeneralSecurityException
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class SecureClient {

    companion object {
        private const val HOST = "127.0.0.1"
        private const val PORT = 443
        private const val TIMEOUT = 10000 // 10 segundos
    }

    @Throws(IOException::class, GeneralSecurityException::class)
    fun start() {
        // Configuração para criação de uma conexão SSL/TLS
        val socket = Socket()
        socket.connect(java.net.InetSocketAddress(HOST, PORT), TIMEOUT)

        // Configurações de criptografia AES-GCM
        val chave = gerarChaveAES()
        val iv = gerarIV()

        // Cria um contexto para criptografia
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, iv) // GCM IV e tamanho do tag de autenticação
        cipher.init(Cipher.ENCRYPT_MODE, chave, spec)

        // Exemplo de mensagem a ser enviada
        val mensagem = "."
        enviarPacoteCriptografado(socket, mensagem, cipher, iv)

        // Manter a comunicação aberta e ler resposta do servidor enquanto estiver ativo
        // Receber dados do socket
        // ...

        socket.close()
    }

    // Função para gerar chave AES de 256 bits
    @Throws(GeneralSecurityException::class)
    private fun gerarChaveAES(): SecretKey {
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(256) // Tamanho da chave AES
        return keyGen.generateKey()
    }

    // Função para gerar IV
    @Throws(GeneralSecurityException::class)
    private fun gerarIV(): ByteArray {
        val iv = ByteArray(12) // IV para AES-GCM
        java.security.SecureRandom().nextBytes(iv)
        return iv
    }

    // Função para enviar pacote criptografado
    @Throws(IOException::class, GeneralSecurityException::class)
    private fun enviarPacoteCriptografado(socket: Socket, mensagem: String, cipher: Cipher, iv: ByteArray) {
        val mensagemBytes = mensagem.toByteArray()
        var offset = 0

        while (offset < mensagemBytes.size) {
            val remaining = mensagemBytes.size - offset
            val chunkSize = Math.min(512, remaining)
            val chunk = mensagemBytes.copyOfRange(offset, offset + chunkSize)

            // Adiciona um contador ao pacote para evitar repetição
            val pacoteComNonce = ByteArray(chunk.size + iv.size + 1)
            pacoteComNonce[0] = (offset and 0xFF).toByte() // Contador como byte
            System.arraycopy(iv, 0, pacoteComNonce, 1, iv.size)
            System.arraycopy(chunk, 0, pacoteComNonce, 1 + iv.size, chunk.size)

            // Criptografa com AES-GCM
            val pacoteCriptografado = cipher.doFinal(pacoteComNonce)

            // Envia o pacote criptografado
            socket.getOutputStream().write(pacoteCriptografado)
            offset += chunkSize
        }
    }
}
