#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 512
#define TIMEOUT 10
#define AES_KEY_SIZE 32  // 256-bit key

// Função para criar um socket seguro com TLS
SSL_CTX* create_ssl_context() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Habilitar verificações SSL
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    return ctx;
}

// Função para enviar pacotes criptografados
void enviar_pacote_criptografado(SSL *ssl, const char *mensagem, unsigned char *chave, int iv_tamanho) {
    int pacotes_size = strlen(mensagem);
    int num_pacotes = (pacotes_size + BUFFER_SIZE - 1) / BUFFER_SIZE;

    for (int i = 0; i < num_pacotes; i++) {
        int start = i * BUFFER_SIZE;
        int end = start + BUFFER_SIZE;
        char pacote[BUFFER_SIZE];
        strncpy(pacote, mensagem + start, end > pacotes_size ? pacotes_size - start : BUFFER_SIZE);

        // Adiciona um contador ao pacote para evitar repetição
        char pacote_com_nonce[BUFFER_SIZE];
        snprintf(pacote_com_nonce, BUFFER_SIZE, "%d|%s", i, pacote);

        // Criptografa com AES-256-GCM
        unsigned char iv[12];
        RAND_bytes(iv, sizeof(iv));
        unsigned char tag[16];
        int len;

        unsigned char pacote_criptografado[BUFFER_SIZE + 32];
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, chave, iv);
        EVP_EncryptUpdate(ctx, pacote_criptografado, &len, (unsigned char*)pacote_com_nonce, strlen(pacote_com_nonce));
        EVP_EncryptFinal_ex(ctx, pacote_criptografado + len, &len);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag);
        EVP_CIPHER_CTX_free(ctx);

        // Anexa IV e Tag de autenticação
        unsigned char pacote_final[BUFFER_SIZE + 44];
        memcpy(pacote_final, iv, 12);
        memcpy(pacote_final + 12, tag, 16);
        memcpy(pacote_final + 28, pacote_criptografado, len);

        // Envia o pacote criptografado
        SSL_write(ssl, pacote_final, sizeof(pacote_final));
    }
}

// Função principal
int main(int argc, char *argv[]) {
    const char *host = "127.0.0.1";
    int port = 443;

    SSL_CTX *ctx = create_ssl_context();
    SSL *ssl = SSL_new(ctx);

    // Conectar ao servidor
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &serv_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    }

    // Configurações de criptografia AES-GCM
    unsigned char chave[AES_KEY_SIZE] = "sua-chave-secreta-de-32-bytes12345678";
    unsigned char iv_tamanho = 12;

    // Exemplo de mensagem a ser enviada
    const char *mensagem = ".";
    enviar_pacote_criptografado(ssl, mensagem, chave, iv_tamanho);

    // Manter a comunicação aberta e ler resposta do servidor enquanto estiver ativo
    while (1) {
        char resposta[1024];
        int bytes = SSL_read(ssl, resposta, sizeof(resposta) - 1);
        if (bytes <= 0) {
            break;
        }
        resposta[bytes] = '\0';
        printf("%s\n", resposta);
    }

    // Fechar a conexão
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    return 0;
}
