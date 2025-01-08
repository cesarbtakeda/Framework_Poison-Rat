#include <iostream>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <unistd.h>

// Configurações de conexão
const char *host = "127.0.0.1";
int port = 443;
int timeout = 10;

// Configuração para criptografia segura (TLS)
SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

int main() {
    SSL_CTX *ctx = create_context();
    SSL *ssl;
    int sock = 0;
    struct sockaddr_in server;
    const char *chave = "sua-chave-secreta-de-32-bytes12345678";
    int iv_tamanho = 16; // AES GCM IV size

    // Criação do socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        exit(EXIT_FAILURE);
    }

    // Conexão ao servidor
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Configurações de criptografia AES-GCM
    const char *mensagem = ".";

    // Função para dividir, criptografar e enviar pacotes
    auto enviar_pacote_criptografado = [&](SSL *ssl, const char *mensagem, const char *chave, int iv_tamanho) {
        int tamanho_pacote = 512;
        int contador;
        int tamanho = strlen(mensagem);
        unsigned char iv[iv_tamanho];

        for (contador = 0; contador < tamanho; contador += tamanho_pacote) {
            int len = (contador + tamanho_pacote > tamanho) ? tamanho - contador : tamanho_pacote;
            RAND_bytes(iv, iv_tamanho);

            // Criptografa com AES-256-GCM
            unsigned char tag[16];
            unsigned char pacote[512];
            int pacote_len = EVP_EncryptUpdate(ssl, pacote, &len, (unsigned char *)(mensagem + contador), len);
            if (pacote_len > 0) {
                EVP_EncryptFinal_ex(ssl, pacote + pacote_len, &len);
                pacote_len += len;

                // Anexa IV e Tag de autenticação
                send(sock, iv, iv_tamanho, 0);
                send(sock, pacote, pacote_len, 0);
            }
        }
    };

    enviar_pacote_criptografado(ssl, mensagem, chave, iv_tamanho);

    // Manter a comunicação aberta e ler resposta do servidor enquanto estiver ativo
    while (1) {
        char buffer[1024] = {0};
        int valread = SSL_read(ssl, buffer, 1024);
        if (valread > 0) {
            std::cout << buffer << std::endl;
        } else {
            break;
        }
        usleep(100000); // Aguarda 100ms antes de tentar novamente
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    return 0;
}
