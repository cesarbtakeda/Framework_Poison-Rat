using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SecureClient
{
    class Program
    {
        static void Main(string[] args)
        {
            string host = "127.0.0.1";
            int port = 443;
            int timeout = 10000; // 10 seconds timeout

            using (TcpClient client = new TcpClient())
            {
                try
                {
                    client.Connect(host, port);
                    client.ReceiveTimeout = timeout;

                    using (NetworkStream stream = client.GetStream())
                    {
                        using (SslStream sslStream = new SslStream(stream, false))
                        {
                            // Configurações de criptografia segura (TLS)
                            sslStream.AuthenticateAsClient(host);

                            // Configurações de criptografia AES-GCM
                            string chave = "sua-chave-secreta-de-32-bytes12345678";
                            int iv_tamanho = 16; // AES GCM IV size

                            // Função para dividir, criptografar e enviar pacotes
                            void EnviarPacoteCriptografado(SslStream sslStream, string mensagem, string chave, int iv_tamanho)
                            {
                                int tamanho_pacote = 512;
                                int contador;
                                byte[] iv = new byte[iv_tamanho];

                                for (contador = 0; contador < mensagem.Length; contador += tamanho_pacote)
                                {
                                    int len = Math.Min(t
