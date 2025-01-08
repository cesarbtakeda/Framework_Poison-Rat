package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "io"
    "net"
)

const (
    HOST = "127.0.0.1"
    PORT = "443"
    CHAVE = "your-secret-key-32-bytes"
    IV_SIZE = 12 // Tamanho do IV para AES-GCM
)

func gerarIV() ([]byte, error) {
    iv := make([]byte, IV_SIZE)
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }
    return iv, nil
}

func enviarPacoteCriptografado(conn net.Conn, mensagem string) error {
    tamanhoPacote := 512
    var offset int

    for offset < len(mensagem) {
        remaining := len(mensagem) - offset
        chunkSize := min(tamanhoPacote, remaining)
        chunk := mensagem[offset : offset+chunkSize]

        // Adiciona um contador ao pacote para evitar repetição
        pacoteComNonce := fmt.Sprintf("%d|%s", offset, chunk)

        // Criptografa com AES-256-GCM
        iv, err := gerarIV()
        if err != nil {
            return err
        }

        block, err := aes.NewCipher([]byte(CHAVE))
        if err != nil {
            return err
        }

        gcm, err := cipher.NewGCM(block)
        if err != nil {
            return err
        }

        pacoteCriptografado := gcm.Seal(nil, iv, []byte(pacoteComNonce), nil)
        pacoteFinal := append(iv, pacoteCriptografado...)

        _, err = conn.Write(pacoteFinal)
        if err != nil {
            return err
        }

        offset += chunkSize
    }

    return nil
}

func main() {
    conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", HOST, PORT))
    if err != nil {
        fmt.Println("Erro ao conectar:", err)
        return
    }
    defer conn.Close()

    fmt.Println("Conectado ao servidor")

    // Exemplo de mensagem a ser enviada
    mensagem := "."

    err = enviarPacoteCriptografado(conn, mensagem)
    if err != nil {
        fmt.Println("Erro ao enviar pacote criptografado:", err)
        return
    }

    // Manter a comunicação aberta e ler resposta do servidor enquanto estiver ativo
    buf := make([]byte, 1024)
    for {
        n, err := conn.Read(buf)
        if err != nil {
            fmt.Println("Erro ao ler resposta:", err)
            break
        }

        fmt.Println("Resposta do servidor:", string(buf[:n]))
    }
}
