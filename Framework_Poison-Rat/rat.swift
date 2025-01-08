import CryptoKit
import Foundation
import Network

let host = "127.0.0.1"
let port: UInt16 = 443
let chave = "your-secret-key-32-bytes".data(using: .utf8)!

// Função para gerar um IV aleatório
func gerarIV() -> Data {
    var iv = Data(count: 12)
    let _ = iv.withUnsafeMutableBytes { (bytes: UnsafeMutableRawBufferPointer) in
        let result = SecRandomCopyBytes(kSecRandomDefault, iv.count, bytes.baseAddress!)
        precondition(result == errSecSuccess, "falha ao gerar IV")
    }
    return iv
}

// Função para enviar pacotes criptografados
func enviarPacoteCriptografado(to connection: NWConnection, mensagem: String) {
    let tamanhoPacote = 512
    var offset = 0

    while offset < mensagem.count {
        let remaining = mensagem.count - offset
        let chunkSize = min(tamanhoPacote, remaining)
        let chunk = String(mensagem[mensagem.index(mensagem.startIndex, offsetBy: offset)..<mensagem.index(mensagem.startIndex, offsetBy: offset + chunkSize)])

        // Adiciona um contador ao pacote para evitar repetição
        let pacoteComNonce = "\(offset)|\(chunk)"

        // Criptografa com AES-256-GCM
        let iv = gerarIV()
        let aes = try! AES.GCM.seal(pacoteComNonce.data(using: .utf8)!, using: SymmetricKey(data: chave), nonce: AES.GCM.Nonce(data: iv))

        // Anexa IV e Tag de autenticação
        let pacoteFinal = iv + aes.ciphertext
        connection.send(content: pacoteFinal, completion: .contentProcessed { sendError in
            if let error = sendError {
                print("Erro ao enviar pacote:", error)
            }
        })

        offset += chunkSize
    }
}

// Criar uma conexão com o servidor
let connection = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(integerLiteral: port), using: .tls)

connection.start(queue: .main)
connection.stateUpdateHandler = { newState in
    switch newState {
    case .ready:
        print("Conectado ao servidor")
        
        // Exemplo de mensagem a ser enviada
        let mensagem = "."
        enviarPacoteCriptografado(to: connection, mensagem: mensagem)

        // Manter a comunicação aberta e ler resposta do servidor enquanto estiver ativo
        connection.receiveMessage { (data, context, isComplete, error) in
            if let error = error {
                print("Erro ao receber resposta:", error)
                return
            }

            if let data = data, !data.isEmpty {
                print("Resposta do servidor:", String(data: data, encoding: .utf8) ?? "")
            }

            // Continue recebendo enquanto a conexão estiver aberta
            connection.receiveMessage { (data, context, isComplete, error) in
                if isComplete {
                    print("Conexão encerrada.")
                    connection.cancel()
                }
            }
        }

    case .failed(let error):
        print("Falha na conexão:", error)
        connection.cancel()
    default:
        break
    }
}
