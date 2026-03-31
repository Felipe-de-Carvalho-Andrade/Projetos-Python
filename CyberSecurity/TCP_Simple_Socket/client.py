import socket

def iniciar_cliente():
    # 1. Configurações do servidor
    host = '127.0.0.1'   # Endereço IP do servidor (localhost)
    porta = 65432        # Porta que o servidor está escutando

    # 2. Criar o objeto socket
    # AF_INET: Indica protocolo IPv4
    # SOCK_STREAM: Indica protocolo TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # 3. Conectar ao servidor
            s.connect((host, porta))
            print(f"Conectado ao servidor {host}:{porta}")

            # 4. Enviar dados
            mensagem = "Olá, servidor! Sou o cliente Python."
            s.sendall(mensagem.encode('utf-8'))

            # 5. Receber a resposta (buffer de 1024 bytes)
            dados = s.recv(1024)
            print(f"Resposta recebida: {dados.decode('utf-8')}")

        except ConnectionRefusedError:
            print("Erro: Não foi possível conectar ao servidor. Ele está ativo?")
        except Exception as e:
            print(f"Ocorreu um erro: {e}")

if __name__ == "__main__":
    iniciar_cliente()