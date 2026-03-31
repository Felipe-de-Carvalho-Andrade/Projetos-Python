import socket

def iniciar_servidor():
    # 1. Configurações do servidor
    host = '127.0.0.1'   # Endereço IP do servidor (localhost)
    porta = 65432        # Porta que o servidor está escutando

    # 2. Criar o objeto socket
    # AF_INET: Indica protocolo IPv4
    # SOCK_STREAM: Indica protocolo TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

        # 3. Bind
        # Associa o socket ao endereço e porta específicos.
        s.bind((host, porta))
        
        # 4. Listen
        # Coloca o socket em modo de espera por conexões.
        s.listen()
        print(f"Servidor aguardando conexões em {host}:{porta}...")

        # 5. Accept
        # O programa 'trava' aqui até que um cliente se conecte.
        # Retorna um novo objeto socket e o endereço do cliente.
        conn, addr = s.accept()
        
        with conn:
            print(f"Conectado com sucesso por: {addr}")
            
            while True:
                # 6. Receber dados (Buffer de 1024 bytes)
                dados = conn.recv(1024)
                
                # Se o cliente fechar a conexão, 'dados' virá vazio
                if not dados:
                    print("Cliente encerrou a conexão.")
                    break
                
                mensagem_recebida = dados.decode('utf-8')
                print(f"Mensagem do cliente: {mensagem_recebida}")

                # 7. Responder ao cliente
                resposta = "Olá cliente, recebi sua mensagem!".encode('utf-8')
                conn.sendall(resposta)

if __name__ == "__main__":
    iniciar_servidor()