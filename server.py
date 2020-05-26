import socket


class Server:

    def start(self, port):
        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Listen for incoming connections
        server_address = ('localhost', port)
        sock.bind(server_address)
        sock.listen(1)

        while True:
            # Wait for a connection
            print('-> Waiting for a connection')
            connection, client_address = sock.accept()

            try:
                print('-> Connection from', client_address)

                # Receive the data in small chunks and retransmit it
                while True:
                    data = connection.recv(16)
                    print('-> Received: %s' % data)
                    if data:
                        print('-> Sending data back to the client')
                        connection.sendall(data)
                    else:
                        print('-> No more data from', client_address)
                        break

            finally:
                # Clean up the connection
                connection.close()

def main():
    server = Server()
    server.start(8000)


if __name__ == '__main__':
    main()
