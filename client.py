import socket


class Client:

    def start(self, port):
        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect the socket to the port where the server is listening
        server_address = ('localhost', port)
        print('-> Connecting to %s port %s' % server_address)
        sock.connect(server_address)

        try:
            # Send data
            message = 'DATA'
            print('-> Sending "%s"' % message)
            sock.sendall(bytes(message, encoding='utf-8'))

            # Look for the response
            amount_received = 0
            amount_expected = len(message)

            while amount_received < amount_expected:
                data = sock.recv(16)
                amount_received += len(data)
                print('-> Received "%s"' % data)

        finally:
            print('-> Closing socket')
            sock.close()


def main():
    client = Client()
    client.start(8000)


if __name__ == '__main__':
    main()
