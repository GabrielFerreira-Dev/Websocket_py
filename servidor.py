import asyncio
import websockets
import ssl
import socket
from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher_suite = Fernet(key)


def get_ip_address():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address


async def echo(websocket, path):
    async for message in websocket:
        print(f"Mensagem criptografada recebida: {message}")
        decrypted_message = cipher_suite.decrypt(message).decode()
        print(f"Mensagem decriptografada: {decrypted_message}")
        response = f"Eco: {decrypted_message}".encode()
        encrypted_response = cipher_suite.encrypt(response)
        await websocket.send(encrypted_response)


ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(certfile="server_cert.pem", keyfile="server_key.pem")


async def main():
    async with websockets.serve(echo, "localhost", 8765, ssl=ssl_context):
        print("O endereço IP do servidor é:", get_ip_address() + ":8765")
        print("Chave: ", key)
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())

    import socket

