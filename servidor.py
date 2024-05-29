import asyncio
import websockets
import ssl
import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Carregar a chave privada RSA do servidor
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(), password=None)

def get_ip_address():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address

async def echo(websocket, path):
    try:
        # Receber a chave pública do cliente
        client_public_key_pem = await websocket.recv()
        client_public_key = serialization.load_pem_public_key(client_public_key_pem)
        print("Chave pública do cliente recebida.")

        async for message in websocket:
            print(f"Mensagem criptografada recebida: {message}")
            decrypted_message = private_key.decrypt(
                message,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            ).decode()
            print(f"Mensagem decriptografada: {decrypted_message}")
            response = f"Eco: {decrypted_message}".encode()
            encrypted_response = client_public_key.encrypt(
                response,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            print(f"Enviando resposta criptografada: {encrypted_response}")
            await websocket.send(encrypted_response)
    except Exception as e:
        print(f"Erro no servidor: {e}")
        await websocket.close()

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(certfile="server_cert.pem", keyfile="server_key.pem")

async def main():
    async with websockets.serve(echo, "0.0.0.0", 8765, ssl=ssl_context):
        print("O endereço IP do servidor é:", get_ip_address() + ":8765")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
