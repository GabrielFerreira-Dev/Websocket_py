import asyncio
import websockets
import ssl
from cryptography.fernet import Fernet

# Chave gerada pelo servidor
key = b'5RtpGd0KW6L9DUAvfhPZwFsRd7Ejy7u9qKgb4GdGcHI='
cipher_suite = Fernet(key)

async def send_message():
    uri = "wss://<IP_DO_SERVIDOR>:8765" # substituir pelo IP do servidor
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    async with websockets.connect(uri, ssl=ssl_context) as websocket:
        message = "Teste Teste!"
        encrypted_message = cipher_suite.encrypt(message.encode())
        print(f"Enviando mensagem criptografada: {encrypted_message}")
        await websocket.send(encrypted_message)
        response = await websocket.recv()
        decrypted_response = cipher_suite.decrypt(response).decode()
        print(f"Resposta decriptografada recebida: {decrypted_response}")

if __name__ == "__main__":
    asyncio.run(send_message())
