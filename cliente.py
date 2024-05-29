import asyncio
import websockets
import ssl
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Gerar par de chaves RSA do cliente
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Serializar a chave pública para enviar ao servidor
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open("public_key.pem", "rb") as key_file:
    server_public_key = serialization.load_pem_public_key(key_file.read())

async def send_message():
    uri = "wss://localhost:8765"  # Substituir pelo IP do servidor se necessário
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    try:
        async with websockets.connect(uri, ssl=ssl_context) as websocket:
            # Enviar a chave pública ao servidor
            await websocket.send(public_key_pem)
            print("Chave pública enviada ao servidor.")

            message = "Teste Teste!"
            encrypted_message = server_public_key.encrypt(
                message.encode(),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            print(f"Enviando mensagem criptografada: {encrypted_message}")
            await websocket.send(encrypted_message)

            response = await websocket.recv()
            print(f"Resposta criptografada recebida: {response}")
            decrypted_response = private_key.decrypt(
                response,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            ).decode()
            print(f"Resposta decriptografada recebida: {decrypted_response}")

    except websockets.exceptions.ConnectionClosedOK:
        print("Conexão fechada normalmente.")
    except Exception as e:
        print(f"Erro no cliente: {e}")

if __name__ == "__main__":
    asyncio.run(send_message())
