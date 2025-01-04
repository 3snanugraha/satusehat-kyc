import base64
import json
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import requests
from dotenv import load_dotenv

load_dotenv()

class KYC:
    def __init__(self):
        self.client_id = os.getenv('CLIENT_ID')
        self.client_secret = os.getenv('CLIENT_SECRET')
        self.satu_sehat_http_url = os.getenv('SATU_SEHAT_HTTP_URL')
        self.satu_sehat_pub_pem = os.getenv("SATUSEHAT_PUB_PEM")

    def generate_key(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        return {
            'publicKey': public_key_pem.decode(),
            'privateKey': private_key_pem.decode()
        }

    def encrypt_message(self, message, pub_pem):
        aes_key = os.urandom(32)
        server_key = serialization.load_pem_public_key(
            pub_pem.encode(),
            backend=default_backend()
        )

        wrapped_key = server_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        iv = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        encrypted_message = iv + ciphertext + encryptor.tag

        payload = wrapped_key + encrypted_message
        data_as_base64 = base64.b64encode(payload).decode()
        return f"-----BEGIN ENCRYPTED MESSAGE-----\r\n{data_as_base64}\r\n-----END ENCRYPTED MESSAGE-----"

    def decrypt_message(self, message, private_key):
        content = message.split('-----BEGIN ENCRYPTED MESSAGE-----\n')[1]
        content = content.split('\n-----END ENCRYPTED MESSAGE-----')[0].strip()
        binary_data = base64.b64decode(content)

        wrapped_key = binary_data[:256]
        encrypted_message = binary_data[256:]

        key = serialization.load_pem_private_key(
            private_key.encode(),
            password=None,
            backend=default_backend()
        )

        try:
            aes_key = key.decrypt(
                wrapped_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            iv = encrypted_message[:12]
            tag = encrypted_message[-16:]
            ciphertext = encrypted_message[12:-16]

            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext).decode() + decryptor.finalize().decode()

        except Exception as e:
            print(f"decryption failed: {e}")
            return None

    def generate_url(self, access_token: str ,agent_name: str, agent_nik: str) -> str:
        key_pair = self.generate_key()

        data = {
            'agent_name': agent_name,
            'agent_nik': agent_nik,
            'public_key': key_pair['publicKey'],
        }

        encrypted_payload = self.encrypt_message(
            json.dumps(data),
            self.satu_sehat_pub_pem
        )

        headers = {
            'Content-Type': 'text/plain',
            'Authorization': f'Bearer {access_token}'
        }

        response = requests.post(
            url=f"{self.satu_sehat_http_url}/kyc/v1/generate-url",
            data=encrypted_payload,
            headers=headers
        )

        if response.status_code != 200:
            print(f'Error: {response.status_code}, {response.json()}')
            return None

        decrypted = self.decrypt_message(response.text, key_pair['privateKey'])
        decrypted_json = json.loads(decrypted)
        return decrypted_json["data"]["url"]

    def generate_token(self) -> str:
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }

        try:
            response = requests.post(
                url=f"{self.satu_sehat_http_url}/oauth2/v1/accesstoken",
                params={"grant_type": "client_credentials"},
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=30
            )

            response.raise_for_status()
            return response.json()["access_token"]

        except requests.RequestException as e:
            print(f"failed to generate token, HTTP error: {e}")
            return None
        except (KeyError, json.JSONDecodeError) as e:
            print(f"failed to parse token from response: {e}")
            return None


if __name__ == "__main__":
    kyc = KYC()
    access_token = kyc.generate_token()
    result = kyc.generate_url(access_token,"x", "x")
    print(result)
