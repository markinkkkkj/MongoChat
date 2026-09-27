from base64 import b64decode, b64encode
from bson.objectid import ObjectId
from datetime import datetime
from hashlib import pbkdf2_hmac, scrypt
from hmac import compare_digest
from os import urandom
from re import compile
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Parâmetros do scrypt para as senhas (mínimo recomendado pela OWASP: N=2^17, r=8, p=1).
SCRYPT_N = 2 ** 17
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 256 * 1024 * 1024

# Iterações do PBKDF2-SHA256 para derivar a chave da conversa (recomendação da OWASP).
KDF_ITERATIONS = 600_000

class Users:
    def __init__(self, name=None, username=None, password=None):
        self._id = None
        self.name = None
        self.username = None
        self.password_hash = None
        if name is not None:
            self.set_name(name)
        if username is not None:
            self.set_username(username)
        if password is not None:
            self.set_password(password)

    @staticmethod
    def format_name(name: str) -> str:
        for i in range(2):
            blank_space = 0
            for letter in name:
                if letter == ' ':
                    blank_space += 1
                else:
                    break
            name = name[blank_space: len(name)]
            name = name[::-1]
        return name

    def is_empty(self) -> bool:
        if self.name is None and self.username is None and self.password_hash is None:
            return True
        else:
            return False

    def set_name(self, name: str):
        name = Users.format_name(name)
        if name.replace(' ', '').isalpha() is False:
            raise Exception("Nome inválido!\nO nome não pode conter números.")
        self.name = name

    def set_username(self, username: str):
        username = username.replace(' ', '')
        regex = compile(r"^(?=[a-zA-Z0-9._-]{3,16}$)(?!.*[_.-]{2})[a-zA-Z0-9]+([._-][a-zA-Z0-9]+)*$")
        if regex.match(username) is None:
            raise Exception('''Username inválido!
Deve ter de 3 a 16 caracteres alfanuméricos
e pode incluir '_', '.' ou '-'. Não pode
começar ou terminar com caracteres especiais,
nem usá-los consecutivamente.''')
        self.username = username

    def set_password(self, password: str):
        password = password.replace(' ', '')
        regex = compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$")
        if regex.match(password) is None:
            raise Exception('''Senha inválida!
A senha deve ter no mínimo 8 caracteres,
incluindo uma letra maiúscula, uma minúscula,
um número e um caractere especial (@$!%*?&).''')
        # A senha nunca é guardada: só o hash, com salt aleatório.
        self.password_hash = Users.hash_password(password)

    @staticmethod
    def hash_password(password: str, salt: bytes = None) -> str:
        if salt is None:
            salt = urandom(16)
        derived = scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                         maxmem=SCRYPT_MAXMEM, dklen=32)
        return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${b64encode(salt).decode()}${b64encode(derived).decode()}"

    @staticmethod
    def verify_password(password_hash: str, password: str) -> bool:
        if not isinstance(password, str) or not isinstance(password_hash, str):
            return False
        try:
            algorithm, n, r, p, salt, expected = password_hash.split("$")
            if algorithm != "scrypt":
                return False
            derived = scrypt(password.replace(' ', '').encode(), salt=b64decode(salt), n=int(n), r=int(r),
                             p=int(p), maxmem=SCRYPT_MAXMEM, dklen=32)
        except ValueError:
            return False
        # Comparação em tempo constante, para não vazar quantos bytes batem.
        return compare_digest(derived, b64decode(expected))

    _dummy_hash = None

    @staticmethod
    def dummy_hash() -> str:
        if Users._dummy_hash is None:
            Users._dummy_hash = Users.hash_password("dummy-password")
        return Users._dummy_hash

    def set_id(self, _id):
        if type(_id) != ObjectId:
            raise Exception("Id inválido!")
        self._id = _id

    def get_id(self):
        return self._id

    def set_user_by_database(self, user:dict):
        self._id = user.pop("_id")
        self.name = user.pop("name", None)
        self.username = user.pop("username", None)
        self.password_hash = user.pop("password_hash", None)

    def to_dict(self):
        return {
            'name': self.name,
            'username': self.username,
            'password_hash': self.password_hash
        }

    def __eq__(self, other):
        if type(other) != type(self):
            return False
        if other.get_id() != self._id:
            return False
        if other.name != self.name:
            return False
        if other.username != self.username:
            return False
        return True

class Messages:
    def __init__(self, sender: Users=None, receiver: Users=None, content: str=None, encrypted=False):
        self._id = None
        self.sender = None
        self.receiver = None
        self.content = None
        self.timestamp = datetime.now()
        self.encrypted = False
        if sender is not None:
            self.set_sender(sender)
        if receiver is not None:
            self.set_receiver(receiver)
        if content is not None:
            self.set_content(content)
        if encrypted:
            self.encrypted = True

    def set_sender(self, sender: Users):
        if self.receiver is not None and self.receiver == sender:
            raise Exception("Não é possível enviar uma mensagem de mesmo remetente e destinatário!")
        self.sender = sender.get_id()

    def set_receiver(self, receiver: Users):
        if self.sender is not None and self.sender == receiver:
            raise Exception("Não é possível enviar uma mensagem de mesmo remetente e destinatário!")
        self.receiver = receiver.get_id()

    def set_content(self, content: str):
        if content.isspace() or content == '':
            raise Exception("A mensagem não pode ser vazia!")
        self.content = content

    @staticmethod
    def derive_key(passphrase: str, salt: bytes) -> bytes:
        # A senha combinada entre os dois usuários vira uma chave AES-256 por PBKDF2, com o salt da conversa.
        if passphrase.isspace() or passphrase == '':
            raise Exception("A chave de criptografia não pode ser vazia!")
        return pbkdf2_hmac("sha256", passphrase.encode(), salt, KDF_ITERATIONS, dklen=32)

    def associated_data(self) -> bytes:
        # Amarra o texto cifrado ao remetente e ao destinatário: trocar os campos no banco invalida a mensagem.
        return f"{self.sender}:{self.receiver}".encode()

    def encrypt_content(self, key: bytes):
        if self.encrypted:
            raise Exception("Mensagem já encriptada!")
        if self.content is None:
            raise Exception("Não há mensagem a ser encriptadas!")
        # AES-GCM com nonce aleatório de 12 bytes por mensagem: nunca reutilizar nonce com a mesma chave.
        nonce = urandom(12)
        encrypted = AESGCM(key).encrypt(nonce, self.content.encode(), self.associated_data())
        self.set_content(b64encode(nonce + encrypted).decode())
        self.encrypted = True

    def decrypted_content(self, key: bytes) -> str:
        if self.encrypted is False:
            raise Exception("Mensagem já desencriptada!")
        if self.content is None:
            raise Exception("Não há mensagem a ser desencriptada!")
        try:
            raw = b64decode(self.content)
            decrypted = AESGCM(key).decrypt(raw[:12], raw[12:], self.associated_data())
        except (InvalidTag, ValueError):
            # O GCM autentica a mensagem: chave errada ou conteúdo alterado dão erro, nunca texto trocado.
            raise Exception("Chave incorreta ou mensagem adulterada!")
        return decrypted.decode()

    def decrypt_content(self, key: bytes):
        self.set_content(self.decrypted_content(key))
        self.encrypted = False

    def set_message_by_database(self, message: dict):
        self._id = message.pop("_id")
        self.sender = message.pop("sender", None)
        self.receiver = message.pop("receiver", None)
        self.content = message.pop("content", None)
        self.timestamp = message.pop("timestamp", None)
        message.pop("cipher", None)
        self.encrypted = True

    def to_dict(self):
        return {
            'sender': self.sender,
            'receiver': self.receiver,
            'content': self.content,
            'cipher': 'AES-256-GCM',
            'timestamp': self.timestamp
        }
