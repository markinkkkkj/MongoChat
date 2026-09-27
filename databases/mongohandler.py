import os

from pymongo import MongoClient, ReturnDocument
from pymongo.errors import DuplicateKeyError, PyMongoError
from pymongo.synchronous.database import Database

from databases.entities import *

class MongoHandler:
    def __init__(self, connection_string=None, database_name=None):
        self.connection_string = connection_string
        self.database_name = database_name
        self.client = MongoClient
        self.database = Database
        # A connection string carrega usuário e senha do banco: vem do ambiente, nunca do código.
        if connection_string is None:
            self.connection_string = os.environ.get("MONGOCHAT_URI")
        if not self.connection_string:
            raise Exception('''Variável de ambiente MONGOCHAT_URI não definida!
Defina a connection string do MongoDB antes de
iniciar o chat (veja o README).''')
        if database_name is None:
            self.database_name = os.environ.get("MONGOCHAT_DB", "mongo_chat")

    def connect(self):
        try:
            self.client = MongoClient(self.connection_string, serverSelectionTimeoutMS=5000)
            self.client.admin.command("ping")
            self.database = self.client.get_database(self.database_name)
            self.database["users"].create_index("username", unique=True)
            self.database["conversations"].create_index("conversation_id", unique=True)
        except PyMongoError as e:
            print(f"Falha na conexão com o Banco de Dados: {e}")
            self.client = None

    def get_user(self, username: str, password: str) -> Users:
        # Busca só o usuário pedido: a lista de usuários (e os hashes) nunca sai do banco.
        # Username vira sempre string, então não dá para injetar operadores do MongoDB ($ne, $gt...).
        document = self.database["users"].find_one({"username": str(username)})
        if document is None:
            # Calcula um hash mesmo sem usuário, para o tempo de resposta não revelar quais usernames existem.
            Users.verify_password(Users.dummy_hash(), password)
            return Users()
        if not Users.verify_password(document.get("password_hash", ""), password):
            return Users()
        found_user = Users()
        found_user.set_user_by_database(document)
        return found_user

    def get_all_users(self):
        documents = self.database["users"].find({}, {"password_hash": 0})
        users_list = []
        for doc in documents:
            found_user = Users()
            found_user.set_user_by_database(doc)
            users_list.append(found_user)
        return users_list

    def register_new_user(self, new_user: Users):
        duplicated = Exception('''Username já cadastrado!
O username informado já está associado
a uma conta. Por favor, utilize outro.''')
        users = self.database["users"]
        if users.find_one({"username": new_user.username}, {"_id": 1}) is not None:
            raise duplicated
        try:
            result = users.insert_one(new_user.to_dict())
        except DuplicateKeyError:
            # Dois cadastros simultâneos com o mesmo username: o índice único barra o segundo.
            raise duplicated
        new_user.set_id(result.inserted_id)

    def get_conversation_salt(self, first_user: Users, second_user: Users) -> bytes:
        # Cada conversa tem um salt aleatório para derivar a chave a partir da senha combinada.
        conversation_id = ":".join(sorted([str(first_user.get_id()), str(second_user.get_id())]))
        conversation = self.database["conversations"].find_one_and_update(
            {"conversation_id": conversation_id},
            {"$setOnInsert": {"conversation_id": conversation_id, "kdf_salt": os.urandom(16)}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        return conversation["kdf_salt"]

    def get_messages(self, first_user: Users, second_user: Users) -> list[Messages]:
        results = self.database["messages"].find({
            "sender": {
                "$in": [first_user.get_id(), second_user.get_id()]
            },
            "receiver": {
                "$in": [first_user.get_id(), second_user.get_id()]
            }
        }).sort("timestamp", 1)
        messages = []
        for message in results:
            found_message = Messages()
            found_message.set_message_by_database(message)
            messages.append(found_message)
        return messages


    def register_message(self, message: Messages):
        if message.encrypted is False:
            raise Exception ("Mensagens não encriptadas não podem ser salvas no banco de dados!")
        self.database["messages"].insert_one(message.to_dict())
