# MongoChat: chat desktop com MongoDB e criptografia

## Descrição

Chat desktop com interface gráfica em CustomTkinter, desenvolvido em 2024 para a disciplina de Estudo de Banco de Dados 2. As mensagens ficam num banco MongoDB (via PyMongo) e são cifradas com AES-256-GCM antes de sair da máquina do usuário.

## Funcionalidades

- **Cadastro e login** com validação de nome, username e senha.
- **Lista de conversas** com os outros usuários cadastrados.
- **Mensagens cifradas:** cada conversa é aberta com uma senha combinada entre os dois usuários; sem ela, o conteúdo aparece cifrado.
- **Armazenamento em MongoDB:** usuários, conversas e mensagens persistidos num banco NoSQL.
- **Interface gráfica** em CustomTkinter.

## Segurança

Revisão de 2026 corrigiu as falhas da versão original (connection string no código, senha em texto puro e AES-CBC com IV fixo):

- **Credenciais fora do código:** a connection string vem da variável de ambiente `MONGOCHAT_URI`.
- **Senhas com hash:** só o hash scrypt (N=2^17, r=8, p=1) com salt aleatório vai para o banco, e a comparação é em tempo constante.
- **Login no banco, não no cliente:** o app busca só o usuário pedido; a lista de usuários nunca traz os hashes. Usuário inexistente custa o mesmo tempo que senha errada, para não revelar quais usernames existem.
- **Username único** garantido por índice no MongoDB.
- **Cifra autenticada:** AES-256-GCM com nonce aleatório por mensagem. Chave errada ou mensagem alterada são detectadas, e trocar remetente ou destinatário no banco invalida a mensagem (dados associados).
- **Chave derivada:** a senha combinada vira uma chave de 256 bits por PBKDF2-SHA256 (600.000 iterações), com salt aleatório por conversa.

Limite conhecido: a senha da conversa é combinada fora do app, e não há troca de chaves (como Diffie-Hellman) nem sigilo futuro.

## Tecnologias Utilizadas

- **Python:** Linguagem principal do projeto.
- **CustomTkinter:** Interface gráfica.
- **PyMongo:** Biblioteca para interação com o MongoDB.
- **cryptography:** AES-256-GCM para as mensagens.
- **hashlib:** scrypt para as senhas e PBKDF2 para derivar a chave da conversa.
- **MongoDB:** Banco de dados NoSQL utilizado para armazenamento.

## Como Executar o Projeto

1. **Clone o repositório:**
   ```bash
   git clone https://github.com/markinkkkkj/MongoChat.git
   cd MongoChat
   ```

2. **Criação do Ambiente Virtual:**
   Para garantir que todas as dependências sejam isoladas do sistema, crie e ative um ambiente virtual Python:

   macOS/Linux
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

   Windows
   ```bash
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   ```

   > **Nota:** Se estiver utilizando o PyCharm, configure o interpretador do projeto para o ambiente virtual recém-criado acessando: `File > Settings > Project: MongoChat > Python Interpreter` e selecionando o ambiente virtual `.venv`.

3. **Instale as dependências:**
   Após ativar o ambiente virtual, instale os pacotes necessários a partir do arquivo `requirements.txt`:
   ```bash
   pip install -r requirements.txt
   ```

   No Linux, o Tkinter pode exigir o pacote do sistema (`tk` no Arch, `python3-tk` no Debian/Ubuntu).

4. **Configure o banco:** defina a connection string do MongoDB (Atlas ou local). Nunca coloque a senha do banco no código.

   macOS/Linux
   ```bash
   export MONGOCHAT_URI="mongodb://127.0.0.1:27017"
   ```

   Windows
   ```bash
   $env:MONGOCHAT_URI = "mongodb://127.0.0.1:27017"
   ```

   Opcional: `MONGOCHAT_DB` muda o nome do banco (padrão: `mongo_chat`).

5. **Execute o chat:**
   ```bash
   python main.py
   ```

6. **Inicie a conversa:** faça login, escolha um usuário e digite a senha combinada com ele no campo de chave (🔑).

## Contribuições

Contribuições são bem-vindas! Sinta-se à vontade para enviar um pull request ou abrir uma issue para sugestões ou problemas.

## Licença

Este projeto está licenciado sob a MIT License. Consulte o arquivo LICENSE para mais detalhes.
