from databases.mongohandler import MongoHandler
from databases.entities import *
from customtkinter import *


class App(CTk):
    def __init__(self):
        super().__init__()

        # Conexão com o banco
        self.mongo = MongoHandler()
        self.mongo.connect()

        # Configurações da window:
        self.geometry("525x700")
        self.config(background="#00684a")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Definição das variáveis de conversa
        self.current_user = Users()
        self.current_receiver: Users = Users()
        self.current_messages: list[Messages] = []
        self.current_key: bytes = b''
        self.current_encrypted = True

        # Configurações dos widgets
        self.login = CTkFrame(self)
        self.register = CTkFrame(self)
        self.chat_list = CTkFrame(self)
        self.chat = CTkFrame(self)
        self.frame_menager(1)

    def login_user(self, username: str, password: str, message_label:CTkLabel):
        try:
            if username == '' or password == '' or username.isspace() or password.isspace():
                return
            user = self.mongo.get_user(username, password)
            if user.is_empty():
                message_label.configure(text='Usuário ou senha incorretos!')
            else:
                self.current_user = user
                self.frame_menager(3)
        except Exception as e:
            message_label.configure(text=e)

    def register_user(self, name: str, username: str, password, message_label: CTkLabel):
        try:
            if name == '' or username == '' or password == ' ' or\
               name.isspace() or username.isspace() or password.isspace():
                return
            user = Users()
            user.set_name(name)
            user.set_username(username)
            user.set_password(password)
            self.mongo.register_new_user(user)
            self.current_user = user
            message_label.configure(text='Usuário cadastrado com sucesso!', text_color="#33866e")
        except Exception as e:
            message_label.configure(text=e, text_color='#cc1919')

    def select_chat(self, second_user: Users):
        self.current_messages = self.mongo.get_messages(self.current_user, second_user)
        self.current_receiver = second_user
        self.frame_menager(4)

    def quit_chat(self):
        self.current_receiver = Users()
        self.current_messages: list[Messages] = []
        self.current_key: bytes = b''
        self.current_encrypted = True
        self.frame_menager(3)

    def error_popup(self, message: str):
        for i in range(len(message)):
            if i % 27 == 0:
                message = message[0:i] + '\n' + message[i:len(message)]
        error = CTkToplevel(self)
        error.geometry("500x300")
        CTkLabel(error, text=message, font=CTkFont(family="Aral", size=30),
                 text_color="#cc1919").pack(pady=(50, 30))
        CTkButton(error, text="Voltar", font=CTkFont(family="Arial", size=40), fg_color="#cc1919",
                  hover_color='#a31414', command=lambda :error.destroy()).pack()
        error.mainloop()

    def decrypt_conversation(self, passphrase: str):
        if self.current_encrypted is False:
            self.error_popup("As mensagens já estão desincriptadas!")
            return
        if passphrase.isspace() or passphrase == '':
            return
        try:
            salt = self.mongo.get_conversation_salt(self.current_user, self.current_receiver)
            key = Messages.derive_key(passphrase, salt)
            # Decifra tudo antes de mostrar: se uma mensagem falhar, a conversa continua cifrada.
            decrypted = [message.decrypted_content(key) for message in self.current_messages]
        except Exception as e:
            self.error_popup(str(e))
            return
        for message, content in zip(self.current_messages, decrypted):
            message.set_content(content)
            message.encrypted = False
        self.current_encrypted = False
        self.current_key = key
        self.frame_menager(4)

    def send_message(self, message: str):
        try:
            if message.isspace() or message == '':
                return
            if self.current_encrypted:
                self.error_popup("É preciso desencriptar a conversa antes de mandar mensagem!")
                return
            new_message = Messages(sender=self.current_user, receiver=self.current_receiver, content=message)
            new_message.encrypt_content(key=self.current_key)
            self.mongo.register_message(new_message)
            if self.current_encrypted:
                self.current_messages.append(new_message)
            else:
                new_message.decrypt_content(self.current_key)
                self.current_messages.append(new_message)
            self.frame_menager(4)
        except Exception as e:
            self.error_popup(str(e))

    def frame_menager(self, frame_number):
        self.login.destroy()
        self.register.destroy()
        self.chat_list.destroy()
        self.chat.destroy()
        if frame_number == 1:
            self.build_login()
        elif frame_number == 2:
            self.build_register()
        elif frame_number == 3:
            self.build_chat_list()
        elif frame_number == 4:
            self.build_chat()

    def build_login(self):
        self.login = CTkFrame(self, bg_color="#00684a")
        self.login.grid(row=0, column=0, padx=20, pady=120, sticky="nsew")
        CTkLabel(self.login, text="Login", font=CTkFont(family="Arial", size=80, weight='bold')).pack(pady=50)
        username = CTkEntry(self.login, placeholder_text="Username", font=CTkFont(family="Arial", size=22),
                         bg_color='transparent', corner_radius=30, width=400)
        username.pack(pady=10)
        password_frame = CTkFrame(self.login, bg_color='transparent',fg_color='transparent')
        password_frame.pack(pady=10)
        password = CTkEntry(password_frame, placeholder_text="Senha", font=CTkFont(family="Arial", size=22), show='*',
                            bg_color='transparent', corner_radius=30, width=360)
        password.grid(column=0, row=0)
        password_visibility = CTkButton(password_frame, text='👁️', font=CTkFont(family='Arial', size=25), width=30,
                                        border_spacing=0, hover=False, cursor='hand2', bg_color='transparent',
                                        fg_color='transparent',
                                        command=lambda :password.configure(show='') if password.cget('show') == '*'
                                        else password.configure(show='*'))
        password_visibility.grid(column=1, row=0)
        redirector_frame = CTkFrame(self.login, bg_color="transparent", fg_color='transparent')
        redirector_frame.pack()
        register_label = CTkLabel(redirector_frame, text="Ainda não tem conta?", fg_color='transparent',
                                  bg_color='transparent', font=CTkFont(family="Arial", size=20), text_color="white")
        register_label.grid(column = 0, row=0)
        register_button = CTkButton(redirector_frame, text="Crie uma agora", fg_color='transparent',
                                    bg_color='transparent', font=CTkFont(family="Arial", size=20, weight='bold'),
                                    text_color="#00684a", hover=False, cursor='hand2',
                                    command=lambda : self.frame_menager(2))
        register_button.grid(column = 1, row=0)
        login_button = CTkButton(self.login, text="Entrar", font=CTkFont(family="Arial", size=30),
                                 bg_color='transparent', fg_color="#00684a", corner_radius=30, width=280,
                                 hover_color="#00533b", cursor='hand2',
                                 command=lambda:self.login_user(username.get(), password.get(), message_label))
        login_button.pack(pady=10)
        message_label = CTkLabel(self.login, text='', font=CTkFont(family="Arial", size=20, weight='bold'),
                                 text_color='#cc1919')
        message_label.pack()

    def build_register(self):
        self.register = CTkFrame(self, bg_color="#00684a")
        self.register.grid(row=0, column=0, padx=20, pady=80, sticky="nsew")
        back_button = CTkButton(self.register, text="⭠", font=CTkFont('Arial', 50), bg_color='transparent',
                                fg_color='transparent', width=30, hover=False, cursor='hand2',
                                command=lambda :self.frame_menager(1))
        back_button.place(x=10, y=10)
        CTkLabel(self.register, text="Cadastro", font=CTkFont(family="Arial", size=80, weight='bold')).pack(pady=(70, 30))
        name = CTkEntry(self.register, placeholder_text="Nome", font=CTkFont(family="Arial", size=22),
                        bg_color='transparent', corner_radius=30, width=400)
        name.pack()
        username = CTkEntry(self.register, placeholder_text="Username", font=CTkFont(family="Arial", size=22),
                         bg_color='transparent', corner_radius=30, width=400)
        username.pack(pady=12)

        password_frame = CTkFrame(self.register, bg_color='transparent',fg_color='transparent')
        password_frame.pack()
        password = CTkEntry(password_frame, placeholder_text="Senha", font=CTkFont(family="Arial", size=22), show='*',
                            bg_color='transparent', corner_radius=30, width=360)
        password.grid(column=0, row=0)
        password_visibility = CTkButton(password_frame, text='👁️', font=CTkFont(family='Arial', size=25), width=30,
                                        border_spacing=0, hover=False, cursor='hand2', bg_color='transparent',
                                        fg_color='transparent',
                                        command=lambda :password.configure(show='') if password.cget('show') == '*'
                                        else password.configure(show='*'))
        password_visibility.grid(column=1, row=0)
        message_label = CTkLabel(self.register, text='', font=CTkFont(family="Arial", size=20, weight='bold'))
        message_label.pack(pady=5)
        register_button = CTkButton(self.register, text="Cadastrar-se", font=CTkFont(family="Arial", size=30),
                                    bg_color='transparent', fg_color="#00684a", corner_radius=30, width=280,
                                    hover_color="#00533b", cursor='hand2',
                                    command=lambda :self.register_user(name.get(), username.get(), password.get(), message_label))
        register_button.pack()

    def build_chat_list(self):
        self.chat_list = CTkFrame(self)
        self.chat_list.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.chat_list.grid_rowconfigure(0, weight=1)
        self.chat_list.grid_columnconfigure(0, weight=1)
        back_button = CTkButton(self.chat_list, text="⭠", font=CTkFont('Arial', size=50), bg_color='transparent',
                                fg_color='transparent', width=30, hover=False, cursor='hand2',
                                command=lambda :self.frame_menager(1))
        back_button.place(x=10, y=10)
        CTkLabel(self.chat_list, text="MongoZap", font=CTkFont(family='Arial', size=50)).place(x=125, y=10)
        users = CTkScrollableFrame(self.chat_list)
        users.grid_columnconfigure(0, weight=1)
        users.grid(row=0, column=0, padx=10, pady=(80, 10), sticky="nsew")
        users_list = self.mongo.get_all_users()
        for user in users_list:
            if user.username == self.current_user.username:
                continue
            button = CTkButton(users, fg_color='#545454', cursor='hand2', height=70, text=f'{user.name}',
                               font=CTkFont(family='Arial', size=25), anchor='w', hover_color="#434343",
                               command=lambda sec_user = user:self.select_chat(sec_user))
            button.grid(column=0, sticky="nsew", pady=(10, 0))

    def build_chat(self):
        self.chat = CTkFrame(self)
        self.chat.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.chat.grid_rowconfigure(0, weight=1)
        self.chat.grid_columnconfigure(0, weight=1)
        messages_frame = CTkScrollableFrame(self.chat)
        messages_frame.grid_columnconfigure(0, weight=1)
        messages_frame.grid(row=0, column=0, padx=10, pady=(80, 0), sticky="nsew")
        back_button = CTkButton(self.chat, text="⭠", font=CTkFont('Arial', size=50), bg_color='transparent',
                                fg_color='transparent', width=30, hover=False, cursor='hand2',
                                command=self.quit_chat)
        back_button.place(x=10, y=10)
        key = CTkEntry(self.chat, placeholder_text="Chave de criptografia", font=CTkFont('Arial', 22),
                       width=320)
        key.place(y=25, x=80)
        key_button = CTkButton(self.chat, text="🔑", font=CTkFont('Arial', size=40), bg_color='transparent',
                                fg_color='transparent', width=30, hover=False, cursor='hand2',
                                command=lambda: self.decrypt_conversation(key.get()))
        key_button.place(x=410, y=10)
        for message in self.current_messages:
            msg = CTkFrame(messages_frame, fg_color='#00533b')
            text = message.content
            for i in range(1, len(text) + 1):
                if i % 32 == 0:
                    text = text[0:i - 1] + '\n' + text[i - 1:len(text)]
            label = CTkLabel(msg, text=text, font=CTkFont("Arial", 22), fg_color='transparent',
                             bg_color='transparent')
            label.pack(pady=5, padx=10)
            if message.sender == self.current_user.get_id():
                msg.configure(fg_color='#545454')
                msg.grid(column=0, sticky='e', pady=(5,0))
            else:
                msg.grid(column=0, sticky='w', pady=(5,0))
        new_message_frame = CTkFrame(self.chat)
        new_message_frame.grid(row=1, column=0, pady=20)
        new_message = CTkEntry(new_message_frame, placeholder_text="Mensagem", font=CTkFont('Arial', 22),
                       width=400)
        new_message.pack(side='left')
        send_message = CTkButton(new_message_frame, text="➤", font=CTkFont('Arial', size=40), bg_color='transparent',
                                fg_color='transparent', width=30, hover=False, cursor='hand2',
                                command=lambda :self.send_message(new_message.get()))
        send_message.pack(side='left')

if __name__ == '__main__':
    app = App()
    app.mainloop()
