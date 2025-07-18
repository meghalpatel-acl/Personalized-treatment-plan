from Constants import *
import os
import socket
import threading

class Server:
    def __init__(self):
        self.users = self.LoadUser()
        self.InitTCPServer()

    def __del__(self):
        print("Closing")
        self.server.close()

    # Handle each client in a separate thread
    def HandleClient(self, conn, addr):
        print(f"[NEW CONNECTION] {addr} connected.")
        try:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                print(f"[{addr}] {data.decode()}")
                response = self.HandleCommand(data.decode())
                conn.sendall(response.encode('utf-8'))

        except Exception as e:
            print(f"Error with {addr}: {e}")
        finally:
            conn.close()
            print(f"[DISCONNECTED] {addr}")


    def InitTCPServer(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((SERVER_HOST, SERVER_PORT))
        self.server.listen(5)
        
        print(f"[LISTENING] Server is running on {SERVER_HOST}:{SERVER_PORT}")

        while True:
            conn, addr = self.server.accept()
            thread = threading.Thread(target=self.HandleClient, args=(conn, addr))
            thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")


    def HandleCommand(self, command_str:str):
        try:
            command, value = command_str.split('::')
            print(command)
            print(value)
            if int(command) == GET_DETAILS:
                if value in self.users:
                    user = self.users[value]
                    formated_str = f"{value}|{user['role']}|{user['password']}|{user['question']}|{user['answer']}"
                    return formated_str
                else:
                    return str(INVALID_USER)
                
            elif int(command) == ADD_USER:
                username, role, password, question, answer = value.split('|')
                if username in self.users:
                    return str(USER_EXIST)
                self.users.setdefault(username, {})['role'] = role
                self.users.setdefault(username, {})['password']= password
                self.users.setdefault(username, {})['question'] = question
                self.users.setdefault(username, {})['answer'] = answer
                self.SaveUserToFile(username, role, password, question, answer)
                return str(SUCCESS)

            elif int(command) == UPDATE_PASSWORD:
                username, password = value.split('|')
                if username in self.users:
                    self.users[username]['password'] = password
                    self.UpdateFile()
                    return str(SUCCESS)
                else:
                    return str(INVALID_USER)
                
            else:
                print("Invalid command")
                return str(INVALID_USER)
        except Exception as e:
            print("Exception : ", str(e))
        
    def LoadUser(self):
        users = {}
        if os.path.exists(USER_FILE):
            with open(USER_FILE, 'r') as f:
                for line in f:
                    parts = line.strip().split('|')
                    if len(parts) == 5:
                        username, role, password, question, answer = parts
                        users[username] = {
                            "role": role,
                            "password": password,
                            "question": question,
                            "answer": answer
                        }
        return users

    def SaveUserToFile(self, username, role, password, question, answer):
        with open(USER_FILE, 'a') as f:
            f.write(f"{username}|{role}|{password}|{question}|{answer}\n")

    def UpdateFile(self):
        with open(USER_FILE, 'w') as f:
            for username, user in self.users.items():
                f.write(f"{username}|{user['role']}|{user['password']}|{user['question']}|{user['answer']}\n")


if __name__ == "__main__":
    svr = Server()