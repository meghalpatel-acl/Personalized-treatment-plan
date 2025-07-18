import tkinter as tk
from tkinter import messagebox
import os
from Utilities import Utilities
from Constants import *

class LoginApp:
    def __init__(self, root:tk.Tk):
        self.root = root
        self.root.title("Login / Signup Page")
        self.root.geometry("600x400")
        self.root.config(bg="#e6f2ff")
        self.utilities = Utilities()

        self.pass_matched = False

        # Buttons
        main_frame = self.PersonalDetails(self.root)

        btn_frame = tk.Frame(main_frame, bg="#ffe6e8")
        btn_frame.grid(row=4, column=0, columnspan=2, pady=(15, 5))
        login_button = self.utilities.CreateButton(btn_frame, "Login", self.Login)
        login_button.grid(row=0, column=0, padx=5)
        login_button = self.utilities.CreateButton(btn_frame, "Create New User", self.SignUpWindow)
        login_button.grid(row=0, column=1, padx=5)

        login_button = self.utilities.CreateButton(main_frame, "Forgot Password?", self.ForgotPassword)
        login_button.grid(row=5, column=0, columnspan=2, pady=(10, 0))

        self.root.protocol("WM_DELETE_WINDOW", self.OnClose)


        # Load users
        self.users = self.LoadUser()

    
    def PersonalDetails(self, parent:tk.Frame) -> tk.Frame:
        # Configure the root grid to center the frame
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_rowconfigure(1, weight=0)
        parent.grid_rowconfigure(2, weight=1)
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_columnconfigure(1, weight=0)
        parent.grid_columnconfigure(2, weight=1)

        # Create a frame to hold widgets (top center)
        main_frame = tk.Frame(parent, bg="#e6f2ff")
        main_frame.grid(row=0, column=1, sticky="n")

        # self.role = tk.StringVar(value="patient")

        # Title
        tk.Label(main_frame, text="Login System", font=("Arial", 16, "bold"), bg="#e6f2ff").grid(row=0, column=0, columnspan=2, pady=(10, 20))

        # Username
        tk.Label(main_frame, text="Username:", font=("Arial", 12), bg="#e6f2ff").grid(row=1, column=0, sticky="w", pady=5)
        self.username_entry = tk.Entry(main_frame)
        self.username_entry.grid(row=1, column=1, pady=5)

        # Password
        tk.Label(main_frame, text="Password:", font=("Arial", 12), bg="#e6f2ff").grid(row=2, column=0, sticky="w", pady=5)
        self.password_entry = tk.Entry(main_frame, show="*")
        self.password_entry.grid(row=2, column=1, pady=5)

        return main_frame


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


    def SaveUserToFile(self, role, username, password, question, answer):
        with open(USER_FILE, 'a') as f:
            f.write(f"{username}|{role}|{password}|{question}|{answer}\n")


    def UpdateFile(self):
        with open(USER_FILE, 'w') as f:
            for username, user in self.users.items():
                f.write(f"{username}|{user['role']}|{user['password']}|{user['question']}|{user['answer']}\n")


    def Login(self):
        # role = self.role.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        # print(self.users.get(role, {}).get(username))
        user = self.users.get(username, {})
        if user:
            role = user.get('role', {})
            if role == 'patient' or role == 'doctor':
                if user.get('password') == password:
                    messagebox.showinfo("Login Success", f"Welcome, {username} ({role})")
                    self.root.withdraw()
                    if role == "doctor":
                        self.OpenDoctorWindow(username)
                    else:
                        self.OpenPatientWindow(username)
                else:
                    messagebox.showerror("Login Failed", "Invalid password")
            else:
                messagebox.showerror("Login Failed", "Invalid role")
        else:
            messagebox.showerror("Login Failed", "Invalid username")


    def SignUpWindow(self):
        self.root.withdraw()
        self.sign_up_win = tk.Toplevel(background="#e6f2ff")
        self.sign_up_win.title("Sign UP")
        self.sign_up_win.geometry("600x400")

        main_frame = tk.Frame(self.sign_up_win, bg="#e6f2ff")
        main_frame.pack(pady=30)

        self.sign_up_role = tk.StringVar(value="patient")

        # Title
        tk.Label(main_frame, text="Login System", font=("Arial", 16, "bold"), bg="#e6f2ff").grid(
            row=0, column=0, columnspan=2, pady=(0, 20)
        )

        # Role
        tk.Label(main_frame, text="Login As:", font=("Arial", 12), bg="#e6f2ff", width=15, anchor="e").grid(
            row=1, column=0, sticky="e", padx=(10, 0), pady=5
        )
        role_frame = tk.Frame(main_frame, bg="#e6f2ff")
        role_frame.grid(row=1, column=1, sticky="w", pady=5)
        tk.Radiobutton(role_frame, text="Doctor", variable=self.sign_up_role, value="doctor", bg="#e6f2ff").grid(row=0, column=0, padx=5)
        tk.Radiobutton(role_frame, text="Patient", variable=self.sign_up_role, value="patient", bg="#e6f2ff").grid(row=0, column=1, padx=5)

        # Username
        tk.Label(main_frame, text="Username:", font=("Arial", 12), bg="#e6f2ff", width=15, anchor="e").grid(
            row=2, column=0, sticky="e", pady=5, padx=(10, 0)
        )
        self.signup_username_entry = tk.Entry(main_frame, width=30)
        self.signup_username_entry.grid(row=2, column=1, pady=5, sticky="w", padx=(5, 20))

        # Password
        tk.Label(main_frame, text="Password:", font=("Arial", 12), bg="#e6f2ff", width=15, anchor="e").grid(
            row=3, column=0, sticky="e", pady=5, padx=(10, 0)
        )
        self.signup_password_entry = tk.Entry(main_frame, show="*", width=30)
        self.signup_password_entry.grid(row=3, column=1, pady=5, sticky="w", padx=(5, 20))

        # Confirm Password
        tk.Label(main_frame, text="Confirm Password:", font=("Arial", 12), bg="#e6f2ff", width=15, anchor="e").grid(
            row=4, column=0, sticky="e", pady=5, padx=(10, 0)
        )
        confirm_password_var = tk.StringVar()
        signup_password_reentry = tk.Entry(main_frame, show="*", width=30, textvariable=confirm_password_var)
        signup_password_reentry.grid(row=4, column=1, pady=5, sticky="w", padx=(5, 20))
        confirm_password_var.trace_add("write", lambda *args: self.check_password_match(confirm_password_var,
                                                                                             self.signup_password_entry,
                                                                                             signup_password_reentry))

        # Security Question
        tk.Label(main_frame, text="Security Question:", font=("Arial", 12), bg="#e6f2ff", width=15, anchor="e").grid(
            row=5, column=0, sticky="e", pady=5, padx=(10, 0)
        )
        self.security_question = tk.StringVar()
        questions = [
            "What is your pet's name?",
            "What is your mother's maiden name?",
            "What is your favorite color?"
        ]
        self.security_question.set(questions[0])
        security_question_cb = self.utilities.CreateComboBox(main_frame, questions, width=28)
        security_question_cb.grid(row=5, column=1, pady=5, sticky="w", padx=(5, 20))

        # Security Answer
        tk.Label(main_frame, text="Your Answer:", font=("Arial", 12), bg="#e6f2ff", width=15, anchor="e").grid(
            row=6, column=0, sticky="e", pady=5, padx=(10, 0)
        )
        self.security_answer = tk.Entry(main_frame, width=30)
        self.security_answer.grid(row=6, column=1, pady=5, sticky="w", padx=(5, 20))

        # Sign Up Button
        sign_up_button = self.utilities.CreateButton(main_frame, "Sign UP", self.SignUP)
        sign_up_button.grid(row=7, column=0, columnspan=2, pady=(10, 5))

        # Sign Up Button
        back_button = self.utilities.CreateButton(main_frame, "Back to login", self.BackToLogin)
        back_button.grid(row=8, column=0, columnspan=2, pady=(10, 5))

        self.sign_up_win.protocol("WM_DELETE_WINDOW", self.BackToLogin)


    def BackToLogin(self, *args):
        if hasattr(self, "sign_up_win") and self.sign_up_win.winfo_exists():
            self.sign_up_win.destroy()
        if hasattr(self, "forgot_pass_win") and self.forgot_pass_win.winfo_exists():
            self.forgot_pass_win.destroy()
        if hasattr(self, "chane_pass_win") and self.forgot_pass_win.winfo_exists():
            self.chane_pass_win.destroy()
            
        self.root.deiconify()

    def check_password_match(self, first_pass, conf_pass, conf_entery):
        password = first_pass.get()
        confirm_password = conf_pass.get()
        if not confirm_password:
            conf_entery.config(foreground="red")
            self.pass_matched = False
        elif password == confirm_password:
            conf_entery.config(foreground="green")
            self.pass_matched = True
        else:
            conf_entery.config(foreground="red")
            self.pass_matched = False


    def SignUP(self):
        if self.pass_matched:
            role = self.sign_up_role.get()

            username = self.signup_username_entry.get()
            password = self.signup_password_entry.get()

            if not username or not password:
                messagebox.showerror("Error", "Username and Password cannot be empty.")
                return

            if username in self.users.get(role, {}):
                messagebox.showerror("Error", "User already exists.")
                return

            question = self.security_question.get().strip()
            answer = self.security_answer.get().strip() 
            # print(self.users)
            # self.users.setdefault(username, {})['role'] = {}
            self.users.setdefault(username, {})['role'] = role
            self.users.setdefault(username, {})['password']= password
            self.users.setdefault(username, {})['question'] = question
            self.users.setdefault(username, {})['answer'] = answer

            self.SaveUserToFile(role, username, password, question, answer)
            messagebox.showinfo("Success", "User created successfully! You can now log in.")

            self.sign_up_win.destroy()
            self.root.deiconify()

            self.pass_matched = False
        else:
            messagebox.showerror("Failed to signup", "Password does not match")

    def ForgotPassword(self):
        self.forgot_pass_win = tk.Toplevel()
        self.forgot_pass_win.title("Enter username")
        self.forgot_pass_win.geometry("300x200")
        tk.Label(self.forgot_pass_win, text="Username: ", font=("Arial", 12)).grid(row=0, column=0, pady=10, padx=10)
        self.user_ent_in_fp = tk.Entry(self.forgot_pass_win, width=15)
        self.user_ent_in_fp.grid(row=0, column=1)
        self.utilities.CreateButton(self.forgot_pass_win, text="Submit", function=self.AskQuestion).grid(row=1, column=0, pady=10)
        self.utilities.CreateButton(self.forgot_pass_win, text="Back to login", function=self.BackToLogin).grid(row=1, column=1)
        self.forgot_pass_win.protocol("WM_DELETE_WINDOW", self.BackToLogin)


    def AskQuestion(self):
        username = self.user_ent_in_fp.get().strip()
        if username not in self.users:
            messagebox.showerror("Error", "User not found.")
            return

        user = self.users.get(username, {})
        question = user['question']
        correct_answer = user['answer']

        # Create password recovery window
        if hasattr(self, "forgot_pass_win") and self.forgot_pass_win.winfo_exists():
            self.forgot_pass_win.destroy()
        self.recovery_win = tk.Toplevel(self.root)
        self.recovery_win.title("Recover Password")
        self.recovery_win.geometry("400x250")
        self.recovery_win.config(bg="#e6f2ff")

        tk.Label(self.recovery_win, text=f"Security Question:", font=("Arial", 12), bg="#e6f2ff").pack(pady=(20, 5))
        tk.Label(self.recovery_win, text=question, font=("Arial", 11), bg="#e6f2ff", wraplength=350).pack(pady=(0, 10))

        tk.Label(self.recovery_win, text="Your Answer:", font=("Arial", 12), bg="#e6f2ff").pack(pady=(5, 0))
        answer_entry = tk.Entry(self.recovery_win, width=40)
        answer_entry.pack(pady=(0, 15))

        def verify_answer():
            user_answer = answer_entry.get().strip()
            if user_answer.lower() == correct_answer.lower():
                self.recovery_win.destroy()
                self.OpenChangePasswordWindow(username)
            else:
                messagebox.showerror("Incorrect", "The answer doesn't match. Try again.", parent=self.recovery_win)

        submit_btn = self.utilities.CreateButton(self.recovery_win, "Submit", verify_answer)
        submit_btn.pack()

        self.recovery_win.protocol("WM_DELETE_WINDOW", self.recovery_win.destroy)



    def OpenChangePasswordWindow(self, username):
        self.chane_pass_win = tk.Toplevel(self.root)
        self.chane_pass_win.title("Change password")
        self.chane_pass_win.geometry("400x250")
        self.chane_pass_win.config(bg="#e6f2ff")

        # Password
        tk.Label(self.chane_pass_win, text="Password:", font=("Arial", 12), bg="#e6f2ff", width=15, anchor="e").grid(
            row=0, column=0, sticky="e", pady=5, padx=(10, 0)
        )
        self.change_password_entry = tk.Entry(self.chane_pass_win, show="*", width=30)
        self.change_password_entry.grid(row=0, column=1, pady=5, sticky="w", padx=(5, 20))

        # Confirm Password
        tk.Label(self.chane_pass_win, text="Confirm Password:", font=("Arial", 12), bg="#e6f2ff", width=15, anchor="e").grid(
            row=1, column=0, sticky="e", pady=5, padx=(10, 0)
        )
        confirm_password_var = tk.StringVar()
        signup_password_reentry = tk.Entry(self.chane_pass_win, show="*", width=30, textvariable=confirm_password_var)
        signup_password_reentry.grid(row=1, column=1, pady=5, sticky="w", padx=(5, 20))
        confirm_password_var.trace_add("write", lambda *args: self.check_password_match(confirm_password_var,
                                                                                             self.change_password_entry,
                                                                                             signup_password_reentry))

        # Submit
        self.utilities.CreateButton(self.chane_pass_win, text="Submit", function=lambda *args: self.ChangePassword(username)).grid(row=2, column=0, columnspan=2)
        self.chane_pass_win.protocol("WM_DELETE_WINDOW", self.BackToLogin)



    def ChangePassword(self, username):
        try:
            if self.pass_matched:
                self.users[username]['password'] = self.change_password_entry.get()
                self.UpdateFile()
                self.chane_pass_win.destroy()
                messagebox.showinfo("Success", "Password change successfully")
                self.pass_matched = False
            else:
                messagebox.showerror("Failed to change password", "Password does not match", parent=self.chane_pass_win)
        except Exception as e:
            print(e)
            messagebox.showerror("Failed to change password", "Exception occured while changing password", 
                                 parent=self.chane_pass_win)
    
        
    def OpenDoctorWindow(self, username):
        self.doctor_win = tk.Toplevel()
        self.doctor_win.title("Doctor Utility")
        self.doctor_win.geometry("300x200")
        tk.Label(self.doctor_win, text=f"Doctor: {username}", font=("Arial", 12)).grid(row=0, column=0, pady=10, padx=10)
        tk.Button(self.doctor_win, text="View Patients", command=lambda: messagebox.showinfo("Patients", "No patients today")).grid(row=1, column=0, pady=10)
        tk.Button(self.doctor_win, text="Logout", command=lambda: self.Logout()).grid(row=2, column=0)
        self.doctor_win.protocol("WM_DELETE_WINDOW", self.OnClose)

    def OpenPatientWindow(self, username):
        self.patient_win = tk.Toplevel()
        self.patient_win.title("Patient Utility")
        self.patient_win.geometry("300x200")
        tk.Label(self.patient_win, text=f"Patient: {username}", font=("Arial", 12)).grid(row=0, column=0, pady=10, padx=10)
        tk.Button(self.patient_win, text="View Reports", command=lambda: messagebox.showinfo("Reports", "No new reports")).grid(row=1, column=0, pady=10)
        tk.Button(self.patient_win, text="Logout", command=lambda: self.Logout()).grid(row=2, column=0)
        self.patient_win.protocol("WM_DELETE_WINDOW", self.OnClose)

    def Logout(self):
        print("On close")

        if hasattr(self, "sign_up_win") and self.sign_up_win.winfo_exists():
            self.sign_up_win.destroy()

        if hasattr(self, "doctor_win") and self.doctor_win.winfo_exists():
            self.doctor_win.destroy()

        if hasattr(self, "patient_win") and self.patient_win.winfo_exists():
            self.patient_win.destroy()

        self.root.deiconify()

    def OnClose(self):
        if hasattr(self, "sign_up_win") and self.sign_up_win.winfo_exists():
            self.sign_up_win.destroy()

        if hasattr(self, "doctor_win") and self.doctor_win.winfo_exists():
            self.doctor_win.destroy()

        if hasattr(self, "patient_win") and self.patient_win.winfo_exists():
            self.patient_win.destroy()

        self.root.deiconify()
        self.root.destroy()