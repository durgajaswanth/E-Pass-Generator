from tkinter import *
from random import randint
import re

password_window_opened = False

def passGenerator():
    global password_window_opened
    if not password_window_opened:
        password_window_opened = True
        # ---Password Generator window---
        window = Tk()
        window.title("Password Generator")
        
        def on_close():
            global password_window_opened
            password_window_opened = False
            window.destroy()
            
        window.protocol("WM_DELETE_WINDOW", on_close)
                
        # ---Generated password strength---
        def calculate_strength(password):
            score = 0
            length = len(password)

            if length >= 8:
                score += 2
            elif length >= 6:
                score += 1

            if re.search(r'[A-Z]', password) and re.search(r'[a-z]', password):
                score += 2
            elif re.search(r'[A-Za-z]', password):
                score += 1
            if re.search(r'\d', password):
                score += 1
            if re.search(r'[^\w\d\s]', password):
                score += 1

            if score <= 2:
                return "Weak"
            elif score <= 4:
                return "Moderate"
            elif score <= 8:
                return "Strong"
            else:
                return "Very Strong"

        def newRand():
            pwEntry.delete(0, END)
            pwLength = myEntry.get()

            if pwLength.isdigit():
                pwLength = int(pwLength)
                
                if pwLength > 45:
                    pwLength = 45
                    
                myPass = ""

                for x in range(pwLength):
                    myPass += chr(randint(33, 126))

                pwEntry.insert(0, myPass)

                # ----Display the password strength----
                strength = calculate_strength(myPass)
                strength_label.config(text="Strength: " + strength)

            else:
                pwEntry.insert(0, "Invalid input")
                strength_label.config(text="Strength: ")

        def clipper():
            window.clipboard_clear()
            window.clipboard_append(pwEntry.get())

        def on_close():
            global password_window_opened
            password_window_opened = False
            window.destroy()      
            
        window.protocol("WM_DELETE_WINDOW", on_close)
        
        # ----Label creation----
        lf = LabelFrame(window, text="How many characters?")
        lf.pack(pady=20)

        # ----Entry Box for number of characters---
        myEntry = Entry(lf, font=("Helvetica", 12))
        myEntry.pack(pady=20, padx=20)

        # ---Entry box for generated password----
        pwEntry = Entry(window, text="", font=("Helvetica", 12), bd=0)
        pwEntry.pack(pady=20)

        # ---Create password strength label---
        strength_label = Label(window, text="Strength: ")
        strength_label.pack(pady=5)

        myFrame = Frame(window)
        myFrame.pack(pady=20)

        myButton = Button(myFrame, text="Generate Password", command=newRand)
        myButton.grid(row=0, column=0, padx=10)

        clipBtn = Button(myFrame, text="Copy to Clipboard", command=clipper)
        clipBtn.grid(row=0, column=1, padx=10)
        
        window.mainloop()

def generate_password_button_clicked():
    passGenerator()

