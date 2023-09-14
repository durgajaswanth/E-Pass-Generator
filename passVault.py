import hashlib
import sqlite3
from tkinter import *
from tkinter import ttk
from tkinter import simpledialog
from tkinter import messagebox
from functools import partial
from passgen import generate_password_button_clicked

global cursor
    
# --------Create Database----------
def create_db():
    with sqlite3.connect("DATABASE123.db") as db:
        cursor = db.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS masterpassword(
        id INTEGER PRIMARY KEY,
        password TEXT NOT NULL
        );
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS vault(
        id INTEGER PRIMARY KEY,
        platform TEXT NOT NULL,
        account TEXT NOT NULL,
        password TEXT NOT NULL);
        """)

    return cursor

cursor = create_db()

# ----create PopUp---
def popUp(text):
    answer = simpledialog.askstring("input string", text)

    return answer

# ----Initiate Window----
window = Tk()
window.title("Password Vault")

def hashPassword(password):
    if isinstance(password, str):
        encoded_password = password.encode('utf-8')
    else:
        encoded_password = password
    hash1 = hashlib.md5(encoded_password)
    hash1 = hash1.hexdigest()
    return hash1

# --------Set up master password screen---------
def firstTimeScreen():
    window.minsize(400, 400)

    lbl = Label(window, text="Enter Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window, text="Re-enter Master Password")
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    txt1 = Entry(window, width=20, show="*")
    txt1.pack()

    def savePassword():
        password = txt.get().strip()
        confirm_password = txt1.get().strip()

        if password == '':
            lbl.config(text="Password must not be empty.")
            return

        if password != confirm_password:
            lbl.config(text="Passwords do not match.")
            return

        hashedPassword = hashPassword(password.encode('utf-8'))
        with sqlite3.connect("DATABASE123.db") as db:
            cursor = db.cursor()
            cursor.execute("INSERT OR REPLACE INTO masterpassword(id, password) VALUES(1, ?)", [hashedPassword])
            cursor.execute("COMMIT")
        vaultScreen()

    btn = Button(window, text="Save", command=savePassword)
    btn.pack(pady=5)
    
# ----------Login screen--------------
def loginScreen():
    with sqlite3.connect("DATABASE123.db") as db:
        cursor = db.cursor()
        
        window.geometry("400x200")
        
        lbl = Label(window, text="Enter Master Password")
        lbl.config(anchor=CENTER)
        lbl.pack()

        txt = Entry(window, width=20, show="*")
        txt.pack()
        txt.focus()

        lbl1 = Label(window)
        lbl1.pack()

        def getMasterPassword():
            checkhashedpassword = hashPassword(txt.get())
            cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [checkhashedpassword])

            return cursor.fetchall()

        def checkPassword():
            password = getMasterPassword()

            if password:
                vaultScreen()

            else:
                txt.delete(0, 'end')
                lbl1.config(text="Wrong Password")

        btn = Button(window, text="Submit", command=checkPassword)
        btn.pack(pady=5)

# -----------Vault functionalities----------
def vaultScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.pack_propagate(0)
    window.geometry("")

    def addEntry():
        platform = simpledialog.askstring(title="Platform", prompt="Enter Platform Name")
        account = simpledialog.askstring(title="Account", prompt="Enter Account Name")
        password = simpledialog.askstring(title="Password", prompt="Enter Password")
        
        if not platform or not account or not password:
            messagebox.showerror("Error", "Please enter all fields")
            return

        top = Toplevel(window)
        top.title("Credentials")
        
        top.attributes("-topmost", True)
        
        lbl = Label(top, text="Platform: " + platform)
        lbl.pack()
        lbl = Label(top, text="Account: " + account)
        lbl.pack()
        lbl = Label(top, text="Password: " + password)
        lbl.pack()
    
        insert_fields = """INSERT INTO vault(platform, account, password)
        VALUES(?, ?, ?)"""

        cursor.execute(insert_fields, (platform, account, password))
        cursor.execute("COMMIT")
        vaultScreen()

    def updateEntry(input):
        update = "Type new password"
        password = popUp(update)

        cursor.execute("UPDATE vault SET password = ? WHERE id = ?", (password, input,))
        cursor.execute("COMMIT")
        vaultScreen()

    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        cursor.execute("COMMIT")
        vaultScreen()

    def copyAcc(input):
        window.clipboard_clear()
        window.clipboard_append(input)

    def copyPass(input):
        window.clipboard_clear()
        window.clipboard_append(input)

# ---------Window layout----------
    window.geometry("900x400")
    main_frame = Frame(window)
    main_frame.pack(fill=BOTH, expand=1)

    my_canvas = Canvas(main_frame)
    my_canvas.pack(side=LEFT, fill=BOTH, expand=1)

    my_scrollbar = ttk.Scrollbar(main_frame, orient=VERTICAL, command=my_canvas.yview)
    my_scrollbar.pack(side=RIGHT, fill=Y)

    my_canvas.configure(yscrollcommand=my_scrollbar.set)
    my_canvas.bind('<Configure>', lambda e: my_canvas.configure(scrollregion=my_canvas.bbox("all")))

    second_frame = Frame(my_canvas)

    my_canvas.create_window((0, 0), window=second_frame, anchor="nw")
    
    btn2 = Button(second_frame, text="Generate Password", command=generate_password_button_clicked)
    btn2.grid(column=2, row=1, padx=10,  pady=10)
    
    btn = Button(second_frame, text="Add Credentials", command=addEntry)
    btn.grid(column=3, row=1, padx=10, pady=10)

    lbl = Label(second_frame, text="Platform")
    lbl.grid(row=2, column=0, padx=40)
    lbl = Label(second_frame, text="Account")
    lbl.grid(row=2, column=1, padx=40)
    lbl = Label(second_frame, text="Password")
    lbl.grid(row=2, column=2, padx=40)

    cursor.execute("SELECT * FROM vault")
    credentials = cursor.fetchall()

# ---------Buttons Layout-----------
    cursor.execute("SELECT * FROM vault")
    credentials = cursor.fetchall()
    
    if len(credentials) == 0:
        lbl = Label(second_frame, text="No Credentials found")
        lbl.grid(row=3, column=0, columnspan=5)
    else:
        for i in range(len(credentials)):
            lbl1 = Label(second_frame, text=(credentials[i][1]))
            lbl1.grid(column=0, row=i + 3)
            lbl2 = Label(second_frame, text=(credentials[i][2]))
            lbl2.grid(column=1, row=i + 3)
            lbl3 = Label(second_frame, text=(credentials[i][3]))
            lbl3.grid(column=2, row=i + 3)
            btn2 = Button(second_frame, text="Copy Acc", command=partial(copyAcc, credentials[i][2]))
            btn2.grid(column=3, row=i + 3, pady=10)
            btn3 = Button(second_frame, text="Copy Pass", command=partial(copyPass, credentials[i][3]))
            btn3.grid(column=4, row=i + 3, pady=10)
            btn1 = Button(second_frame, text="Update", command=partial(updateEntry, credentials[i][0]))
            btn1.grid(column=5, row=i + 3, pady=10)
            btn = Button(second_frame, text="Delete", command=partial(removeEntry, credentials[i][0]))
            btn.grid(column=6, row=i + 3, pady=10)       
            
cursor.execute("SELECT * FROM masterpassword LIMIT 1")
if cursor.fetchall():
    loginScreen()
else:
    firstTimeScreen()
    
    window.mainloop()
