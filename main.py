from tkinter import *
from tkinter import messagebox
from PIL import ImageTk, Image
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_and_encrypt():
    title=entry1.get()
    message=text1.get('1.0',END)
    master_secret=entry2.get()
    if len(title)==0 or len(message)==0 or len(master_secret)==0:
        messagebox.showinfo(title='Error!',message='Please enter all info')
    else:
        #encryption
        message_encrypted=encode(master_secret,message)
        try:
            with open('secret.txt','a') as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        except FileNotFoundError:
            with open('secret.txt','w') as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        finally:
            entry1.delete(0,END)
            text1.delete(1.0,END)
            entry2.delete(0,END)

def decrypt_notes():
    message_encrypted=text1.get(1.0,END)
    master_secret=entry2.get()

    if len(message_encrypted)==0 or len(master_secret)==0:
        messagebox.showinfo(title='Error!', message='Please enter all info')
    else:
        try:
            decrypted_message=decode(master_secret,message_encrypted)
            text1.delete(1.0,END)
            text1.insert(1.0,decrypted_message)
        except:
            messagebox.showinfo(title='Error!',message='Please enter encrypted text')


window=Tk()
window.title('Secret Notes UI')
window.minsize(height=700,width=500)
window.config(padx=10,pady=10)

#image
image=ImageTk.PhotoImage(Image.open('top secret (1).png'))

#imagelabel

imagelabel=Label(image=image).pack()

#label1
label1=Label(text='Enter Your Title')
label1.config(padx=3,pady=3)
label1.pack()

#entry1
entry1=Entry()
entry1.pack()

#label2
label2=Label(text='Enter Your Secret')
label2.config(padx=3,pady=3)
label2.pack()

#text1
text1=Text(height=20,width=40)
text1.pack()

#label3
label3=Label(text='Enter Your Master Key')
label3.config(padx=3,pady=3)
label3.pack()

#entry2
entry2=Entry()
entry2.pack()


#button1
button1=Button(text='Save&Encrypt',command=save_and_encrypt)
button1.pack()

#button2
button2=Button(text='Decrypt',command=decrypt_notes)
button2.pack()



window.mainloop()


