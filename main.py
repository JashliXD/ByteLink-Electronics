from tkinter import *
from tkinter import ttk
from tkinter import filedialog
import socket
import threading
import ast
import json
import os
import base64
import pickle

# my modules
import datahandlers as dh
import utils

#important modules
from PIL import Image, ImageTk
from io import BytesIO

root = Tk()
class App:
    def __init__(self, master):
        self.master = master
        self.master.geometry("800x600")
        self.master.config(bg="#353BA7")
        self.master.title("ByteLink Electronics")
        self.master.grid_columnconfigure(0, weight=1)
        #self.master.grid_rowconfigure(0, weight=1)
        #self.master.resizable(False, False)
        icon = Image.open("images/icon/icon.png")
        icon.thumbnail((25,25), Image.Resampling.LANCZOS)
        self.icon_tk = ImageTk.PhotoImage(icon)
        self.master.iconphoto(False, self.icon_tk)
        self.connectorpage()
    
    def destroy(self):
        for i in self.master.winfo_children():
            i.destroy()

    def login_function(self, username, password, err):
        if username == "":
            err.config(text="Please enter a username")
            return
        elif len(username) < 3:
            err.config(text="Username must be at least 3 characters")
            return
        
        elif password == "":
            err.config(text="Please enter a password")
            return
        elif username == "" and password == "":
            err.config(text="Please enter a username and password")
            return
        elif len(password) < 8:
            err.config(text="Password must be at least 8 characters")
            return

        #self.user = dh.login(username, password)

        #if self.user == None:
        #    err.config(text=f"{username} is not found.")
        #    return

        message = f"@login|{username}|{password}".encode("utf-8")
        self.client.send(message)
        reply = self.client.recv(1024)
        reply = reply.decode("utf-8")
        if reply == "UNKNOWN_USER":
            err.config(text="User not found")
            return
        elif reply == "PASSWORD_INVALID":
            err.config(text="Password Incorrect.")
            return
        if self.remember_me.get():
            with open("creds.cookies", 'w+') as file:
                cookie_user = base64.b64encode(username.encode("utf-8"))
                cookie_pass = base64.b64encode(password.encode("utf-8"))
                data = {"user": str(cookie_user)[2:], "pass": str(cookie_pass)[2:]}
                json.dump(data, file)
        self.user = ast.literal_eval(reply)
        self.store_page()

    def register_function(self, email ,username, password, err):
        # Error handlings
        if email == "":
            err.config(text="Please enter valid email address")

        elif username == "":
            err.config(text="Please enter a username")
            return
        elif len(username) < 3:
            err.config(text="Username must be at least 3 characters")
            return
        
        elif password == "":
            err.config(text="Please enter a password")
            return
        elif username == "" and password == "":
            err.config(text="Please enter a username and password")
            return
        elif len(password) < 8:
            err.config(text="Password must be at least 8 characters")
            return
        

        message = f"@register|{email}|{username}|{password}".encode("utf-8")
        self.client.send(message)
        res = self.client.recv(1024)
        if res == '404':
            err.config(text="Something went wrong. Please try again.")
            return

        # redirect to login page
        self.loginpage()

    def connector_function(self, ip_address, port):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
     
        try:
            self.client.connect((ip_address, int(port)))
            self.client.settimeout(0.1)
            print("Connection established")
            self.loginpage()
        except Exception as e:
            print(f"Error Connecting : {e}")

    def host_function(self):
        self.server = threading.Thread(target=dh.server)
        self.server.start()

        self.connector_function(socket.gethostbyname(socket.gethostname()), 8888)

    def logout_function(self):
        self.user = None

        self.loginpage()
    
    def remember_me_cookies(self):
        file = 'creds.cookies'
        if os.path.isfile(file):
            with open(file) as f:
                data = json.load(f)
                user = base64.b64decode(data.get('user')).decode('utf-8')
                password = base64.b64decode(data.get('pass')).decode('utf-8')
                self.users.insert(0, user)
                self.password.insert(0, password)

    def store_create_file_image(self):  
        self.image_directory = filedialog.askopenfilename(filetypes=[("Image Files", "*.png")])

        if self.image_directory:
            store_image = Image.open(self.image_directory)
            store_image.thumbnail((100,100), Image.Resampling.LANCZOS)
            store_img = ImageTk.PhotoImage(store_image)
            
            self.image_button.config(image = store_img, compound=TOP)
            self.image_button.image = store_img

    def create_store(self):
        image_button = self.image_button.image
        store_name = self.store_name_entry.get()
        store_location = self.store_location_entry.get("1.0", "end-1c")
        if image_button and store_name and store_location:
            self.client.send(f"@create_server|{store_name}|{self.image_directory}|{store_location}|{self.user[3]}".encode("utf-8"))
            reply = self.client.recv(4096).decode('utf-8')
            if reply == 'Goods':
                self.store_page()

    def all_stores(self):
        self.client.send("@get_all_store".encode('utf-8'))
        data=b''
        chunk = 4096
        while True:
            try:
                data_chunks = self.client.recv(chunk)
                if not data_chunks:
                    break
                data += data_chunks
            except socket.timeout:
                break
        return data

    def show_items(self, item):
        self.destroy()

        def update(ent,var, increment=1):
            val = int(ent.get())
            var.set(val)
            new =var.get() + increment
            if new >= 1:
                var.set(new)
        
        def val_int(inp):
            if inp == "":
                return True
            try:
                int(inp)
                return True
            except:
                return False

        self.main = Frame(self.master)
        self.main.grid()
        # upper frame
        self.header = Frame(self.master, width=800,height=50)
        self.header.config(bg='#353BA7')
        
        self.header.grid_propagate(0)
        self.header.grid_columnconfigure(0, weight=1)
        home = Button(self.header,command=self.store_page,image=self.icon_tk, text="Store",bg="#698ae8",fg="#f8f9fe", borderwidth=0,width=12,height=3, font=('Arial 11 bold'), compound=LEFT)
        home.image=self.icon_tk
        logout = Button(self.header,command=self.logout_function, text="Logout",bg="#698ae8",fg="#f8f9fe", borderwidth=0,width=9,height=3, font=('Arial 11 bold'))
        manage_store = Button(self.header,command=self.manage_store_page, text="Manage Store",bg="#698ae8",fg="#f8f9fe", borderwidth=0,width=12,height=3, font=('Arial 11 bold'))
        logout.grid(sticky=E,row=0,column=2)
        self.header.grid()
        self.header.update_idletasks()
        home.config(width=logout.winfo_width(), height=logout.winfo_height())
        home.grid(sticky=W,row=0,column=0)
        manage_store.grid(sticky=E,row=0,column=1,padx=1)
        
        self.header.config(height=logout.winfo_height())
        
        # bottom frame
        self.item_frame = Frame(self.master, width=800,height=550)
        self.item_frame.config(bg='#F8F9FE')
        self.item_frame.grid()
        self.item_frame.grid_propagate(0)

        
        # DONT TOUCH
        frame_canvas = Frame(self.item_frame,width=800,background="#f8f9fe")
        frame_canvas.grid(row=0,column=0,sticky='nw')
        frame_canvas.grid_rowconfigure(0,weight=1)
        frame_canvas.grid_columnconfigure(0,weight=1)
        frame_canvas.grid_propagate(0)
        canvas = Canvas(frame_canvas, bg='#F8F9FE',width=800,height=550)
        canvas.grid(row=0,column=0,sticky='news')
        scrollbar = ttk.Scrollbar(frame_canvas,orient='vertical',command=canvas.yview)
        scrollbar.grid(row=0,column=1, sticky='ns')
        canvas.bind("<Configure>", lambda x: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.configure(yscrollcommand=scrollbar.set)
        frame = Frame(canvas,bg='#F8F9FE')
        canvas.create_window((0,0), window=frame,anchor='nw')
        
        #data
        image_blob, item_name, item_description, item_price, item_stock, item_id, store_id = item
        img = Image.open(BytesIO(image_blob))
        img_tk = ImageTk.PhotoImage(img)
        # item header - literally everything
        self.item_header = Frame(frame, width=800, bg='#2d4286')
        self.item_header.grid()
        self.item_header.grid_rowconfigure(0, weight=1)
        self.item_header.grid_propagate(0)

        self.item_image = Label(self.item_header, image=img_tk, bg='#2d4286')
        self.item_image.image = img_tk
        self.item_label = Label(self.item_header, text=item_name, font=(f"Arial {img.size[1]//5} bold"),fg="#f8f9fe", bg='#2d4286')

        self.item_image.grid(row=0, column=0,pady=10,padx=5)
        self.item_label.grid(row=0, column=1)
        
        self.frame = Frame(self.item_header, bg='#2d4286')
        self.frame.grid(row=1,column=1)

        quantity_var = IntVar()
        quantity_var.set(1)
        valid = self.master.register(val_int)
        label1 = Label(self.frame, text="Price:", font=(f"Arial {img.size[1]//10} bold"),fg="#f8f9fe", bg='#2d4286')
        label2 = Label(self.frame, text="Quantity:", font=(f"Arial {img.size[1]//10} bold"),fg="#f8f9fe", bg='#2d4286')

        self.quantity_ent = Entry(self.frame,width=5,validate='key', bg='#2d4286',validatecommand=(valid, "%P"),fg="#f8f9fe", textvariable=quantity_var, font=(f"Arial {img.size[1]//13} bold"))
        button_minus = Button(self.frame, text='-',fg="#f8f9fe",borderwidth=0,bg="#353ba7", font=(f"Arial {img.size[1]//15} bold"),command=lambda quantity_var=quantity_var: update(self.quantity_ent,quantity_var, -1))
        button_plus = Button(self.frame, text='+',fg="#f8f9fe",borderwidth=0,bg="#353ba7", font=(f"Arial {img.size[1]//15} bold"),command=lambda quantity_var=quantity_var: update(self.quantity_ent,quantity_var))
        self.item_price = Label(self.frame, text="₱"+str(item_price), bg='#2d4286', font=(f"Arial {img.size[1]//10} bold"),fg="#f8f9fe")
        self.item_stock = Label(self.frame, bg='#2d4286', text=str(item_stock) + " in stock", font=(f"Arial {img.size[1]//10} bold"),fg="#f8f9fe")

        self.buy_now = Button(self.frame, text='Buy Now!',fg="#f8f9fe",bg="#353ba7", font=(f"Arial {img.size[1]//10} bold"),borderwidth=0)

        label1.grid(row=0, column=0)
        self.item_price.grid(row=0, column=1,columnspan=4)
        
        label2.grid(row=1, column=0)
        button_minus.grid(row=1, column=1)
        self.quantity_ent.grid(row=1, column=2)
        button_plus.grid(row=1, column=3)
        self.item_stock.grid(row=1, column=4,padx=20)
        self.buy_now.grid(row=2, column=4)
        self.item_header.update_idletasks()
        
        fsize = self.frame.winfo_height() + img.size[1]
        self.item_header.config(height=fsize)
        # description frame
        self.des_frame = Frame(frame, width=800, bg="#F8F9FE")
        self.des_frame.grid(row=1,column=0,pady=10)
        self.des_frame.grid_propagate(0)
        self.des_head = Label(self.des_frame, text="Description", fg="#2d4286", bg="#F8F9FE",font=("Arial 30 bold"))
        self.des_text = Label(self.des_frame, text=item_description, fg="#698ae8", bg="#F8F9FE",font=("Arial 14"))
        self.des_head.grid()
        self.des_text.grid(pady=10)
        self.des_frame.update_idletasks()
        h_info = self.des_head.winfo_height() * 2 + self.des_text.winfo_height()
        self.des_frame.config(height=h_info, width=800-scrollbar.winfo_width())
        
        # DONT TOUCHC
        frame.update_idletasks()
        frame_canvas.config(height=550)

    def connectorpage(self):
        self.master.geometry("400x500")
        self.destroy()
        # HEADER
        self.header = Frame(self.master, height=140, width=500,bg="#353BA7")
        self.header.pack(pady=20)
        self.header.pack_propagate(0)

        image = Image.open('images/icon/icon.png')
        image.thumbnail((75,75), Image.Resampling.LANCZOS)
        self.header_img = ImageTk.PhotoImage(image)

        self.header_lb = Label(self.header, image=self.header_img,bg="#353BA7")
        self.header_lb.image = self.header_img
        
        self.header_lb.pack()
        self.head = Label(self.header, text="Server Connector", font=("Arial 30 bold"),bg="#353BA7",fg='#f8f9fe').pack(pady=10)
        self.CStyle = ttk.Style()

        self.CStyle.configure("CStyle.TButton", background="#2D4286", font=("Arial 14 bold"),foreground='#698AE8')
        self.CStyle.configure("CStyle.TFrame", background="#2D4286", borderwidth=4)

        # CONNECTOR
        self.frame0 = ttk.Frame(self.master,width=300,height=280, style="CStyle.TFrame")
        
        self.frame0.pack(pady=10)
        self.frame0.pack_propagate(0)
        self.ip_lb = Label(self.frame0, font=("Arial 18 bold"), text="Server IP Address",bg="#2D4286",fg="#f8f9fe")
        self.ip_entry = ttk.Entry(self.frame0, font=("Arial 18"))
        self.port_lb = Label(self.frame0, font=("Arial 18 bold"), text="Port",bg="#2D4286",fg="#f8f9fe")
        self.port_entry = ttk.Entry(self.frame0, width=9,font=("Arial 18 bold"))
        self.connect_btn = ttk.Button(self.frame0, text="Connect",style="CStyle.TButton", command=lambda: self.connector_function(self.ip_entry.get(), self.port_entry.get()))
        self.host_btn = ttk.Button(self.frame0, text="Host",style="CStyle.TButton", command=self.host_function)

        self.ip_lb.pack(anchor='w',padx=5,pady=3)
        self.ip_entry.pack(anchor='w',padx=5,pady=3)
        self.port_lb.pack(anchor='w',padx=5,pady=3)
        self.port_entry.pack(anchor='w',padx=5,pady=3)
        self.connect_btn.pack(anchor='w',padx=5,pady=9)
        self.host_btn.pack(anchor='w',padx=5,pady=3,side="bottom")

    def loginpage(self):
        self.master.geometry("800x600")
        self.destroy()
        # Style

        self.LStyle = ttk.Style()
        self.LStyle.configure("LStyle.TLabel", font=("Arial 18 bold"), foreground="#F8F9FE",background="#2D4286")
        self.LStyle.configure("LStyle.TButton", background="#2D4286", font=("Arial 14 bold"),foreground='#698AE8')
        #self.LStyle.configure("LStyle.TLabel", font=("Arial"))
        self.LStyle.configure("LStyle.TFrame", background="#2D4286", borderwidth=4)

        self.LStyle.configure("LStyle-Register.TLabel", font=("Arial 11 bold"), foreground="#F8F9FE", background="#2D4286")
        self.LStyle.configure("LStyle-Error.TLabel", font=("Arial 13 bold"), foreground="red", background="#2D4286")

        self.LStyle.configure("LStyle-Header.TLabel", background="#353BA7", font=("Arial 30 bold"), foreground="#F8F9FE")
        #Header
        img = Image.open('images/icon/icon.png').resize((75,75))
        self.img_tk = ImageTk.PhotoImage(img)

        self.label_img = ttk.Label(self.master, image=self.img_tk, style="LStyle-Header.TLabel")
        self.label_img.image = self.img_tk

        self.label_img.grid(row=0,pady=10)

        self.label = ttk.Label(self.master, text="Login to", style="LStyle-Header.TLabel")
        self.labelb = ttk.Label(self.master, text="ByteLink Electronics", style="LStyle-Header.TLabel")
        self.label.grid(row=1, column=0)
        self.labelb.grid(row=2, column=0)
        
        self.frame0 = ttk.Frame(self.master, width=500, height=300, style="LStyle.TFrame")
        # Center the self.frame0
        self.frame0.grid(row=3,column=0,pady=30)
        self.frame0.grid_columnconfigure(0, weight=1)
        self.frame0.grid_columnconfigure(2, weight=1)
        #self.frame0.grid_rowconfigure(0, weight=1)
        #self.frame0.grid_rowconfigure(2, weight=1)
        self.frame0.grid_propagate(0)
        self.remember_me = BooleanVar()
        # Code ----
        self.label1 = ttk.Label(self.frame0,style="LStyle.TLabel", text="Username: ")
        self.label2 = ttk.Label(self.frame0,style="LStyle.TLabel", text="Password: ")
        self.users = ttk.Entry(self.frame0, font="Arial 18")
        self.password = ttk.Entry(self.frame0, show="*", font="Arial 18")
        self.error = ttk.Label(self.frame0, style="LStyle-Error.TLabel")
        self.login_btn = ttk.Button(self.frame0, text="Login",style="LStyle.TButton" , command=lambda: self.login_function(self.users.get(), self.password.get(), self.error))
        self.remember = ttk.Checkbutton(self.frame0, text="Remember Me!", variable=self.remember_me)
        self.label3 = ttk.Label(self.frame0, text="Not yet registered?", style="LStyle-Register.TLabel")
        self.register_btn = ttk.Button(self.frame0, text="Register", command=self.registerpage, style="LStyle.TButton")

        self.label1.grid(row=1, column=1,pady=20)
        self.label2.grid(row=2, column=1,pady=10)
        self.users.grid(row=1, column=2)
        self.password.grid(row=2, column=2)
        self.remember_me_cookies()
        self.remember.grid(row=3, column=2,pady=3)
        self.login_btn.grid(row=4,column=2)
        
        self.error.grid(row=5,column=2)
        
        self.label3.grid(row=6, column=1)
        self.register_btn.grid(row=6, column=2, pady=10)
    
    def registerpage(self):
        self.destroy()

        self.frame1 = Frame(self.master, width=400, height=400)
        self.frame1.pack()

        self.label0 = Label(self.frame1, text="Register")

        self.mail = Label(self.frame1, text="Email: ")
        self.username = Label(self.frame1, text="Username: ")
        self.password = Label(self.frame1, text="Password: ")
        self.error = Label(self.frame1, fg="red")

        self.register_btn = Button(self.frame1, text="Register", command=lambda: self.register_function(self.email.get(), self.user.get(), self.passcode.get(), self.error))

        self.label1 = Label(self.frame1, text="Already Have Account?")
        self.login_btn = Button(self.frame1, text="Login Page", command=self.loginpage)

        self.email = Entry(self.frame1)
        self.user = Entry(self.frame1)
        self.passcode = Entry(self.frame1, show="*")
        
        self.label0.grid()
        
        self.mail.grid(row=1, column=1)
        self.username.grid(row=2, column=1)
        self.password.grid(row=3, column=1)
        
        self.email.grid(row=1, column=2)
        self.user.grid(row=2, column=2)
        self.passcode.grid(row=3, column=2)

        self.register_btn.grid(row=4,column=2, pady=10)
        self.error.grid(row=5, column=2)
        self.label1.grid(row=6, column=1)
        self.login_btn.grid(row=6, column=2)

    def selection_page(self, user):
        self.destroy()
        self.frame2 = Frame(self.master, width=400, height=400)
        self.frame2.pack()
        #print(user)
        self.welcome = Label(self.frame2, text=f"Welcome {user[0]}", font=("Calibri 30"))

        self.images = Image.open('images/1413908.png').resize((100,100))
        self.tk_img = ImageTk.PhotoImage(self.images)
        #self.store_btn = Button(self.frame2, image=tk_img[0], borderwidth=0,bg='red')
        self.shop_btn = Button(self.frame2, image=self.tk_img,text="hello", borderwidth=0,bg='green')
        self.shop_btn.image = self.tk_img

        

        self.welcome.grid(row=1, column=1)
        #self.store_btn.grid(row=2, column=1)
        self.shop_btn.grid(row=3, column=2)

    def store_page(self):
        self.destroy()
        
        def get_products(store_id):
            self.client.send(f"@get_products|{store_id}".encode("utf-8"))  
            data=b''
            chunk = 32768
            while True:
                try:
                    raw_data = self.client.recv(chunk)
                    #print(raw_data)
                    if not raw_data:
                        break
                    data += raw_data
                except:
                    break
            return pickle.loads(data)
        
        self.header = Frame(self.master,bg='#353BA7')
        self.header.pack(fill=BOTH)

        self.redirect = Button(self.header,image=self.icon_tk,font=("Arial 11 bold"), text="Store",width=9,height=3,borderwidth=0,bg="#698ae8",fg="#f8f9fe", command=self.store_page, compound=LEFT)
        self.redirect.image = self.icon_tk
        self.logout = Button(self.header,font=("Arial 11 bold"), text="Logout",width=9,height=3,borderwidth=0,bg="#698ae8",fg="#f8f9fe", command=self.logout_function)
        self.redirect.pack(side=LEFT)
        self.logout.pack(side=RIGHT)
        self.client.send(f'@has_store|{self.user[3]}'.encode('utf-8'))
        if pickle.loads(self.client.recv(1024)) == False:
            self.store = Button(self.header,font=("Arial 11 bold"), text="Create Store",width=12,height=3,bg="#698ae8",fg="#f8f9fe", borderwidth=0,command=self.store_create_page).pack(side=RIGHT,padx=1)
        else:
            self.store = Button(self.header,font=("Arial 11 bold"), text="Manage Store", width=12, height=3,bg="#698ae8",fg="#f8f9fe",borderwidth=0, command=self.manage_store_page).pack(side=RIGHT,padx=1)
        
        self.header.update_idletasks()
        self.redirect.config(width=self.logout.winfo_width(), height=self.logout.winfo_height())
        # Good luck reading this
        self.frame0 = Frame(self.master)
        self.frame0.pack(fill=BOTH, expand=1)
        self.canvas = Canvas(self.frame0)
        self.scrollbar = Scrollbar(self.frame0, orient=VERTICAL, command=self.canvas.yview)
        self.scrollbar.pack(side=RIGHT, fill=Y)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.bind("<Configure>", lambda x: self.canvas.configure(scrollregion= self.canvas.bbox('all')))
        self.canvas.pack(fill=BOTH, side=LEFT)
        self.main_frame = Frame(self.frame0)
        self.canvas.create_window((0,0), window=self.main_frame , anchor='nw')
        # Main
        # Loopy
        all_store = self.all_stores()

        all_store = pickle.loads(all_store)
        for store in all_store:
            _store_id, store_name, store_image, store_location, _user_id = store
            
            store_frame = Frame(self.main_frame)
            store_frame.grid(pady=40)

            head_frame = Frame(store_frame, background="#353BA7",width=750,height=100)
            head_frame.grid(row=0,column=0)
            head_frame.grid_propagate(0)
            head_frame.grid_rowconfigure(0, weight=1)
            head_frame.grid_columnconfigure(1, weight=1)

            img = Image.open(BytesIO(store_image))
            store_tk = ImageTk.PhotoImage(img)

            label = Label(head_frame, image=store_tk, fg="#f8f9fe",bg="#353BA7")
            label.image = store_tk

            label2 = Label(head_frame, text=store_name, font=("Arial 30 bold"), fg="#f8f9fe",bg="#353BA7")
            label3 = Label(head_frame, font=("Arial 15 bold"), fg="#f8f9fe",bg="#353BA7")

            label.grid(row=0,padx=10,pady=5,sticky=W)
            label2.grid(row=0, column=1,sticky=W)
            label3.grid(row=0, column=2,sticky=E)
            item_frame = Frame(store_frame, background="#698AE8",width=750)
            item_frame.grid(row=1,column=0)
            item_frame.grid_propagate(0)
            items_raw = get_products(_store_id)
            label3.config(text=str(len(items_raw))+" items")
            items = utils.reshape(items_raw, 5)
            # buttons...
            width,height = 110,130
            pady = 5
            for x,shape in enumerate(items):
                for y, item in enumerate(shape):
                    image = Image.open(BytesIO(item[0]))
                    image.thumbnail((100,100), Image.LANCZOS)
                    img_tk = ImageTk.PhotoImage(image)
                    btn = Button(item_frame, text=utils.trimmer(item[1],9), command=lambda x=item: self.show_items(x), image=img_tk,width=width,height=height,compound=TOP, anchor='s')
                    btn.image = img_tk
                    btn.grid(row=x,column=y,padx=10,pady=pady)
            height_calculation = (height + 2 * pady) * len(items) + (2 * (pady) * len(items))
            item_frame.config(height=height_calculation)

    def store_create_page(self):
        self.destroy()
        self.label_store_img = None
        # Stylish
        self.create_style = ttk.Style()

        self.create_style.configure("Header.TLabel", font=("Arial 30 bold"), foreground="#F8F9FE",background="#353BA7")
        self.create_style.configure("Create_Style.TFrame", background="#2D4286", borderwidth=4)
        self.create_style.configure("Create_Style.TLabel", font=("Arial 18 bold"), foreground="#F8F9FE",background="#2D4286")

        self.image = Image.open('images/icon/2.png').resize((75,75))

        self.image = ImageTk.PhotoImage(self.image)
        self.header_img = ttk.Label(self.master, image=self.image, style="Header.TLabel")
        self.header_img.image = self.image
        self.header = ttk.Label(self.master, text='Create Store', style="Header.TLabel")
        self.header_img.grid(pady=10)
        self.header.grid(pady=10)

        self.main_frame = ttk.Frame(self.master, style="Create_Style.TFrame", width=460, height=350)
        self.main_frame.grid(pady=20)
        self.main_frame.grid_propagate(0)
        
        # Store Image
        # Store name
        # Store Location

        # Labels
        self.label0 = ttk.Label(self.main_frame, text="Store Image",style="Create_Style.TLabel")
        self.label1 = ttk.Label(self.main_frame, text="Store Name",style="Create_Style.TLabel")
        self.label2 = ttk.Label(self.main_frame, text="Store Location",style="Create_Style.TLabel")

        self.label0.grid(row=0,pady=10,padx=10)
        self.label1.grid(row=1,pady=5,padx=10)
        self.label2.grid(row=2,pady=5,padx=10)
        # Entries
        self.image_button = ttk.Button(self.main_frame, text="Select Image...",command=self.store_create_file_image)
        self.image_button.image = None
        self.image_button.grid(row=0, column=1,pady=5)
        self.store_name_entry = ttk.Entry(self.main_frame, font=("Arial 18 bold"),width=15)
        self.store_name_entry.grid(row=1, column=1,pady=5,padx=50)
        self.store_location_entry = Text(self.main_frame, height=5, width=25)
        self.store_location_entry.grid(row=2,column=1,pady=5)
        
        self.back_btn = ttk.Button(self.main_frame, text="Back", command=self.store_page)
        self.create_store_btn = ttk.Button(self.main_frame, text="Create Store", command=self.create_store)

        self.back_btn.grid(row=3)
        self.create_store_btn.grid(row=3,column=1,pady=30)

    def manage_store_page(self):
        self.destroy()
        self.manage_style = ttk.Style()
        self.manage_style.configure("HEADER.TFrame", background="#698ae8")
        self.manage_style.configure("BUTTON.TFrame", background="#353BA7")
        self.manage_style.configure("MAIN.TFrame", background="white")
        #variable outer variables
        self.img_dir = None
        self.selected_page = None
        def destroy():
            for i in self.main_frame.winfo_children():
                i.destroy()
            
        def get_store():
            self.client.send(f"@get_store|{self.user[3]}".encode("utf-8"))
            data=b''
            chunk = 4096
            while True:
                try:
                    raw_data = self.client.recv(chunk)
                    if not raw_data:
                        break
                    data += raw_data
                except:
                    break
            
            return pickle.loads(data)
        
        def change_photo(btn):
            self.img_dir = None
            self.img_dir = filedialog.askopenfilename(filetypes=[("Image Files", "*.png")])

            if self.img_dir:
                img = Image.open(self.img_dir)
                img.thumbnail((100,100), Image.Resampling.LANCZOS)

                image = ImageTk.PhotoImage(img)
                btn.config(image=image,compound=TOP)
                btn.image = image

        def update_store(image, name, location):
            if not image:
                image=''
            self.client.send(f"@update_store|{name}|{image}|{location}|{self.user[3]}".encode('utf-8'))

            reciever = self.client.recv(1024)
            if reciever:
                self.store_page()

        def button_handler(btn, cmd):
            if cmd == self.selected_page:
                return
            self.selected_page = None
            self.img_dir = None
            buttons = [child for child in self.button_frame.winfo_children() if isinstance(child, Button)]
            for button in buttons:
                button.config(bg='#2D4286',fg="#F8F9FE")
            btn.config(bg='#F8F9FE',fg="#2D4286")
            if cmd == 'store_info':
                self.selected_page = 'store_info'
                store_info_frame()
            if cmd == 'add_products':
                self.selected_page = 'add_products'
                add_products_frame()
            if cmd == 'my_products':
                self.selected_page = 'my_products'
                my_products_frame()

        def add_product_function(img_dir=None, product_name=None, product_description=None, price=None, stock=None, error=None):
            img = img_dir.image
            item_name = product_name.get()
            description = product_description.get("1.0", "end-1c")
            item_price = price.get()
            item_stocks = stock.get()
            id_ = self.store[0]
            if not img or not item_name or not description or not item_price or not item_stocks:
                error.config(text="Please fill the form")
                return
            img = self.img_dir
            self.client.send(f"@add_product|{id_}|{img}|{item_name}|{description}|{item_price}|{item_stocks}".encode("utf-8"))
            reply = self.client.recv(1024).decode("utf-8")
            if reply == 'Success':
                self.img_dir = None
                self.products = get_products_function()
                add_products_frame()
            else:
                self.manage_store_page()
        
        def get_products_function():
            print(self.store[0])
            self.client.send(f"@get_products|{self.store[0]}".encode("utf-8"))  
            data=b''
            chunk = 32768
            while True:
                try:
                    raw_data = self.client.recv(chunk)
                    #print(raw_data)
                    if not raw_data:
                        break
                    data += raw_data
                except:
                    break
            return pickle.loads(data)

        def validation_input(val):
            if val == "":
                return True
            try:
                int(val)
                return True
            except ValueError:
                try:
                    float(val)
                    return True
                except ValueError:
                    return False

        def key_input(val):
            if len(val) > 22:
                return False
            return True
            
        def delist_function(item_id):
            self.client.send(f"@delist|{item_id}".encode("utf-8"))
            res = self.client.recv(1024).decode('utf-8')
            if res == 'Success':
                self.products = get_products_function()
                my_products_frame()
        
        def update_item(item_name=None, item_description=None, price_=None, stock_=None, item_id=None, error=None):
            img = self.img_dir
            name = item_name.get()
            description = item_description.get("1.0", "end-1c")
            price = price_.get()
            stock = stock_.get()

            if not img or not name or not description or not price or not stock or not item_id:
                error.config(text="Please fill the form")
                return

            self.client.send(f'@update_item|{img}|{name}|{description}|{price}|{stock}|{item_id}'.encode('utf-8'))
            reply = self.client.recv(1024).decode('utf-8')
            if reply == 'Success':
                self.products = get_products_function()
                my_products_frame()
                return
            print(reply)

        def item_frame(item):
            destroy()
            style = ttk.Style()
            style.configure("Header.TLabel", font=("Arial 20 bold"), foreground="#2d4286", background="#f8f9fe")
            style.configure("Header2.TLabel", foreground="#2d4286", background="#f8f9fe")
            style.configure("Name.TLabel", font=("Arial 16 bold"), foreground="#2d4286", background="#f8f9fe")
            style.configure("Description.TLabel", font=("Arial 12 bold"), foreground="#2d4286", background="#f8f9fe")
            style.configure("Name.TEntry", foreground="#2d4286", background="#f8f9fe")
            style.configure("Selector.TButton", font=("Arial 12 bold"), foreground="#2d4286", background="#f8f9fe")
            style.configure("MainFrame.TFrame", background="#f8f9fe")
            
            # DONT TOUCH
            frame_canvas = Frame(self.main_frame,width=600,background="#f8f9fe")
            frame_canvas.grid(row=0,column=0,sticky='nw')
            frame_canvas.grid_rowconfigure(0,weight=1)
            frame_canvas.grid_columnconfigure(0,weight=1)
            frame_canvas.grid_propagate(0)
            canvas = Canvas(frame_canvas, bg='#F8F9FE',width=580,height=550)
            canvas.grid(row=0,column=0,sticky='news')
            scrollbar = ttk.Scrollbar(frame_canvas,orient='vertical',command=canvas.yview)
            scrollbar.grid(row=0,column=1, sticky='ns')
            canvas.bind("<Configure>", lambda x: canvas.configure(scrollregion=canvas.bbox("all")))
            canvas.configure(yscrollcommand=scrollbar.set)
            frame = Frame(canvas,bg='#F8F9FE')
            canvas.create_window((0,0), window=frame,anchor='nw')
            # Rest of code here ----
            
            # Frame
            #frame.grid_columnconfigure(0, weight=1)
            #frame.grid_propagate(0)
            # End Frame

            # Data
            image_byte = item[0]
            item_name = item[1]
            item_description = item[2]
            item_price = item[3]
            item_stock = item[4]

            item_id = item[5]
            # Processing Image
            picture = Image.open(BytesIO(image_byte))
            size = picture.size[0] / 2, picture.size[1] / 2
            picture.thumbnail(size, Image.Resampling.LANCZOS)
            image = ImageTk.PhotoImage(picture)
            # header
            header_frame = Frame(frame, width=600, height=150, background="#e1e7f6")
            header_frame.grid(row=0,column=0,columnspan=3)
            header_frame.grid_columnconfigure(1, weight=1)
            header_frame.grid_rowconfigure(0, weight=1)
            header_frame.grid_propagate(0)
            header = ttk.Label(header_frame, text=item_name, style="Header.TLabel", wraplength=300)
            header_img = ttk.Label(header_frame, image=image, style="Header2.TLabel")
            header_img.image = image
            # validator
            validator = self.master.register(validation_input)
            key_validator = self.master.register(key_input)
            
            # !? idk
            selector_lb = ttk.Label(frame, text="Image", style="Name.TLabel")
            name_lb = ttk.Label(frame, text="Name", style="Name.TLabel")
            description_lb = ttk.Label(frame, text="Description", style="Name.TLabel")
            price_lb = ttk.Label(frame, text="Price", style="Name.TLabel")
            stock_lb = ttk.Label(frame, text="Stock", style="Name.TLabel")

            selector_btn = ttk.Button(frame, image=image)
            selector_btn.image = image
            name_entry = ttk.Entry(frame,font=("Arial 16 bold"), validate="key",validatecommand=(key_validator, "%P"), style="Name.TEntry")
            description = Text(frame, width=35,height=6, font=("Arial 11"), borderwidth=0, highlightbackground="#2d4286", highlightthickness=2)
            price_ent = ttk.Entry(frame,font=("Arial 16 bold"), validate="key",validatecommand=(validator, "%P"), style="Name.TEntry")
            stock_ent = ttk.Entry(frame,font=("Arial 16 bold"), validate="key",validatecommand=(validator, "%P"), style="Name.TEntry")
            
            selector_btn.config(command=lambda: change_photo(selector_btn),text="Select Photo...")
            name_entry.insert(0, item_name)
            description.insert(END, item_description)
            price_ent.insert(0, item_price)
            stock_ent.insert(0, item_stock)
            # header grid
            header_img.grid(row=0,column=0,padx=20)
            header.grid(row=0,column=1)
            # left
            selector_lb.grid(row=1,column=0,pady=10)
            name_lb.grid(row=2,column=0,pady=10)
            description_lb.grid(row=3,column=0,pady=10)
            price_lb.grid(row=4,column=0,pady=10)
            stock_lb.grid(row=5,column=0,pady=10)
            # right
            selector_btn.grid(row=1,column=1,pady=10)
            name_entry.grid(row=2,column=1,pady=10)
            description.grid(row=3,column=1,pady=10)
            price_ent.grid(row=4,column=1,pady=10)
            stock_ent.grid(row=5,column=1,pady=10)

            error_lb  = ttk.Label(frame, style="Error.TLabel")

            error_lb.grid(row=6,column=1,pady=10)
            
            back_btn = Button(frame, text="Back", font=("Arial 16 bold"), foreground="#f8f9fe",background="#2d4286",borderwidth=0)
            delist_btn = Button(frame, text="Delist", font=("Arial 16 bold"), foreground="#f8f9fe",background="#ff4c4c",borderwidth=0)
            update_btn = Button(frame, text="Update", font=("Arial 16 bold"), foreground="#f8f9fe",background="#508871",borderwidth=0)

            back_btn.config(command=my_products_frame)
            delist_btn.config(command=lambda: delist_function(item_id=item_id))
            update_btn.config(command=lambda: update_item(item_name=name_entry, item_description=description, price_=price_ent, stock_=stock_ent, item_id=item_id, error=error_lb))

            back_btn.grid(row=7,column=0,pady=10)
            delist_btn.grid(row=7,column=1,pady=10)
            update_btn.grid(row=7,column=2,pady=10)
            
            # dont touch
            frame.update_idletasks()
            frame_canvas.config(height=550)

        def store_info_frame():
            destroy()
            
            # DONT TOUCH
            frame_canvas = Frame(self.main_frame,width=600)
            frame_canvas.grid(row=0,column=0,sticky='nw')
            frame_canvas.grid_rowconfigure(0,weight=1)
            frame_canvas.grid_columnconfigure(0,weight=1)
            frame_canvas.grid_propagate(0)
            canvas = Canvas(frame_canvas, bg='#F8F9FE',width=580,height=550)
            canvas.grid(row=0,column=0,sticky='news')
            scrollbar = ttk.Scrollbar(frame_canvas,orient='vertical',command=canvas.yview)
            scrollbar.grid(row=0,column=1, sticky='ns')
            canvas.bind("<Configure>", lambda x: canvas.configure(scrollregion=canvas.bbox("all")))
            canvas.configure(yscrollcommand=scrollbar.set)
            frame = Frame(canvas,bg='#F8F9FE')
            canvas.create_window((0,0), window=frame,anchor='nw')
            # Rest of code here ----
            style = ttk.Style()

            style.configure("Header.TLabel", font=("Arial 40 bold"), foreground="#2d4286")
            style.configure("Name.TLabel", font=("Arial 22 bold"), foreground="#2d4286")
            header_label = ttk.Label(frame, text="Your Store", style="Header.TLabel")

            img = Image.open(BytesIO(self.store[2]))
            image = ImageTk.PhotoImage(img)
            
            label = ttk.Label(frame, text="Image:", style="Name.TLabel")
            label2 = ttk.Label(frame, text="Name:", style="Name.TLabel")
            label3 = ttk.Label(frame, text="Location:", style="Name.TLabel")
            
            store_image_btn = ttk.Button(frame, image=image,text="Select Image...",compound=TOP)
            store_image_btn.image = image
            store_name = ttk.Entry(frame)
            store_location = Text(frame, width=10, height=6)

            store_name.insert(0, self.store[1])
            store_location.insert(END, self.store[3])
            
            store_image_btn.config(command=lambda: change_photo(store_image_btn))

            update_btn = ttk.Button(frame, text='Update', command=lambda: update_store(self.img_dir, store_name.get(), store_location.get("1.0", "end-1c")))

            header_label.grid(row=0,columnspan=2)
            label.grid(row=1,column=0)
            store_image_btn.grid(row=1,column=1)
            label2.grid(row=2,column=0)
            store_name.grid(row=2,column=1)
            label3.grid(row=3,column=0)
            store_location.grid(row=3,column=1)
            update_btn.grid(column=2)

            #DONT TOUCH
            frame.update_idletasks()
            frame_canvas.config(height=550)

        def add_products_frame():
            destroy()
            style = ttk.Style()

            style.configure("MainFrame.TFrame", background="#f8f9fe")
            style.configure("Header.TLabel", font=("Arial 40 bold"), foreground="#2d4286", background="#f8f9fe")
            style.configure("Name.TLabel", font=("Arial 16 bold"), foreground="#2d4286", background="#f8f9fe")
            style.configure("Name.TEntry", foreground="#2d4286", background="#f8f9fe")
            style.configure("Selector.TButton", font=("Arial 12 bold"), foreground="#2d4286", background="#f8f9fe")

            style.configure("Error.TLabel", font=("Arial 11 bold"),foreground="#2d4286", background="#f8f9fe")

            frame = ttk.Frame(self.main_frame, width=600,height=550, style="MainFrame.TFrame")
            frame.grid(row=0,column=0)
            frame.grid_columnconfigure(0,weight=1)
            #frame.grid_rowconfigure(0,weight=1)
            frame.grid_propagate(0)
            
            validation = self.master.register(validation_input)
            key_validate = self.master.register(key_input)

            header = ttk.Label(frame, text="Add Product", style="Header.TLabel")

            product_image = ttk.Label(frame, text="Product Image", style="Name.TLabel")
            product_name_lb = ttk.Label(frame, text="Product Name", style="Name.TLabel")
            product_description_lb = ttk.Label(frame, text="Product\nDescription", style="Name.TLabel")
            product_pricing_lb = ttk.Label(frame, text="Price", style="Name.TLabel")
            product_stock_lb = ttk.Label(frame, text="Stock", style="Name.TLabel")

            error_lb = ttk.Label(frame, style="Error.TLabel")

            selector_btn = ttk.Button(frame, text="Select Image", style="Selector.TButton")
            name_entry = ttk.Entry(frame,validate='key',validatecommand=(key_validate, "%P"), style="Name.TEntry",width=22, font=("Arial 16 bold"))
            product_text = Text(frame, width=40,height=6, font=("Arial 11"), borderwidth=0, highlightbackground="#2d4286", highlightthickness=2)
            price_entry = ttk.Entry(frame, style="Name.TEntry", font=("Arial 16 bold"),width=5,validate='key', validatecommand=(validation, '%P'))
            product_stock = ttk.Entry(frame, style="Name.TEntry", font=("Arial 16 bold"),width=5,validate='key', validatecommand=(validation, '%P'))

            add_product_btn = Button(frame, text="Add Product", command=lambda: add_product_function(selector_btn, name_entry, product_text, price_entry, product_stock, error=error_lb))

            selector_btn.config(command=lambda: change_photo(selector_btn))
            selector_btn.image = None

            header.grid(row=0,column=0,columnspan=2)

            product_image.grid(row=1, column=0)
            selector_btn.grid(row=1, column=1)
            
            product_name_lb.grid(row=2,column=0, pady=10,padx=10)
            name_entry.grid(row=2,column=1)

            product_description_lb.grid(row=3,column=0, pady=10,padx=10)
            product_text.grid(row=3,column=1,padx=30)

            product_pricing_lb.grid(row=4,column=0, pady=10,padx=10)
            price_entry.grid(row=4,column=1)

            product_stock_lb.grid(row=5,column=0, pady=10,padx=10)
            product_stock.grid(row=5,column=1)

            error_lb.grid(row=6, column=1)

            add_product_btn.grid(row=7, column=1)
        
        def my_products_frame():
            destroy()
            
            # DONT TOUCH
            frame_canvas = Frame(self.main_frame,width=600,background="#f8f9fe")
            frame_canvas.grid(row=0,column=0,sticky='nw')
            frame_canvas.grid_rowconfigure(0,weight=1)
            frame_canvas.grid_columnconfigure(0,weight=1)
            frame_canvas.grid_propagate(0)
            canvas = Canvas(frame_canvas, bg='#F8F9FE',width=580,height=550)
            canvas.grid(row=0,column=0,sticky='news')
            scrollbar = ttk.Scrollbar(frame_canvas,orient='vertical',command=canvas.yview)
            scrollbar.grid(row=0,column=1, sticky='ns')
            canvas.bind("<Configure>", lambda x: canvas.configure(scrollregion=canvas.bbox("all")))
            canvas.configure(yscrollcommand=scrollbar.set)
            frame = Frame(canvas,bg='#F8F9FE')
            canvas.create_window((0,0), window=frame,anchor='nw')
            # Rest of code here ----
            reshape = utils.reshape(self.products, 4)
            for x, shape in enumerate(reshape):
                for y, item in enumerate(shape):
                    byte = BytesIO(item[0])
                    image = Image.open(byte)
                    image.thumbnail((128,128), Image.LANCZOS)
                    img = ImageTk.PhotoImage(image)
                    product_name = item[1]
                    price = round(item[3])
                    text = utils.trimmer(product_name,len_=10) + '\n₱' + str(price)
                    buttons = Button(frame, text=text, image=img,font=("Arial 11 bold"),compound=TOP,borderwidth=0,anchor='s',highlightbackground="#353ba7",bg="#698ae8",fg="#F8F9FE")
                    buttons.image = img
                    buttons.config(width=130, height=164,command=lambda x=item: item_frame(x))
                    buttons.grid(row=x,column=y,padx=5,pady=10)
            #DONT TOUCH
            frame.update_idletasks()
            frame_canvas.config(height=550)
        
        self.store = get_store()
        self.products = get_products_function()
        self.header_tk = ttk.Frame(self.master,width=800,height=50, style="HEADER.TFrame")
        self.header_tk.grid(row=0,column=0, columnspan=2)
        self.header_tk.grid_columnconfigure(0, weight=1)
        self.header_tk.grid_propagate(0)

        self.button_frame = ttk.Frame(self.master, width=200, height=550, style="BUTTON.TFrame")
        self.main_frame = ttk.Frame(self.master, width=600,height=550, style="MAIN.TFrame")

        self.button_frame.grid(row=1,column=0)
        self.main_frame.grid(row=1,column=1, sticky='news')

        self.button_frame.grid_propagate(0)
        self.main_frame.grid_propagate(0)

        self.store_info_btn = Button(self.button_frame, width=16, height=2,text="Store Info", font=("Arial 16 bold"), fg="#F8F9FE",bg='black',borderwidth=0)
        self.products_btn = Button(self.button_frame, width=16, height=2,text="Add Product", font=("Arial 16 bold"),fg="#F8F9FE",bg='black',borderwidth=0)
        self.myproducts_btn = Button(self.button_frame, width=16, height=2, text="My Products", font=("Arial 16 bold"),fg="#F8F9FE",bg='black',borderwidth=0)
        self.store_info_btn.config(command=lambda: button_handler(btn=self.store_info_btn,cmd='store_info'))
        self.products_btn.config(command=lambda: button_handler(btn=self.products_btn,cmd='add_products'))
        self.myproducts_btn.config(command=lambda: button_handler(btn=self.myproducts_btn,cmd='my_products'))
        
        self.store_info_btn.grid(row=1)
        self.myproducts_btn.grid(row=2)
        self.products_btn.grid(row=3)

        self.store_btn = Button(self.header_tk,width=12,height=3, text="Store",bg="#e1e7f6",fg="#698ae8", command=self.store_page,borderwidth=0,font=("Arial 11 bold"), image=self.icon_tk,compound=LEFT)
        self.store_btn.image = self.icon_tk
        self.logout_btn = Button(self.header_tk,width=12,height=3, text="Logout",bg="#e1e7f6",fg="#698ae8", command=self.logout_function,borderwidth=0,font=("Arial 11 bold"))
        self.logout_btn.grid(row=0,column=1,sticky=E)
        self.header_tk.update_idletasks()
        self.store_btn.config(width=self.logout_btn.winfo_width(),height=self.logout_btn.winfo_height())
        self.store_btn.grid(row=0,column=0,sticky=W)
        self.header_tk.config(height=self.logout_btn.winfo_height())
        
        button_handler(btn=self.store_info_btn,cmd='store_info')

if __name__ == "__main__":
    App(root)
    root.mainloop()