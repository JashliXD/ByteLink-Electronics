import sqlite3
from hashlib import sha256
import socket
import threading
import pickle

from PIL import Image
from io import BytesIO

# not yet updated to server / client version
def create_account(email, username, password):
    try:
        db = sqlite3.connect('database.db')
        cursor = db.cursor()
        # hashing
        hashed_password = sha256(password.encode('utf-8')).hexdigest()

        cursor.execute("INSERT INTO User (email, username, password) VALUES (?, ?, ?)",(email, username, hashed_password))

        db.commit()
        return "101".encode("utf-8")
    except:
        return "404".encode("utf-8")
    
# login using server / client
def login(username, password):
    db = sqlite3.connect('database.db')
    cursor = db.cursor()
    # hashing
    hashed = sha256(password.encode('utf-8')).hexdigest()

    cursor.execute("SELECT * FROM User Where username=?",(username,))
    user = cursor.fetchone()
    
    db.close()
    if user == None:
        return "UNKNOWN_USER".encode("utf-8")
    if user[1] != hashed:
        return "PASSWORD_INVALID".encode("utf-8")
    user = str(user).encode('utf-8')
    return user

def has_store(user_id):
    db = sqlite3.connect('database.db')
    cursor = db.cursor()

    cursor.execute("SELECT * FROM Store Where user_id=?",(user_id,))
    user = cursor.fetchone()
    if user:
        return True
    db.close()
    return False
# store test
def create_store(name,store_image, location, user_id):
    db = sqlite3.connect('database.db')
    cursor = db.cursor()

    if has_store(user_id):
        print("Already have store")
        return "USER_STORE_101"

    #print(name, store_image, location, user_id)

    image = Image.open(store_image)
    image.thumbnail((100,100), Image.Resampling.LANCZOS)
    
    with BytesIO() as byte:
        image.save(byte, "PNG")
        image_data = byte.getvalue()

    

    cursor.execute("INSERT INTO Store (store_name,store_image, location, user_id) VALUES (?, ?, ?, ?)", (name,image_data, location, user_id))
    db.commit()
    db.close()
    return "Goods".encode('utf-8')

def get_all_store():
    db = sqlite3.connect('database.db')
    cursor = db.cursor()

    cursor.execute("SELECT * FROM Store")
    table = cursor.fetchall()
    db.close()
    return pickle.dumps(table)

def get_user_store(user_id):
    db = sqlite3.connect('database.db')
    cursor = db.cursor()

    cursor.execute("SELECT * FROM Store Where user_id=?", (user_id,))
    store = cursor.fetchone()

    db.close()

    return store

def update_store(name=None, image_path=None, location=None, user_id=None):
    db = sqlite3.connect('database.db')
    cursor = db.cursor()

    
    request = "UPDATE Store SET "
    value = []
    if name:
        print("Name")
        request += ' store_name=?,'
        value.append(name)
    if image_path:
        print("Image Path")
        request += ' store_image=?,'
        with BytesIO() as byte:
            image = Image.open(image_path)
            image.thumbnail((100,100), Image.Resampling.LANCZOS)
            image.save(byte, "PNG")
            image_data = byte.getvalue()
        value.append(image_data)
    if location:
        print("Location")
        request += ' location=?,'
        value.append(location)
    request = request.rstrip(',')
    request += " WHERE user_id=?"
    value.append(user_id)
    cursor.execute(request, tuple(value))
    db.commit()
    db.close()
    return pickle.dumps(True)

def add_product(id_,img_dir, item_name, item_description, price, stock):
    try:
        db = sqlite3.connect('database.db')
        cursor = db.cursor()

        with BytesIO() as byte:
            img = Image.open(img_dir)
            img.thumbnail((256,256), Image.Resampling.LANCZOS)
            img.save(byte, "PNG")
            image_data = byte.getvalue()

        cursor.execute("INSERT INTO Item (store_id, item_image, item_name, item_description, price, stock) VALUES (?,?,?,?,?,?)", (id_, image_data, item_name, item_description, price, stock))
        
        db.commit()
        db.close()
        return "Success"
    except Exception as e:
        print(e)
        return "Error"
    # convert message to command unit

def get_products_user(store_id):
    db = sqlite3.connect('database.db')
    cursor = db.cursor()

    cursor.execute("SELECT * FROM Item Where store_id=?", (int(store_id),))
    items = cursor.fetchall()

    db.close()

    return items

def delist_item(item_id):
    try:
        db = sqlite3.connect('database.db')
        cursor = db.cursor()

        cursor.execute("DELETE FROM Item Where item_id=?", (int(item_id),))

        db.commit()
        db.close()
        return "Success"
    except:
        return "Failure"

def update_item(image=None, name=None, description=None, price=None, stock=None, item_id=None):
    try:
        db = sqlite3.connect('database.db')
        cursor = db.cursor()
        request = "UPDATE Item SET "
        value = []
        if image:
            print("Image")
            request += ' item_image=?,'
            with BytesIO() as byte:
                image = Image.open(image)
                image.thumbnail((256,256), Image.LANCZOS)
                image.save(byte, "PNG")
                image_data = byte.getvalue()
            value.append(image_data)
        if name:
            print("name")
            request += ' item_name=?,'
            value.append(name)
        if description:
            print("des")
            request += ' item_description=?,'
            value.append(description)
        if price:
            print("pr")
            request += ' price=?,'
            value.append(price)
        if stock:
            print("stock")
            request += ' stock=?,'
            value.append(stock)
        print("STRIP")
        request = request.rstrip(',')
        request += ' WHERE item_id=?'
        value.append(item_id)
        print("EXEC")
        cursor.execute(request, tuple(value))
        db.commit()
        db.close()
        return "Success"
    except Exception as e: 
        print(e)
        return "Failure"


def commandhandler(string):
    if string.startswith('@'):
        arr = string.split('|')
        arr[0] = arr[0][1:]

        return arr
    else:
        print("Unknown command")
# handler
def handler(client):
    while True:
        data = client.recv(1024)
        if not data:
            break

        msg = data.decode('utf-8')

        infos = commandhandler(msg)
        command = infos[0]

        if command == 'login':
            user = login(infos[1], infos[2])
            client.send(user)
        
        if command == 'register':
            res = create_account(infos[1], infos[2], infos[3])
            client.send(res)
        
        if command == 'create_server':
            res = create_store(infos[1], infos[2], infos[3], infos[4])
            client.send(res)
        
        if command == 'has_store':
            res = has_store(int(infos[1]))
            client.send(pickle.dumps(res))
        
        if command == 'get_all_store':
            res = get_all_store()
            for i in range(0, len(res), 4096):
                chunk = res[i:i+4096]
                client.sendall(chunk)

        if command == 'get_store':
            res = get_user_store(int(infos[1]))
            compile = pickle.dumps(res) # compiles into bytes
            for i in range(0, len(compile), 4096):
                chunk = compile[i:i+4096]
                client.sendall(chunk)
        
        if command == 'update_store':
            print(msg)
            print(infos)
            res = update_store(infos[1],infos[2],infos[3], int(infos[4]))
            client.send(res)

        if command == 'add_product':
            res = add_product(infos[1], infos[2], infos[3], infos[4], int(infos[5]), int(infos[6]))
            client.send(res.encode('utf-8'))
        
        if command == 'get_products':
            res = get_products_user(infos[1])
            chunk = 32768
            compile = pickle.dumps(res)
            for i in range(0 , len(compile), chunk):
                part = compile[i:i+chunk]
                client.sendall(part)
            
        if command == 'delist':
            res = delist_item(int(infos[1]))
            client.send(res.encode('utf-8'))
        
        if command == 'update_item':
            res = update_item(infos[1], infos[2], infos[3], float(infos[4]),int(infos[5]), int(infos[6]))
            client.send(res.encode('utf-8'))
    client.close()
# server
def server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    ip = socket.gethostbyname(socket.gethostname())
    port=8888 # standard socket for this project

    server.bind((ip, port))

    server.listen()
    while True:
        client, addr = server.accept()
        print(f"Connection established with {client} | {addr}")
        client_handler = threading.Thread(target=handler, args=(client,))
        client_handler.start()


if __name__ == "__main__":
    print(get_all_store())
    print(f"Server started \n\tIP ADDRESS: {socket.gethostbyname(socket.gethostname())}\n\tPORT: 8888")
    server()