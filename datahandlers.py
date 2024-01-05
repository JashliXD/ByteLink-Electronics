import sqlite3
from hashlib import sha256
import socket
import threading
import pickle
import asyncio

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

    cursor.execute("INSERT INTO Store (store_name,store_image, location, user_id) VALUES (?, ?, ?, ?)", (name,store_image, location, user_id))
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

def update_store(name=None, image_data=None, location=None, user_id=None):
    db = sqlite3.connect('database.db')
    cursor = db.cursor()

    
    request = "UPDATE Store SET "
    value = []
    if name:
        print("Name")
        request += ' store_name=?,'
        value.append(name)
    if image_data:
        print("Image Path")
        request += ' store_image=?,'
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


        cursor.execute("INSERT INTO Item (store_id, item_image, item_name, item_description, price, stock) VALUES (?,?,?,?,?,?)", (id_, img_dir, item_name, item_description, price, stock))
        
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
            value.append(image)
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

def validator(inp):
    try:
        data = pickle.loads(inp)
        return data
    except:
        return inp.decode('utf-8')

async def handler_async(reader, writer):
    print(f"User: {reader} {writer}")
    while True:
        raw = await reader.read(3)
        if not raw:
            break
        
        if raw.startswith(b'BIG'):
            data = b''
            try:
                while True:
                    raw_data = await asyncio.wait_for(reader.read(1024), timeout=0.8)
                    if not raw_data:
                        break
                    data += raw_data
            except:
                print("Timeout data")
            
            infos = pickle.loads(data)
            command = infos[0]
        elif raw.startswith(b'SML'):
            data = await reader.read(1024)
            print(data)
            if not data:
                break
            msg = validator(data)
            infos = commandhandler(msg)
            command = infos[0]
        
        if raw == b'&@&':
            break

        if command == 'login':
            user = login(infos[1], infos[2])
            writer.write(user)
            await writer.drain()
        
        if command == 'register':
            res = create_account(infos[1], infos[2], infos[3])
            writer.write(res)
            await writer.drain()
        
        if command == 'create_store':
            res = create_store(infos[1], infos[2], infos[3], infos[4])
            writer.write(res)
            await writer.drain()
        
        if command == 'has_store':
            res = has_store(int(infos[1]))
            writer.write(pickle.dumps(res))
            await writer.drain()
        
        if command == 'get_all_store':
            res = get_all_store()
            for i in range(0, len(res), 4096):
                chunk = res[i:i+4096]
                writer.write(chunk)
                await writer.drain()

        if command == 'get_store':
            res = get_user_store(int(infos[1]))
            compile = pickle.dumps(res) # compiles into bytes
            for i in range(0, len(compile), 4096):
                chunk = compile[i:i+4096]
                writer.write(chunk)
                await writer.drain()
        
        if command == 'update_store':
            res = update_store(infos[1],infos[2],infos[3], int(infos[4]))
            writer.write(res)
            await writer.drain()

        if command == 'add_product':
            res = add_product(infos[1], infos[2], infos[3], infos[4], int(infos[5]), int(infos[6]))
            writer.write(res.encode('utf-8'))
            await writer.drain()
        
        if command == 'get_products':
            res = get_products_user(infos[1])
            chunk = 32768
            compile = pickle.dumps(res)
            for i in range(0 , len(compile), chunk):
                part = compile[i:i+chunk]
                writer.write(part)
                await writer.drain()
            
        if command == 'delist':
            res = delist_item(int(infos[1]))
            writer.write(res.encode('utf-8'))
            await writer.drain()
        
        if command == 'update_item':
            res = update_item(infos[1], infos[2], infos[3], float(infos[4]),int(infos[5]), int(infos[6]))
            writer.write(res.encode('utf-8'))
            await writer.drain()
    print("Shutting down")

async def server(ip, port):
    server = None
    try:
        server = await asyncio.start_server(handler_async, ip, port)

        #host, port_ = server.sockets[0].getsockname()
        print("Server listening")
        async with server:
            await server.serve_forever()
    except:
        print("Error")

if __name__ == "__main__":
    print(f"Server started \n\tIP ADDRESS: {socket.gethostbyname(socket.gethostname())}\n\tPORT: 8888")
    asyncio.run(server(socket.gethostbyname(socket.gethostname()), 8888))