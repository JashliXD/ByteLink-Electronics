import sqlite3

db = sqlite3.connect('database.db')

conn = db.cursor()

conn.execute('''CREATE TABLE IF NOT EXISTS User (
             username TEXT,
             password TEXT,
             email TEXT,
             user_id INTEGER PRIMARY KEY
)''')

conn.execute('''CREATE TABLE IF NOT EXISTS Store (
             store_id INTEGER PRIMARY KEY,
             store_name TEXT,
             store_image BLOB,
             location TEXT,
             user_id INTEGER,

             FOREIGN KEY (user_id) REFERENCES User (user_id)
)''')

conn.execute('''CREATE TABLE IF NOT EXISTS Item (
             item_image BLOB,
             item_name TEXT,
             item_description TEXT,
             price REAL,
             stock INTEGER,
             item_id INTEGER PRIMARY KEY,
             store_id INTEGER,
             FOREIGN KEY (store_id) REFERENCES Store (store_id)
)''')

conn.execute('''CREATE TABLE IF NOT EXISTS Cart (
             cart_id INTEGER PRIMARY KEY,
             user_id INTEGER,
             item_id INTEGER,
             store_id INTEGER,
             quantity INTEGER,

             FOREIGN KEY (store_id) REFERENCES Store (store_id)
             FOREIGN KEY (user_id) REFERENCES User (user_id)
             FOREIGN KEY (item_id) REFERENCES Item (item_id)
)''')

db.commit()

db.close()