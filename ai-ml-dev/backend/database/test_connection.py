import psycopg2

try:
    conn = psycopg2.connect(
        dbname="phantomnet_db",
        user="postgres",
        password="phantom",
        host="localhost",
        port=5432
    )
    print("Database connected successfully")
    conn.close()
except Exception as e:
    print("Connection failed:", e)
