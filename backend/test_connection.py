import psycopg2

try:
    conn = psycopg2.connect(
        dbname="phantomnet",
        user="postgres",
        password="password@321",
        host="localhost",
        port=5432
    )
    print("Database connected successfully")
    cur = conn.cursor()
    cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';")
    tables = cur.fetchall()
    print("Tables:", tables)
    cur.close()
    conn.close()
except Exception as e:
    print("Connection failed:", e)
