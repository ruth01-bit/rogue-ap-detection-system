import psycopg2

try:

    conn = psycopg2.connect(
        host="localhost",
        database="RogueAPDetection",
        user="postgres",
        password="admin123"
    )

    cursor = conn.cursor()

    print("Connected successfully!")

except Exception as e:

    print(e)