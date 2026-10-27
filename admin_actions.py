import psycopg2

conn = psycopg2.connect(
    host="localhost",
    database="RogueAPDetectionH",
    user="postgres",
    password="admin123"
)

cursor = conn.cursor()

ssid = input("Enter SSID to review: ")

decision = input(
    "Enter decision (SAFE/BLOCKED): "
)

cursor.execute("""
UPDATE access_points

SET admin_decision = %s

WHERE ssid = %s
""",
(
    decision,
    ssid
))

conn.commit()

print("Administrator decision saved.")