import sqlite3

DB_PATH = "fogo_requests.db"  # Đúng tên file bạn đang dùng

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

# Tạo bảng nếu chưa tồn tại
c.execute("""
CREATE TABLE IF NOT EXISTS requests (
    user_id INTEGER,
    last_request TEXT,
    request_type TEXT,
    wallet TEXT,
    tx TEXT
)
""")

conn.commit()
conn.close()
print("✅ Table 'requests' created or already exists.")
