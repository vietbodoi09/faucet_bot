import sqlite3

DB_PATH = "fogo_requests.db"
conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

# Lấy danh sách các cột hiện tại
c.execute("PRAGMA table_info(requests)")
columns = [row[1] for row in c.fetchall()]

# Thêm cột request_type nếu thiếu
if "request_type" not in columns:
    c.execute("ALTER TABLE requests ADD COLUMN request_type TEXT")
    print("✅ Added column: request_type")

# Thêm cột tx nếu thiếu (vì tên hiện tại là tx_hash → đổi lại hoặc giữ nguyên nếu đã dùng rồi)
if "tx" not in columns:
    c.execute("ALTER TABLE requests ADD COLUMN tx TEXT")
    print("✅ Added column: tx")

conn.commit()
conn.close()
print("🎉 Schema updated safely.")
