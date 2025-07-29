import sqlite3

conn = sqlite3.connect("requests.db")  # Đổi nếu DB bạn có tên khác
c = conn.cursor()

# Thêm cột 'request_type' nếu chưa tồn tại
try:
    c.execute("ALTER TABLE requests ADD COLUMN request_type TEXT")
    print("✅ Added column: request_type")
except sqlite3.OperationalError as e:
    print("ℹ️ Column 'request_type' may already exist:", e)

# Thêm cột 'wallet' nếu chưa tồn tại
try:
    c.execute("ALTER TABLE requests ADD COLUMN wallet TEXT")
    print("✅ Added column: wallet")
except sqlite3.OperationalError as e:
    print("ℹ️ Column 'wallet' may already exist:", e)

# Thêm cột 'tx' nếu chưa tồn tại
try:
    c.execute("ALTER TABLE requests ADD COLUMN tx TEXT")
    print("✅ Added column: tx")
except sqlite3.OperationalError as e:
    print("ℹ️ Column 'tx' may already exist:", e)

conn.commit()
conn.close()
print("🎉 Database schema updated without losing existing data.")
