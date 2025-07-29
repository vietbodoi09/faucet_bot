import sqlite3

# Đường dẫn đến file database của bạn
DB_PATH = "fogo_requests.db"

def migrate_send_to_send_fogo():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Kiểm tra trước khi cập nhật
    cursor.execute("SELECT COUNT(*) FROM requests WHERE request_type = 'send'")
    count = cursor.fetchone()[0]
    print(f"🔎 Found {count} row(s) with request_type = 'send'")

    if count == 0:
        print("✅ No rows to migrate.")
    else:
        # Cập nhật request_type = 'send' → 'send_fogo'
        cursor.execute("UPDATE requests SET request_type = 'send_fogo' WHERE request_type = 'send'")
        conn.commit()
        print(f"✅ Successfully migrated {cursor.rowcount} row(s) from 'send' → 'send_fogo'")

    conn.close()

if __name__ == "__main__":
    migrate_send_to_send_fogo()
