import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from database import init_db

def seed_database():
    init_db()
    print("[+] Database initialized successfully.")

if __name__ == "__main__":
    seed_database()
