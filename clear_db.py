import sqlite3
from pathlib import Path

def clear_database_data(db_path):
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Get all table names
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' 
            AND name NOT LIKE 'sqlite_%';
        """)
        
        tables = cursor.fetchall()
        
        # Begin transaction
        conn.execute("BEGIN TRANSACTION")
        
        # Delete data from each table
        for table in tables:
            table_name = table[0]
            print(f"Clearing data from table: {table_name}")
            cursor.execute(f"DELETE FROM {table_name}")
        
        # Commit the transaction
        conn.commit()
        print("All data has been cleared successfully while preserving the schema!")

    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        conn.rollback()
    finally:
        # Close the connection
        conn.close()

if __name__ == "__main__":
    # Specify your database path
    db_path = "/Users/karansaini/Desktop/Skaeo/flask_blog/instance/blog.db"  # Change this to your database path
    
    # Check if database exists
    if not Path(db_path).exists():
        print(f"Database file {db_path} not found!")
    else:
        # Ask for confirmation
        confirm = input(f"Are you sure you want to delete all data from {db_path}? (yes/no): ")
        if confirm.lower() == 'yes':
            clear_database_data(db_path)
        else:
            print("Operation cancelled.")
