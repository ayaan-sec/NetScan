import sqlite3
import os
from datetime import datetime

# Ensure the reports directory exists
os.makedirs('reports', exist_ok=True)

DATABASE_PATH = 'scanner.db'


def get_db_connection():
    """Create a database connection with row factory for dict-like access."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the database with the scans table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            port_range TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            open_ports_count INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            report_path TEXT
        )
    ''')
    
    conn.commit()
    conn.close()


def save_scan(target, port_range, open_ports_count, critical_count, high_count, medium_count, low_count, report_path):
    """
    Save a scan record to the database.
    
    Args:
        target: The scanned target (IP or hostname)
        port_range: The port range that was scanned
        open_ports_count: Number of open ports found
        critical_count: Number of critical CVEs found
        high_count: Number of high CVEs found
        medium_count: Number of medium CVEs found
        low_count: Number of low CVEs found
        report_path: Path to the generated PDF report
    
    Returns:
        The ID of the newly created scan record
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    scan_date = datetime.now().isoformat()
    
    cursor.execute('''
        INSERT INTO scans (target, port_range, scan_date, open_ports_count, 
                          critical_count, high_count, medium_count, low_count, report_path)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (target, port_range, scan_date, open_ports_count, critical_count, 
          high_count, medium_count, low_count, report_path))
    
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return scan_id


def get_all_scans():
    """
    Retrieve all scan records from the database.
    
    Returns:
        List of dictionaries containing scan records
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM scans ORDER BY scan_date DESC')
    rows = cursor.fetchall()
    
    scans = []
    for row in rows:
        scan = dict(row)
        # Format the date for display
        try:
            dt = datetime.fromisoformat(scan['scan_date'])
            scan['scan_date_formatted'] = dt.strftime('%Y-%m-%d %H:%M')
        except:
            scan['scan_date_formatted'] = scan['scan_date']
        scans.append(scan)
    
    conn.close()
    return scans


def get_scan_by_id(scan_id):
    """
    Retrieve a specific scan record by ID.
    
    Args:
        scan_id: The ID of the scan to retrieve
    
    Returns:
        Dictionary containing the scan record, or None if not found
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
    row = cursor.fetchone()
    
    conn.close()
    
    if row:
        scan = dict(row)
        # Format the date for display
        try:
            dt = datetime.fromisoformat(scan['scan_date'])
            scan['scan_date_formatted'] = dt.strftime('%Y-%m-%d %H:%M')
        except:
            scan['scan_date_formatted'] = scan['scan_date']
        return scan
    
    return None


def delete_scan(scan_id):
    """
    Delete a scan record from the database.
    
    Args:
        scan_id: The ID of the scan to delete
    
    Returns:
        True if deleted successfully, False if scan not found
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # First check if the scan exists
    cursor.execute('SELECT report_path FROM scans WHERE id = ?', (scan_id,))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        return False
    
    # Delete the report file if it exists
    report_path = row['report_path']
    if report_path and os.path.exists(report_path):
        try:
            os.remove(report_path)
        except OSError:
            pass  # Ignore if file cannot be deleted
    
    # Delete the scan record
    cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
    conn.commit()
    conn.close()
    
    return True


# Initialize the database when this module is imported
init_db()
