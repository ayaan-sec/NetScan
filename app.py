"""
NetScan - Network Port Scanner & Vulnerability Reporter

Prerequisites:
=============
1. nmap must be installed on your system:
   
   Ubuntu/Debian:
   $ sudo apt-get install nmap
   
   CentOS/RHEL/Fedora:
   $ sudo yum install nmap
   
   macOS:
   $ brew install nmap
   
   Windows:
   Download from https://nmap.org/download.html and install
   Make sure nmap is added to your PATH

2. Python dependencies:
   $ pip install -r requirements.txt

Running the application:
=======================
$ python app.py

The app will start on http://0.0.0.0:5000

Note: Some scan features may require administrator/root privileges.
"""

from flask import Flask, render_template, jsonify, request, send_file
import os
import threading

from scanner import PortScanner
from cve_lookup import CVELookup
from report import generate_report
from database import save_scan, get_all_scans, get_scan_by_id, delete_scan

app = Flask(__name__)

# Global scanner and CVE lookup instances
port_scanner = PortScanner()
cve_lookup = CVELookup()

# Store scan progress for status updates
scan_progress = {}
scan_lock = threading.Lock()


def update_progress(scan_id, status, progress=0):
    """Update the progress of a scan."""
    with scan_lock:
        scan_progress[scan_id] = {'status': status, 'progress': progress}


def get_progress(scan_id):
    """Get the progress of a scan."""
    with scan_lock:
        return scan_progress.get(scan_id, {'status': 'unknown', 'progress': 0})


def run_scan_task(scan_id, target, start_port, end_port, speed):
    """Run the scan task in background and update progress."""
    try:
        update_progress(scan_id, 'Connecting...', 10)
        
        # Perform port scan
        update_progress(scan_id, 'Scanning ports...', 30)
        scan_results = port_scanner.scan(target, start_port, end_port, speed)
        
        if scan_results.get('error'):
            update_progress(scan_id, 'Error', -1)
            return scan_results
        
        # Service detection
        update_progress(scan_id, 'Detecting services...', 50)
        
        # CVE lookup for each open port
        update_progress(scan_id, 'Looking up CVEs...', 70)
        open_ports = scan_results.get('open_ports', [])
        
        for i, port in enumerate(open_ports):
            progress = 70 + (i / len(open_ports) * 25) if open_ports else 95
            update_progress(scan_id, 'Looking up CVEs...', int(progress))
            
            # Look up CVEs for this port
            cves = cve_lookup.lookup_service(port)
            port['cves'] = cves
            
            # Determine highest severity for this port
            severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']
            highest_severity = 'NONE'
            for cve in cves:
                severity = cve.get('severity', 'NONE')
                if severities.index(severity) < severities.index(highest_severity):
                    highest_severity = severity
            
            port['highest_severity'] = highest_severity
        
        update_progress(scan_id, 'Done', 100)
        return scan_results
        
    except Exception as e:
        update_progress(scan_id, 'Error', -1)
        return {'error': True, 'message': str(e)}


@app.route('/')
def index():
    """Serve the main application page."""
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    """
    Run a port scan and CVE lookup.
    
    JSON body parameters:
    - target: IP address or hostname to scan
    - start_port: Starting port number
    - end_port: Ending port number
    - speed: Scan speed ('normal', 'fast', 'thorough')
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': True, 'message': 'No data provided'}), 400
        
        target = data.get('target', '').strip()
        start_port = data.get('start_port', 1)
        end_port = data.get('end_port', 1024)
        speed = data.get('speed', 'normal')
        
        # Validate inputs
        if not target:
            return jsonify({'error': True, 'message': 'Target is required'}), 400
        
        # Generate scan ID
        import uuid
        scan_id = str(uuid.uuid4())
        
        # Run scan task
        update_progress(scan_id, 'Initializing...', 5)
        
        results = run_scan_task(scan_id, target, start_port, end_port, speed)
        
        if results.get('error'):
            return jsonify({
                'error': True,
                'message': results.get('message', 'Scan failed'),
                'is_private': results.get('is_private', False)
            }), 500
        
        # Calculate CVE counts
        cve_summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for port in results.get('open_ports', []):
            for cve in port.get('cves', []):
                severity = cve.get('severity', 'NONE').lower()
                if severity in cve_summary:
                    cve_summary[severity] += 1
        
        # Generate PDF report
        report_path, report_filename = generate_report(results)
        
        # Save to database
        scan_id_db = save_scan(
            target=results['target'],
            port_range=results['port_range'],
            open_ports_count=results['open_count'],
            critical_count=cve_summary['critical'],
            high_count=cve_summary['high'],
            medium_count=cve_summary['medium'],
            low_count=cve_summary['low'],
            report_path=report_path
        )
        
        return jsonify({
            'error': False,
            'scan_id': scan_id_db,
            'target': results['target'],
            'port_range': results['port_range'],
            'open_ports_count': results['open_count'],
            'is_private': results.get('is_private', False),
            'cve_summary': cve_summary,
            'open_ports': results['open_ports'],
            'report_filename': report_filename,
            'progress': get_progress(scan_id)
        })
        
    except Exception as e:
        return jsonify({
            'error': True,
            'message': f'Server error: {str(e)}'
        }), 500


@app.route('/history', methods=['GET'])
def get_history():
    """Return all scan history records."""
    try:
        scans = get_all_scans()
        return jsonify({'error': False, 'scans': scans})
    except Exception as e:
        return jsonify({
            'error': True,
            'message': f'Failed to retrieve history: {str(e)}'
        }), 500


@app.route('/report/<int:scan_id>', methods=['GET'])
def get_report(scan_id):
    """
    Generate and serve the PDF report for a specific scan.
    
    Args:
        scan_id: The ID of the scan to generate report for
    """
    try:
        scan = get_scan_by_id(scan_id)
        
        if not scan:
            return jsonify({'error': True, 'message': 'Scan not found'}), 404
        
        report_path = scan.get('report_path')
        
        if not report_path or not os.path.exists(report_path):
            return jsonify({'error': True, 'message': 'Report file not found'}), 404
        
        return send_file(report_path, as_attachment=True, download_name=os.path.basename(report_path))
        
    except Exception as e:
        return jsonify({
            'error': True,
            'message': f'Failed to retrieve report: {str(e)}'
        }), 500


@app.route('/history/<int:scan_id>', methods=['DELETE'])
def delete_history(scan_id):
    """
    Delete a scan from history.
    
    Args:
        scan_id: The ID of the scan to delete
    """
    try:
        success = delete_scan(scan_id)
        
        if not success:
            return jsonify({'error': True, 'message': 'Scan not found'}), 404
        
        return jsonify({'error': False, 'message': 'Scan deleted successfully'})
        
    except Exception as e:
        return jsonify({
            'error': True,
            'message': f'Failed to delete scan: {str(e)}'
        }), 500


if __name__ == '__main__':
    # Ensure reports directory exists
    os.makedirs('reports', exist_ok=True)
    
    # Run the Flask app
    app.run(debug=False, host='0.0.0.0', port=5000)
