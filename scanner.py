import socket
import ipaddress
import nmap


class PortScanner:
    """Port scanner using python-nmap with fallback banner grabbing."""
    
    # Common ports for quick selection
    COMMON_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 
                    3306, 3389, 5432, 5900, 8080, 8443, 9200]
    
    # Timing templates for nmap
    TIMING_MAP = {
        'normal': '-T3',
        'fast': '-T4',
        'thorough': '-T5'
    }
    
    def __init__(self):
        self.nm = nmap.PortScanner()
    
    def validate_target(self, target):
        """
        Validate target and check if it's private/loopback.
        
        Args:
            target: IP address or hostname
        
        Returns:
            Tuple (is_valid, is_private, error_message)
        """
        try:
            # Try to parse as IP address
            ip = ipaddress.ip_address(target)
            
            # Check if loopback
            if ip.is_loopback:
                return True, True, "Loopback address detected"
            
            # Check if private
            if ip.is_private:
                return True, True, "Private address detected"
            
            return True, False, None
            
        except ValueError:
            # Not an IP, might be a hostname - let nmap handle it
            # We'll consider hostnames as potentially private if they look like local domains
            if any(local in target.lower() for local in ['localhost', '.local', '.lan', '.internal']):
                return True, True, "Local hostname detected"
            return True, False, None
    
    def grab_banner(self, target, port, timeout=3):
        """
        Attempt to grab banner from a service using raw sockets.
        
        Args:
            target: IP address or hostname
            port: Port number
            timeout: Socket timeout in seconds
        
        Returns:
            Banner string or None if failed
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Try to receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else None
            
        except (socket.timeout, socket.error, ConnectionRefusedError, OSError):
            return None
        except Exception:
            return None
    
    def scan(self, target, start_port, end_port, speed='normal'):
        """
        Perform a port scan on the target.
        
        Args:
            target: IP address or hostname to scan
            start_port: Starting port number
            end_port: Ending port number
            speed: Scan speed - 'normal', 'fast', or 'thorough'
        
        Returns:
            Dictionary with scan results or error information
        """
        # Validate target
        is_valid, is_private, error_msg = self.validate_target(target)
        
        if not is_valid:
            return {
                'error': True,
                'message': f"Invalid target: {error_msg}",
                'is_private': False
            }
        
        # Validate port range
        try:
            start = int(start_port)
            end = int(end_port)
            
            if start < 1 or end > 65535 or start > end:
                return {
                    'error': True,
                    'message': "Invalid port range. Ports must be 1-65535 and start <= end.",
                    'is_private': is_private
                }
        except ValueError:
            return {
                'error': True,
                'message': "Port numbers must be integers.",
                'is_private': is_private
            }
        
        # Build port range string
        port_range = f"{start}-{end}"
        
        # Get timing template
        timing = self.TIMING_MAP.get(speed, '-T3')
        
        try:
            # Run nmap scan with service detection
            # -Pn: Skip host discovery (treat all hosts as up)
            # -sT: TCP connect scan (works without root, fallback from SYN)
            # -sV: Version detection
            # --open: Only show open ports
            # --max-retries: Limit retries for faster scanning
            args = f'{timing} -Pn -sT -sV --open --max-retries 2'
            
            self.nm.scan(target, port_range, arguments=args)
            
            # Check if any hosts were found
            all_hosts = self.nm.all_hosts()
            if not all_hosts:
                # No hosts responded - try direct socket connection as fallback
                open_ports = self._fallback_socket_scan(target, start, end)
                return {
                    'error': False,
                    'target': target,
                    'port_range': port_range,
                    'open_ports': open_ports,
                    'open_count': len(open_ports),
                    'is_private': is_private,
                    'fallback': True
                }
            
            # Use the first host found (nmap may resolve hostname to IP)
            host_key = all_hosts[0]
            if target in all_hosts:
                host_key = target
            
            # Extract results
            open_ports = []
            host_info = self.nm[host_key]
            
            for proto in host_info.all_protocols():
                ports = sorted(host_info[proto].keys())
                
                for port in ports:
                    port_data = host_info[proto][port]
                    
                    # Only include open ports
                    if port_data['state'] == 'open':
                        # Get service details
                        service_info = {
                            'port': port,
                            'protocol': proto.upper(),
                            'state': port_data['state'],
                            'service': port_data.get('name', 'unknown'),
                            'product': port_data.get('product', ''),
                            'version': port_data.get('version', ''),
                            'extrainfo': port_data.get('extrainfo', ''),
                            'banner': None
                        }
                        
                        # If nmap couldn't identify the service, try banner grabbing
                        if service_info['service'] == 'unknown' or not service_info['product']:
                            banner = self.grab_banner(target, port)
                            if banner:
                                service_info['banner'] = banner
                                # Try to extract service name from banner
                                if not service_info['service'] or service_info['service'] == 'unknown':
                                    # Common banner patterns
                                    banner_lower = banner.lower()
                                    if 'ssh' in banner_lower:
                                        service_info['service'] = 'ssh'
                                    elif 'ftp' in banner_lower:
                                        service_info['service'] = 'ftp'
                                    elif 'http' in banner_lower or 'apache' in banner_lower or 'nginx' in banner_lower:
                                        service_info['service'] = 'http'
                                    elif 'smtp' in banner_lower:
                                        service_info['service'] = 'smtp'
                                    elif 'pop3' in banner_lower:
                                        service_info['service'] = 'pop3'
                                    elif 'imap' in banner_lower:
                                        service_info['service'] = 'imap'
                                    elif 'mysql' in banner_lower:
                                        service_info['service'] = 'mysql'
                                    elif 'postgres' in banner_lower:
                                        service_info['service'] = 'postgresql'
                        
                        open_ports.append(service_info)
            
            return {
                'error': False,
                'target': target,
                'port_range': port_range,
                'open_ports': open_ports,
                'open_count': len(open_ports),
                'is_private': is_private
            }
            
        except nmap.PortScannerError as e:
            error_msg = str(e)
            # Provide helpful error for common nmap issues
            if 'requires root privileges' in error_msg.lower():
                error_msg = "SYN scan requires root/admin privileges. Try running with sudo or as administrator."
            elif 'nmap' in error_msg.lower() and 'not found' in error_msg.lower():
                error_msg = "nmap is not installed or not in PATH. Please install nmap."
            
            return {
                'error': True,
                'message': f"Scan error: {error_msg}",
                'is_private': is_private
            }
            
        except Exception as e:
            return {
                'error': True,
                'message': f"Unexpected error during scan: {str(e)}",
                'is_private': is_private
            }
    
    def _fallback_socket_scan(self, target, start_port, end_port):
        """
        Fallback scan using raw sockets when nmap host detection fails.
        This performs simple TCP connect scans on common ports.
        
        Args:
            target: IP or hostname
            start_port: Start of port range
            end_port: End of port range
            
        Returns:
            List of open port dictionaries
        """
        open_ports = []
        
        # Limit range for fallback scan to avoid being too slow
        ports_to_scan = min(end_port - start_port + 1, 100)
        
        for port in range(start_port, start_port + ports_to_scan):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)  # Short timeout for quick scanning
                result = sock.connect_ex((target, port))
                
                if result == 0:  # Port is open
                    # Try to grab banner
                    banner = self.grab_banner(target, port, timeout=2)
                    
                    # Guess service from port number
                    service = self._guess_service_from_port(port)
                    
                    open_ports.append({
                        'port': port,
                        'protocol': 'TCP',
                        'state': 'open',
                        'service': service,
                        'product': '',
                        'version': '',
                        'extrainfo': '',
                        'banner': banner
                    })
                
                sock.close()
                
            except (socket.timeout, socket.error, OSError):
                pass
            except Exception:
                pass
        
        return open_ports
    
    def _guess_service_from_port(self, port):
        """Guess service name from well-known port number."""
        common_services = {
            20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap', 443: 'https',
            445: 'smb', 993: 'imaps', 995: 'pop3s', 3306: 'mysql',
            3389: 'rdp', 5432: 'postgresql', 5900: 'vnc', 8080: 'http-proxy',
            8443: 'https-alt', 9200: 'elasticsearch'
        }
        return common_services.get(port, 'unknown')
    
    @staticmethod
    def get_common_ports_range():
        """Return the range string for common ports."""
        return ','.join(map(str, PortScanner.COMMON_PORTS))
