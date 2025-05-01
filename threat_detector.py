import re
import logging
from collections import Counter

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Threat patterns organized by category
THREAT_PATTERNS = {
    # Command execution
    'powershell': {
        'pattern': r'powershell\s+(-|/)([eE][^w]|[^e])',
        'category': 'command_execution',
        'severity': 'medium'
    },
    'cmd.exe': {
        'pattern': r'cmd\.exe',
        'category': 'command_execution',
        'severity': 'medium'
    },
    'rundll32': {
        'pattern': r'rundll32',
        'category': 'command_execution',
        'severity': 'medium'
    },
    'regsvr32': {
        'pattern': r'regsvr32',
        'category': 'command_execution',
        'severity': 'medium'
    },
    'wscript': {
        'pattern': r'wscript',
        'category': 'command_execution',
        'severity': 'medium'
    },
    
    # Credential theft
    'mimikatz': {
        'pattern': r'mimikatz',
        'category': 'credential_theft',
        'severity': 'high'
    },
    'password dump': {
        'pattern': r'password\s*dump',
        'category': 'credential_theft',
        'severity': 'high'
    },
    'credential theft': {
        'pattern': r'credential\s*theft',
        'category': 'credential_theft',
        'severity': 'high'
    },
    'lsass dump': {
        'pattern': r'lsass.*dump',
        'category': 'credential_theft',
        'severity': 'high'
    },
    
    # Privilege escalation
    'privilege escalation': {
        'pattern': r'privilege\s*escalation',
        'category': 'privilege_escalation',
        'severity': 'high'
    },
    'uac bypass': {
        'pattern': r'uac\s*bypass',
        'category': 'privilege_escalation',
        'severity': 'high'
    },
    'sudo': {
        'pattern': r'sudo\s+\w+',
        'category': 'privilege_escalation',
        'severity': 'medium'
    },
    'elevation': {
        'pattern': r'elevat(e|ion)(\s+of)?\s+privilege',
        'category': 'privilege_escalation',
        'severity': 'high'
    },
    
    # Persistence
    'registry key': {
        'pattern': r'registry\s*key',
        'category': 'persistence',
        'severity': 'medium'
    },
    'startup folder': {
        'pattern': r'startup\s*folder',
        'category': 'persistence',
        'severity': 'medium'
    },
    'scheduled task': {
        'pattern': r'scheduled\s*task',
        'category': 'persistence',
        'severity': 'medium'
    },
    'autorun': {
        'pattern': r'autorun',
        'category': 'persistence',
        'severity': 'medium'
    },
    
    # Remote access
    'reverse shell': {
        'pattern': r'reverse\s*shell',
        'category': 'remote_access',
        'severity': 'high'
    },
    'remote access': {
        'pattern': r'remote\s*access',
        'category': 'remote_access',
        'severity': 'medium'
    },
    'backdoor': {
        'pattern': r'backdoor',
        'category': 'remote_access',
        'severity': 'high'
    },
    'c2 server': {
        'pattern': r'c2\s*(server|communication)',
        'category': 'remote_access',
        'severity': 'high'
    },
    
    # Malware indicators
    'ransomware': {
        'pattern': r'ransomware',
        'category': 'malware_indicators',
        'severity': 'high'
    },
    'encryption': {
        'pattern': r'encrypt(ed|ion)(\s+files|\s+disk)?',
        'category': 'malware_indicators',
        'severity': 'medium'
    },
    'trojan': {
        'pattern': r'trojan',
        'category': 'malware_indicators',
        'severity': 'high'
    },
    'payload': {
        'pattern': r'(malicious\s+)?payload',
        'category': 'malware_indicators',
        'severity': 'high'
    },
    
    # Network activity
    'unusual port': {
        'pattern': r'(suspicious|unusual)\s+port\s+\d+',
        'category': 'network_activity',
        'severity': 'medium'
    },
    'unusual connection': {
        'pattern': r'(suspicious|unusual)\s+connection',
        'category': 'network_activity',
        'severity': 'medium'
    },
    'beaconing': {
        'pattern': r'beacon(ing)?',
        'category': 'network_activity',
        'severity': 'medium'
    },
    'exfiltration': {
        'pattern': r'(data\s+)?exfiltration',
        'category': 'network_activity',
        'severity': 'high'
    },
    
    # Other suspicious activities
    'suspicious process': {
        'pattern': r'suspicious\s*process',
        'category': 'suspicious_activity',
        'severity': 'medium'
    },
    'unauthorized access': {
        'pattern': r'unauthorized\s*access',
        'category': 'suspicious_activity',
        'severity': 'medium'
    },
    'failed login': {
        'pattern': r'failed\s*login',
        'category': 'suspicious_activity',
        'severity': 'low'
    }
}

def scan_log_for_threats(log_data):
    """
    Scan a log entry for known threat patterns
    
    Args:
        log_data (str): The log data to scan
        
    Returns:
        list: List of detected threat keywords, empty if none found
    """
    # Convert to lowercase for case-insensitive matching
    log_data_lower = log_data.lower()
    
    # Scan for matches
    detected_keywords = []
    
    for keyword, threat_info in THREAT_PATTERNS.items():
        if re.search(threat_info['pattern'], log_data_lower, re.IGNORECASE):
            detected_keywords.append(keyword)
    
    # Additional heuristics - look for multiple failed attempts
    failed_login_count = len(re.findall(r'failed\s*login', log_data_lower, re.IGNORECASE))
    if failed_login_count >= 3 and 'failed login' not in detected_keywords:
        detected_keywords.append('failed login')
    
    # Check for suspicious IP addresses
    suspicious_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_data)
    suspicious_ip_count = 0
    
    for ip in suspicious_ips:
        # Check for common non-routable or suspicious IP patterns
        if re.match(r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.)', ip):
            continue
        suspicious_ip_count += 1
    
    if suspicious_ip_count >= 2 and 'unusual connection' not in detected_keywords:
        detected_keywords.append('unusual connection')
    
    # Log the results
    if detected_keywords:
        logger.info(f"Detected {len(detected_keywords)} threat patterns: {', '.join(detected_keywords)}")
    else:
        logger.info("No threat patterns detected")
    
    return detected_keywords

def get_threat_categories(detected_keywords):
    """
    Get the categories for the detected threat keywords
    
    Args:
        detected_keywords (list): List of detected keywords
        
    Returns:
        list: List of unique threat categories
    """
    categories = set()
    
    for keyword in detected_keywords:
        if keyword in THREAT_PATTERNS:
            categories.add(THREAT_PATTERNS[keyword]['category'])
    
    return list(categories)

def calculate_threat_score(detected_keywords, log_data):
    """
    Calculate a numerical threat score based on detected keywords and patterns
    
    Args:
        detected_keywords (list): List of detected keywords
        log_data (str): The raw log data
        
    Returns:
        int: Numerical threat score
    """
    score = 0
    
    # Score based on detected keywords and their severity
    for keyword in detected_keywords:
        if keyword in THREAT_PATTERNS:
            severity = THREAT_PATTERNS[keyword]['severity']
            if severity == 'high':
                score += 10
            elif severity == 'medium':
                score += 5
            else:  # low
                score += 2
    
    # Additional scoring based on frequency of certain words
    log_lower = log_data.lower()
    
    # Count words that indicate potential problems
    problem_words = ['error', 'failed', 'warning', 'denied', 'unauthorized', 'suspicious']
    for word in problem_words:
        count = log_lower.count(word)
        score += min(count, 5)  # Cap at 5 points per word
    
    return score
