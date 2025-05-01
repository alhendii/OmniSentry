import re
import logging
from collections import Counter

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Define patterns and threat categories for NLP analysis
THREAT_PATTERNS = {
    "command_execution": [
        r"powershell\s+-[ec]", r"cmd\.exe", r"rundll32", r"regsvr32", r"wscript",
        r"cscript", r"bitsadmin", r"certutil -decode", r"regsvr32", r"wmic"
    ],
    "credential_theft": [
        r"mimikatz", r"hashdump", r"passworddump", r"lsass", r"credential", 
        r"kerberos", r"ntlm", r"pass(word)?dump", r"hash(es)?\s+dump"
    ],
    "privilege_escalation": [
        r"UAC\s+bypass", r"privilege\s+escalation", r"sudo", r"administrator\s+access",
        r"root\s+access", r"elevation", r"admin\s+privilege"
    ],
    "persistence": [
        r"registry\s+key", r"startup\s+folder", r"scheduled\s+task", r"service\s+creation",
        r"autorun", r"boot\s+key", r"winlogon", r"run\s+key"
    ],
    "data_exfiltration": [
        r"upload", r"exfiltration", r"ftp", r"transfer", r"pastebin", r"raw\.githubusercontent",
        r"download", r"base64", r"encoded\s+data"
    ],
    "remote_access": [
        r"reverse\s+shell", r"remote\s+access", r"backdoor", r"RAT", r"remote\s+desktop",
        r"VNC", r"TeamViewer", r"ssh", r"telnet", r"netcat", r"nc\.exe"
    ],
    "malware_indicators": [
        r"trojan", r"virus", r"ransomware", r"malware", r"suspicious\s+file",
        r"suspicious\s+process", r"payload", r"exploit"
    ],
    "network_activity": [
        r"unusual\s+port", r"outbound\s+connection", r"C2", r"command\s+and\s+control",
        r"unusual\s+traffic", r"beaconing", r"DNS\s+request"
    ]
}

# Security impact weights for categories
CATEGORY_WEIGHTS = {
    "command_execution": 7,
    "credential_theft": 9,
    "privilege_escalation": 8,
    "persistence": 6,
    "data_exfiltration": 8,
    "remote_access": 9,
    "malware_indicators": 7,
    "network_activity": 5
}

def analyze_log_content(log_data, detected_keywords=None):
    """
    Analyze log data using NLP to identify threats, patterns, and assess severity
    
    Args:
        log_data (str): The log data to analyze
        detected_keywords (list): List of already detected keywords
        
    Returns:
        dict: Analysis results containing categories, severity, and threat_indicators
    """
    try:
        log_data_lower = log_data.lower()
        results = {
            'categories': [],
            'severity': 'Low',
            'threat_score': 0,
            'threat_indicators': [],
            'matched_patterns': {}
        }
        
        # Find matches for each category
        for category, patterns in THREAT_PATTERNS.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, log_data_lower, re.IGNORECASE)
                if found:
                    matches.extend(found)
            
            if matches:
                results['categories'].append(category)
                results['matched_patterns'][category] = matches
                # Add to threat score based on category weight and number of matches
                category_score = CATEGORY_WEIGHTS[category] * min(len(matches), 3)
                results['threat_score'] += category_score
        
        # Analyze frequency of suspicious terms
        word_counter = Counter(re.findall(r'\b\w+\b', log_data_lower))
        suspicious_terms = ["failed", "error", "warning", "unauthorized", "suspicious", 
                           "attempt", "blocked", "denied", "exploit", "breach"]
        
        for term in suspicious_terms:
            if word_counter[term] > 2:  # If term appears multiple times
                results['threat_score'] += min(word_counter[term], 5)
                results['threat_indicators'].append(f"Multiple '{term}' occurrences ({word_counter[term]})")
        
        # Check for sequence patterns that might indicate sophisticated attacks
        sequence_patterns = [
            (r"login\s+attempt.*failed.*login\s+attempt.*failed", "Multiple failed login attempts"),
            (r"download.*execute", "Download and execute pattern"),
            (r"encode.*decode", "Encode-decode pattern"),
            (r"scan.*exploit", "Scan and exploit pattern")
        ]
        
        for pattern, description in sequence_patterns:
            if re.search(pattern, log_data_lower, re.IGNORECASE | re.DOTALL):
                results['threat_score'] += 5
                results['threat_indicators'].append(description)
        
        # Determine final severity based on threat score
        if results['threat_score'] >= 20:
            results['severity'] = 'High'
        elif results['threat_score'] >= 10:
            results['severity'] = 'Medium'
        else:
            results['severity'] = 'Low'
            
        logger.debug(f"NLP Analysis completed: {results}")
        return results
        
    except Exception as e:
        logger.error(f"Error analyzing log with NLP: {str(e)}")
        return {
            'categories': [],
            'severity': 'Low',
            'threat_score': 0,
            'threat_indicators': ["Analysis error occurred"],
            'matched_patterns': {}
        }

def calculate_threat_level(detected_keywords, log_data):
    """
    Calculate a threat level based on keywords and log content analysis
    
    Args:
        detected_keywords (list): List of detected keywords
        log_data (str): The log data
        
    Returns:
        str: Threat level (Low, Medium, High)
    """
    # These are high-severity keywords that immediately raise the threat level
    high_severity_keywords = [
        "mimikatz", "password dump", "credential theft", "ransomware", 
        "privilege escalation", "shellcode", "reverse shell"
    ]
    
    # Medium severity keywords
    medium_severity_keywords = [
        "powershell", "rundll32", "regsvr32", "certutil", "bypass",
        "suspicious process", "unauthorized access"
    ]
    
    # Initial score
    threat_score = 0
    
    # Add points for detected keywords
    for keyword in detected_keywords:
        if keyword.lower() in [k.lower() for k in high_severity_keywords]:
            threat_score += 10
        elif keyword.lower() in [k.lower() for k in medium_severity_keywords]:
            threat_score += 5
        else:
            threat_score += 2
    
    # Run NLP analysis to get additional insights
    nlp_results = analyze_log_content(log_data, detected_keywords)
    
    # Combine the scores
    combined_score = threat_score + nlp_results['threat_score']
    
    # Determine threat level based on combined score
    if combined_score >= 20:
        return "High"
    elif combined_score >= 10:
        return "Medium"
    else:
        return "Low"