import re
import logging

# Define known malicious patterns to scan for
KNOWN_THREATS = [
    "powershell",
    "mimikatz",
    "rundll32",
    "certutil -decode",
    "bitsadmin /transfer",
    "regsvr32",
    "wscript.shell",
    "iex(",
    "invoke-expression",
    "downloadstring",
    "downloadfile",
    "bypass",
    "passworddump",
    "hashdump",
    "shellcode",
    "base64 -d",
    "chmod +x",
    "netcat",
    "meterpreter",
    "reverse shell",
    "privilege escalation",
    "unauthorized access",
    "malware",
    "trojan",
    "ransomware",
    "suspicious process",
    "unauthorized command",
    "suspicious script",
    "exploitation attempt",
    "credential theft"
]

def scan_log_for_threats(log_data):
    """
    Scan a log entry for known threat patterns
    
    Args:
        log_data (str): The log data to scan
        
    Returns:
        list: List of detected threat keywords, empty if none found
    """
    log_data_lower = log_data.lower()
    detected_keywords = []
    
    # Check for each known threat pattern
    for threat in KNOWN_THREATS:
        if threat.lower() in log_data_lower:
            detected_keywords.append(threat)
    
    logging.debug(f"Scan results: {detected_keywords}")
    return detected_keywords
