import json
import os
import logging
from openai import OpenAI

# Initialize the OpenAI client
openai_api_key = os.environ.get("OPENAI_API_KEY")
client = OpenAI(api_key=openai_api_key)

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def analyze_log_with_ai(log_data, detected_keywords=None):
    """
    Analyze log data using OpenAI's GPT to generate insights and recommendations.
    
    Args:
        log_data (str): The log data to analyze
        detected_keywords (list): List of already detected keywords
        
    Returns:
        dict: Analysis results containing summary, threat_level, and recommendations
    """
    try:
        # Create the prompt with context
        prompt = f"""
As a cybersecurity expert, analyze this log entry for security threats.
Detected keywords: {', '.join(detected_keywords) if detected_keywords else 'None'}

Log data:
{log_data}

Provide a concise analysis including:
1. A brief summary of the potential threat (2-3 sentences)
2. Threat level (Low, Medium, or High)
3. Two specific recommendations for remediation

Respond in JSON with these three fields: "summary", "threat_level", and "recommendations" (as an array).
"""
        # Call OpenAI API
        response = client.chat.completions.create(
            model="gpt-4o", # the newest OpenAI model is "gpt-4o" which was released May 13, 2024
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert specializing in log analysis."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            max_tokens=500
        )
        
        # Parse the response
        analysis = json.loads(response.choices[0].message.content)
        
        logger.debug(f"AI Analysis completed: {analysis}")
        return analysis
        
    except Exception as e:
        logger.error(f"Error analyzing log with AI: {str(e)}")
        return {
            "summary": "Unable to complete AI analysis at this time.",
            "threat_level": "Unknown",
            "recommendations": ["Review log manually", "Try analysis again later"]
        }

def calculate_threat_level(detected_keywords, log_data):
    """
    Calculate a simple threat level based on keywords and patterns
    
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
    
    # Count occurrences of certain patterns
    failed_login_count = log_data.lower().count("failed login")
    error_count = log_data.lower().count("error")
    warning_count = log_data.lower().count("warning")
    
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
    
    # Add points for failed logins and errors
    threat_score += failed_login_count * 2
    threat_score += error_count + warning_count
    
    # Determine threat level based on score
    if threat_score >= 10:
        return "High"
    elif threat_score >= 5:
        return "Medium"
    else:
        return "Low"