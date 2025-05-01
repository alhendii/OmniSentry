import os
import logging
from flask import Flask
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "threatlite-default-secret")

# In-memory storage for detected threats
# This would be replaced with a database in a production environment
class ThreatStorage:
    def __init__(self):
        self.threats = []
        self.next_id = 1
    
    def add_threat(self, detected_keywords, raw_log):
        threat = {
            'id': self.next_id,
            'timestamp': datetime.now(),
            'detected_keywords': detected_keywords,
            'raw_log': raw_log
        }
        self.threats.append(threat)
        self.next_id += 1
        return threat
    
    def get_all_threats(self):
        return sorted(self.threats, key=lambda x: x['timestamp'], reverse=True)
    
    def get_threat_by_id(self, threat_id):
        for threat in self.threats:
            if threat['id'] == threat_id:
                return threat
        return None

# Initialize threat storage
threat_storage = ThreatStorage()

# Import routes after initializing app and storage
from routes import *

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
