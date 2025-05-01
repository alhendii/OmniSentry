from app import db
from datetime import datetime
import json

class Threat(db.Model):
    __tablename__ = 'threats'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    detected_keywords = db.Column(db.String(500))  # Stored as JSON string
    raw_log = db.Column(db.Text)
    threat_level = db.Column(db.String(20), default="Medium")  # Low, Medium, High
    threat_categories = db.Column(db.String(500), nullable=True)  # Stored as JSON string
    threat_indicators = db.Column(db.String(1000), nullable=True)  # Stored as JSON string
    source = db.Column(db.String(100), default="manual_upload")  # manual_upload, agent, etc.
    
    def set_detected_keywords(self, keywords_list):
        self.detected_keywords = json.dumps(keywords_list)
        
    def get_detected_keywords(self):
        if not self.detected_keywords:
            return []
        return json.loads(self.detected_keywords)
        
    def set_threat_categories(self, categories_list):
        self.threat_categories = json.dumps(categories_list)
        
    def get_threat_categories(self):
        if not self.threat_categories:
            return []
        return json.loads(self.threat_categories)
    
    def set_threat_indicators(self, indicators_list):
        self.threat_indicators = json.dumps(indicators_list)
        
    def get_threat_indicators(self):
        if not self.threat_indicators:
            return []
        return json.loads(self.threat_indicators)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'detected_keywords': self.get_detected_keywords(),
            'threat_level': self.threat_level,
            'threat_categories': self.get_threat_categories(),
            'threat_indicators': self.get_threat_indicators(),
            'source': self.source
        }
        
    def to_detail_dict(self):
        """Return dictionary with additional raw log data"""
        data = self.to_dict()
        data['raw_log'] = self.raw_log
        return data