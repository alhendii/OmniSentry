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
    ai_summary = db.Column(db.Text, nullable=True)
    ai_recommendations = db.Column(db.Text, nullable=True)  # Stored as JSON string
    source = db.Column(db.String(100), default="manual_upload")  # manual_upload, agent, etc.
    
    def set_detected_keywords(self, keywords_list):
        self.detected_keywords = json.dumps(keywords_list)
        
    def get_detected_keywords(self):
        if not self.detected_keywords:
            return []
        return json.loads(self.detected_keywords)
        
    def set_ai_recommendations(self, recommendations_list):
        self.ai_recommendations = json.dumps(recommendations_list)
        
    def get_ai_recommendations(self):
        if not self.ai_recommendations:
            return []
        return json.loads(self.ai_recommendations)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'detected_keywords': self.get_detected_keywords(),
            'threat_level': self.threat_level,
            'ai_summary': self.ai_summary,
            'ai_recommendations': self.get_ai_recommendations(),
            'source': self.source
        }
        
    def to_detail_dict(self):
        """Return dictionary with additional raw log data"""
        data = self.to_dict()
        data['raw_log'] = self.raw_log
        return data