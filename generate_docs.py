
from fpdf import FPDF
import os

class ThreatWatchDocs(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'ThreatWatch Lite Documentation', 0, 1, 'C')
        self.ln(10)

def generate_documentation():
    pdf = ThreatWatchDocs()
    pdf.add_page()
    
    # Title and Introduction
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, 'ThreatWatch Lite', 0, 1, 'C')
    pdf.ln(10)
    
    pdf.set_font('Arial', '', 12)
    pdf.multi_cell(0, 10, "ThreatWatch Lite is a security monitoring dashboard designed for endpoint threat detection and analysis. The application provides real-time monitoring of security logs, intelligent threat detection, and detailed analysis of potential security incidents.")
    
    # Core Features
    pdf.ln(10)
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, 'Core Features:', 0, 1)
    
    features = [
        "Real-time Log Analysis - Monitors and analyzes security logs in real-time",
        "NLP-powered Detection - Uses Natural Language Processing for threat detection",
        "Threat Categorization - Automatically categorizes threats by severity",
        "Interactive Dashboard - Provides clear security status overview",
        "Detailed Logging - Maintains comprehensive threat logs",
        "Smart Filtering - Filter threats by level and categories",
        "RESTful API - Full API support for integration with other tools",
        "Responsive Design - Mobile-friendly interface"
    ]
    
    pdf.set_font('Arial', '', 12)
    for feature in features:
        pdf.cell(0, 10, '• ' + feature, 0, 1)
    
    # Technical Stack
    pdf.ln(10)
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, 'Technical Stack:', 0, 1)
    
    tech_stack = [
        "Backend: Flask (Python)",
        "Database: SQLAlchemy with PostgreSQL",
        "Frontend: Bootstrap with custom CSS",
        "NLP Analysis: Custom implementation",
        "Authentication: Flask-Login",
        "Deployment: Gunicorn WSGI server"
    ]
    
    pdf.set_font('Arial', '', 12)
    for tech in tech_stack:
        pdf.cell(0, 10, '• ' + tech, 0, 1)

    # API Endpoints
    pdf.ln(10)
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, 'API Endpoints:', 0, 1)

    endpoints = [
        ("/upload [POST] - Upload log data in JSON format"),
        ("/api/threats [GET] - Retrieve all detected threats"),
        ("/api/threat/:id [GET] - View specific threat details"),
        ("/filter_threats [GET] - Filter threats by level/keyword")
    ]

    pdf.set_font('Arial', '', 12)
    for endpoint in endpoints:
        pdf.cell(0, 10, '• ' + endpoint, 0, 1)

    # Security Features
    pdf.ln(10)
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, 'Security Features:', 0, 1)

    security = [
        "Pattern-based threat detection",
        "Threat scoring system",
        "Real-time alerts",
        "Log persistence and analysis",
        "Configurable threat patterns",
        "Secure API endpoints"
    ]

    pdf.set_font('Arial', '', 12)
    for feature in security:
        pdf.cell(0, 10, '• ' + feature, 0, 1)
    
    # Save the PDF
    pdf.output('ThreatWatch_Documentation.pdf')

if __name__ == "__main__":
    generate_documentation()
