from fpdf import FPDF
from datetime import datetime

class ThreatWatchDocs(FPDF):
    def header(self):
        # Set header
        if self.page_no() > 1:
            self.set_font('Arial', 'I', 8)
            self.cell(0, 10, 'ThreatWatch Lite Documentation', 0, 0, 'L')
            self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'R')
            self.ln(15)

def generate_documentation():
    # Create PDF object
    pdf = ThreatWatchDocs()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # Title page
    pdf.add_page()
    pdf.set_font('Arial', 'B', 24)
    pdf.cell(0, 20, 'ThreatWatch Lite', ln=True, align='C')
    pdf.ln(10)
    
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, 'Endpoint Threat Detection Dashboard', ln=True, align='C')
    pdf.ln(10)
    
    pdf.set_font('Arial', '', 12)
    pdf.cell(0, 10, f'Documentation generated on: {datetime.now().strftime("%Y-%m-%d")}', ln=True, align='C')
    pdf.ln(20)
    
    # Description
    pdf.set_font('Arial', 'I', 12)
    pdf.multi_cell(0, 10, 'ThreatWatch Lite is a minimalist security dashboard designed for monitoring endpoint threats. It uses pattern matching and NLP-based analysis to detect potential security issues in log files.')
    
    # Table of Contents
    pdf.add_page()
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, 'Table of Contents', ln=True)
    pdf.ln(5)
    
    # Content sections
    sections = [
        '1. Introduction',
        '2. Dashboard Overview',
        '3. Log Upload Functionality',
        '4. Threat Analysis & Detection',
        '5. Detailed Threat View',
        '6. Filtering & Categorization',
        '7. API Integration',
        '8. Technical Architecture'
    ]
    
    pdf.set_font('Arial', '', 12)
    for section in sections:
        pdf.cell(0, 10, section, ln=True)
    
    # Introduction
    pdf.add_page()
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, '1. Introduction', ln=True)
    pdf.ln(5)
    
    pdf.set_font('Arial', '', 12)
    intro_text = '''ThreatWatch Lite is a cybersecurity dashboard focused on endpoint threat detection. It provides a streamlined, minimalist interface for monitoring and analyzing security threats detected in system logs.

Key Features:
- NLP-based threat detection using pattern matching and keyword analysis
- Real-time threat scoring and categorization
- Support for manual log uploads and simulated agent feeds
- Detailed threat analysis with remediation suggestions
- API endpoints for integration with other security tools

This application focuses on a lightweight, pattern-matching approach to threat detection rather than using external AI services, making it suitable for environments with limited connectivity or privacy requirements.'''
    
    for line in intro_text.split('\n'):
        pdf.multi_cell(0, 10, line)
        if not line:
            pdf.ln(5)
    
    # Additional sections would be added here following the same pattern
    
    # Dashboard Overview
    pdf.add_page()
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, '2. Dashboard Overview', ln=True)
    pdf.ln(5)
    
    pdf.set_font('Arial', '', 12)
    dashboard_text = '''The main dashboard provides an at-a-glance view of all detected threats, organized by severity level (High, Medium, Low). The interface uses a minimalist design with contextual colors to highlight critical information.

Dashboard Components:
- Threat Table: Displays all detected threats with severity, categories, and detected keywords
- Upload Panel: Allows users to submit log files for analysis or paste raw log content
- Quick Filters: Enables filtering by threat level, keywords, or categories
- API Endpoints: Documentation for integrating with the system programmatically

Color Coding:
- Red: High severity threats that require immediate attention
- Yellow: Medium severity threats that should be investigated
- Green: Low severity threats that are less urgent'''
    
    for line in dashboard_text.split('\n'):
        pdf.multi_cell(0, 10, line)
        if not line:
            pdf.ln(5)
    
    # Output the PDF
    pdf_path = 'ThreatWatch_Lite_Documentation.pdf'
    pdf.output(pdf_path)
    print(f'Documentation generated: {pdf_path}')
    return pdf_path

if __name__ == '__main__':
    try:
        print("Generating ThreatWatch Lite documentation...")
        pdf_path = generate_documentation()
        print(f"Documentation saved to: {pdf_path}")
    except Exception as e:
        print(f"Error generating documentation: {e}")