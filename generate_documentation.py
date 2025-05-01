import os
from datetime import datetime
from fpdf import FPDF

class ThreatWatchDocumentation:
    def __init__(self):
        self.pdf = FPDF()
        self.pdf.set_auto_page_break(auto=True, margin=15)
        
    def add_title_page(self):
        """Create the title page for the documentation"""
        self.pdf.add_page()
        self.pdf.set_font("Arial", "B", 24)
        self.pdf.cell(0, 20, "ThreatWatch Lite", ln=True, align="C")
        self.pdf.ln(10)
        self.pdf.set_font("Arial", "B", 16)
        self.pdf.cell(0, 10, "Endpoint Threat Detection Dashboard", ln=True, align="C")
        self.pdf.ln(10)
        self.pdf.set_font("Arial", "", 12)
        self.pdf.cell(0, 10, f"Documentation generated on: {datetime.now().strftime('%Y-%m-%d')}", ln=True, align="C")
        self.pdf.ln(20)
        
        # Add mini description
        self.pdf.set_font("Arial", "I", 12)
        self.pdf.multi_cell(0, 10, "ThreatWatch Lite is a minimalist security dashboard designed for monitoring endpoint threats. It uses pattern matching and NLP-based analysis to detect potential security issues in log files.")
        
    def add_toc(self):
        """Add table of contents"""
        self.pdf.add_page()
        self.pdf.set_font("Arial", "B", 16)
        self.pdf.cell(0, 10, "Table of Contents", ln=True)
        self.pdf.ln(5)
        
        self.pdf.set_font("Arial", "", 12)
        toc_items = [
            ("1. Introduction", 3),
            ("2. Dashboard Overview", 4),
            ("3. Log Upload Functionality", 5),
            ("4. Threat Analysis & Detection", 6),
            ("5. Detailed Threat View", 7),
            ("6. Filtering & Categorization", 8),
            ("7. API Integration", 9),
            ("8. Technical Architecture", 10)
        ]
        
        for item, page in toc_items:
            self.pdf.cell(0, 10, f"{item}", ln=True)
            
    def add_introduction(self):
        """Add introduction section"""
        self.pdf.add_page()
        self.pdf.set_font("Arial", "B", 16)
        self.pdf.cell(0, 10, "1. Introduction", ln=True)
        self.pdf.ln(5)
        
        content = [
            "ThreatWatch Lite is a cybersecurity dashboard focused on endpoint threat detection. It provides a streamlined, minimalist interface for monitoring and analyzing security threats detected in system logs.",
            "",
            "Key Features:",
            "• NLP-based threat detection using pattern matching and keyword analysis",
            "• Real-time threat scoring and categorization",
            "• Support for manual log uploads and simulated agent feeds",
            "• Detailed threat analysis with remediation suggestions",
            "• API endpoints for integration with other security tools",
            "",
            "This application focuses on a lightweight, pattern-matching approach to threat detection rather than using external AI services, making it suitable for environments with limited connectivity or privacy requirements."
        ]
        
        self.pdf.set_font("Arial", "", 12)
        for line in content:
            if line == "":
                self.pdf.ln(5)
            else:
                self.pdf.multi_cell(0, 10, line)
    
    def add_screenshot_placeholder(self, caption):
        """Add a placeholder for a screenshot with caption"""
        self.pdf.set_font("Arial", "I", 10)
        self.pdf.cell(0, 10, f"[Screenshot: {caption}]", ln=True, align="C")
        self.pdf.ln(10)
    
    def add_dashboard_overview(self):
        """Add dashboard overview section with screenshot"""
        self.pdf.add_page()
        self.pdf.set_font("Arial", "B", 16)
        self.pdf.cell(0, 10, "2. Dashboard Overview", ln=True)
        self.pdf.ln(5)
        
        self.pdf.set_font("Arial", "", 12)
        overview_text = "The main dashboard provides an at-a-glance view of all detected threats, organized by severity level (High, Medium, Low). The interface uses a minimalist design with contextual colors to highlight critical information."
        self.pdf.multi_cell(0, 10, overview_text)
        self.pdf.ln(5)
        
        # Add dashboard screenshot placeholder
        self.add_screenshot_placeholder("Fig 1: ThreatWatch Lite Dashboard")
        
        # Explain the interface elements
        self.pdf.set_font("Arial", "", 12)
        interface_elements = [
            "Dashboard Components:",
            "• Threat Table: Displays all detected threats with severity, categories, and detected keywords",
            "• Upload Panel: Allows users to submit log files for analysis or paste raw log content",
            "• Quick Filters: Enables filtering by threat level, keywords, or categories",
            "• API Endpoints: Documentation for integrating with the system programmatically",
            "",
            "Color Coding:",
            "• Red: High severity threats that require immediate attention",
            "• Yellow: Medium severity threats that should be investigated",
            "• Green: Low severity threats that are less urgent"
        ]
        
        for element in interface_elements:
            if element == "":
                self.pdf.ln(5)
            else:
                self.pdf.multi_cell(0, 10, element)
    
    def add_log_upload_section(self):
        """Add log upload functionality section with screenshot"""
        self.pdf.add_page()
        self.pdf.set_font("Arial", "B", 16)
        self.pdf.cell(0, 10, "3. Log Upload Functionality", ln=True)
        self.pdf.ln(5)
        
        self.pdf.set_font("Arial", "", 12)
        upload_text = "ThreatWatch Lite supports two methods for submitting log data: direct file upload or pasting raw log content. Both methods trigger the same analysis pipeline."
        self.pdf.multi_cell(0, 10, upload_text)
        self.pdf.ln(5)
        
        # Add upload form screenshot placeholder
        self.add_screenshot_placeholder("Fig 2: Log Upload Interface")
        
        # Explain upload methods
        self.pdf.set_font("Arial", "", 12)
        upload_details = [
            "Upload Methods:",
            "• File Upload: Accepts .log and .txt files containing system or application logs",
            "• Text Input: Allows pasting raw log content directly into the text area",
            "• API Submission: Logs can be submitted programmatically via the /upload endpoint",
            "",
            "Supported Sources:",
            "• Manual uploads from security analysts",
            "• Simulated agent feeds (for testing/demonstration)",
            "• Potential integration with real endpoint agents"
        ]
        
        for detail in upload_details:
            if detail == "":
                self.pdf.ln(5)
            else:
                self.pdf.multi_cell(0, 10, detail)
    
    def add_threat_analysis_section(self):
        """Add threat analysis & detection section"""
        self.pdf.add_page()
        self.pdf.set_font("Arial", "B", 16)
        self.pdf.cell(0, 10, "4. Threat Analysis & Detection", ln=True)
        self.pdf.ln(5)
        
        self.pdf.set_font("Arial", "", 12)
        analysis_text = "ThreatWatch Lite uses a combination of pattern matching, keyword detection, and contextual analysis to identify potential security threats in log data."
        self.pdf.multi_cell(0, 10, analysis_text)
        self.pdf.ln(5)
        
        # Explain detection methodology
        detection_details = [
            "Detection Process:",
            "1. Log Scanning: Each log is scanned for known threat patterns and suspicious keywords",
            "2. Pattern Matching: Detected patterns are matched against a database of known threats",
            "3. Contextual Analysis: The system analyzes surrounding context to improve detection accuracy",
            "4. Threat Scoring: A numerical score is calculated based on the severity and number of detected patterns",
            "5. Categorization: Threats are categorized into types (e.g., command_execution, credential_theft)",
            "",
            "NLP Techniques Used:",
            "• Keyword frequency analysis",
            "• Pattern recognition for command structures",
            "• Contextual indicators (unusual time patterns, repeated failures)",
            "• Correlation between multiple suspicious activities"
        ]
        
        for detail in detection_details:
            if detail == "":
                self.pdf.ln(5)
            else:
                self.pdf.multi_cell(0, 10, detail)
    
    def add_detailed_threat_view(self):
        """Add detailed threat view section with screenshot"""
        self.pdf.add_page()
        self.pdf.set_font("Arial", "B", 16)
        self.pdf.cell(0, 10, "5. Detailed Threat View", ln=True)
        self.pdf.ln(5)
        
        self.pdf.set_font("Arial", "", 12)
        detail_text = "When a threat is detected, users can access a detailed view that provides comprehensive information about the threat, including raw logs, detected patterns, and potential security implications."
        self.pdf.multi_cell(0, 10, detail_text)
        self.pdf.ln(5)
        
        # Add detail view screenshot placeholder
        self.add_screenshot_placeholder("Fig 3: Detailed Threat Analysis View")
        
        # Explain components of the detailed view
        detail_components = [
            "Detailed View Components:",
            "• Threat Summary: ID, timestamp, source, and severity level",
            "• Detected Keywords: Specific suspicious patterns found in the log",
            "• Threat Categories: Types of security threats identified",
            "• Raw Log Display: Complete log entry with highlighted suspicious elements",
            "• Security Advisory: Potential impact and recommended actions",
            "• MITRE ATT&CK Mapping: Correlation with known attack techniques"
        ]
        
        for component in detail_components:
            self.pdf.multi_cell(0, 10, component)
    
    def add_filtering_section(self):
        """Add filtering & categorization section"""
        self.pdf.add_page()
        self.pdf.set_font("Arial", "B", 16)
        self.pdf.cell(0, 10, "6. Filtering & Categorization", ln=True)
        self.pdf.ln(5)
        
        self.pdf.set_font("Arial", "", 12)
        filter_text = "ThreatWatch Lite provides robust filtering capabilities to help security analysts focus on the most relevant threats and patterns."
        self.pdf.multi_cell(0, 10, filter_text)
        self.pdf.ln(5)
        
        # Add filter section screenshot placeholder
        self.add_screenshot_placeholder("Fig 4: Threat Filtering Interface")
        
        # Explain filtering options
        filter_options = [
            "Filtering Capabilities:",
            "• By Severity Level: Filter to show only High, Medium, or Low threats",
            "• By Keyword: Search for specific suspicious commands or patterns",
            "• By Category: Filter by threat categories (e.g., 'command_execution', 'credential_theft')",
            "• Time-based: Focus on recent threats (most recent shown at the top)",
            "",
            "Categorization System:",
            "ThreatWatch Lite automatically categorizes threats into groups that help analysts understand the nature of potential attacks:",
            "",
            "• command_execution: Suspicious command or script execution",
            "• credential_theft: Attempts to access or steal authentication credentials",
            "• remote_access: Unusual remote access attempts or patterns",
            "• privilege_escalation: Attempts to gain higher privileges",
            "• data_exfiltration: Potential data theft or unauthorized transfers",
            "• persistence: Actions that maintain presence on compromised systems"
        ]
        
        for option in filter_options:
            if option == "":
                self.pdf.ln(5)
            else:
                self.pdf.multi_cell(0, 10, option)
    
    def add_api_section(self):
        """Add API integration section"""
        self.pdf.add_page()
        self.pdf.set_font("Arial", "B", 16)
        self.pdf.cell(0, 10, "7. API Integration", ln=True)
        self.pdf.ln(5)
        
        self.pdf.set_font("Arial", "", 12)
        api_text = "ThreatWatch Lite provides a simple RESTful API that enables integration with other security tools and automation workflows."
        self.pdf.multi_cell(0, 10, api_text)
        self.pdf.ln(5)
        
        # List and explain API endpoints
        api_endpoints = [
            "Available Endpoints:",
            "",
            "1. POST /upload",
            "   Purpose: Submit log data for analysis",
            "   Payload: {\"log\": \"log data here\", \"source\": \"endpoint_name\"}",
            "   Response: JSON object with threat details if detected",
            "",
            "2. GET /api/threats",
            "   Purpose: Retrieve all detected threats",
            "   Parameters: None",
            "   Response: JSON array of all threat objects",
            "",
            "3. GET /api/threat/:id",
            "   Purpose: Get detailed information about a specific threat",
            "   Parameters: Threat ID in URL",
            "   Response: JSON object with complete threat details",
            "",
            "4. GET /filter_threats",
            "   Purpose: Filter threats by level or keyword",
            "   Parameters: ?level=High&keyword=powershell&category=command_execution",
            "   Response: JSON array of matching threat objects"
        ]
        
        for endpoint in api_endpoints:
            if endpoint == "":
                self.pdf.ln(5)
            else:
                self.pdf.multi_cell(0, 10, endpoint)
    
    def add_technical_architecture(self):
        """Add technical architecture section"""
        self.pdf.add_page()
        self.pdf.set_font("Arial", "B", 16)
        self.pdf.cell(0, 10, "8. Technical Architecture", ln=True)
        self.pdf.ln(5)
        
        self.pdf.set_font("Arial", "", 12)
        arch_text = "ThreatWatch Lite is built with a modular architecture that separates concerns and allows for easy extension and maintenance."
        self.pdf.multi_cell(0, 10, arch_text)
        self.pdf.ln(5)
        
        # Explain architecture components
        architecture = [
            "Component Architecture:",
            "",
            "1. Flask Web Application (main.py, app.py, routes.py)",
            "   • Handles HTTP requests and routes",
            "   • Manages sessions and user interface",
            "   • Processes form submissions and API calls",
            "",
            "2. Database Layer (models.py)",
            "   • SQLAlchemy ORM for database interactions",
            "   • Threat model for storing detected threats",
            "   • JSON serialization for API responses",
            "",
            "3. Threat Detection Engine (threat_detector.py)",
            "   • Pattern matching and keyword detection",
            "   • Threat scoring algorithm",
            "   • Category mapping logic",
            "",
            "4. NLP Analysis Module (nlp_analyzer.py)",
            "   • Text analysis for threat context",
            "   • Indicator extraction from log content",
            "   • Severity calculation based on patterns",
            "",
            "5. Frontend (templates/, static/)",
            "   • Responsive Bootstrap-based interface",
            "   • Client-side filtering and sorting",
            "   • Interactive threat visualization"
        ]
        
        for line in architecture:
            if line == "":
                self.pdf.ln(5)
            else:
                self.pdf.multi_cell(0, 10, line)
    
    def generate_pdf(self):
        """Generate the complete PDF documentation"""
        # Add all sections
        self.add_title_page()
        self.add_toc()
        self.add_introduction()
        self.add_dashboard_overview()
        self.add_log_upload_section()
        self.add_threat_analysis_section()
        self.add_detailed_threat_view()
        self.add_filtering_section()
        self.add_api_section()
        self.add_technical_architecture()
        
        # Save PDF
        pdf_path = "ThreatWatch_Lite_Documentation.pdf"
        self.pdf.output(pdf_path)
        print(f"Documentation generated: {pdf_path}")
        
        # No need to close webdriver since we're not using Selenium
        
        return pdf_path

if __name__ == "__main__":
    try:
        print("Generating ThreatWatch Lite documentation...")
        doc = ThreatWatchDocumentation()
        pdf_path = doc.generate_pdf()
        print(f"Documentation saved to: {pdf_path}")
    except Exception as e:
        print(f"Error generating documentation: {e}")