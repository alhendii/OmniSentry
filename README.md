# OmniSentry - Endpoint Threat Detection Dashboard

## Description

OmniSentry is a minimalist cybersecurity dashboard designed for monitoring and detecting endpoint threats. It provides a streamlined interface for analyzing security threats in system logs using pattern matching and NLP-based techniques, without relying on external AI services.

## Features

- **NLP-based Threat Detection**: Analyzes log data using pattern matching and keyword scoring to identify security threats
- **Responsive Dashboard**: Clean, minimalist UI with intuitive severity color coding (red, yellow, green)
- **Multiple Input Methods**: Support for manual log uploads via file or text paste, and simulated agent feeds
- **Real-time Analysis**: Immediate threat assessment with detailed categorization and scoring
- **Comprehensive Filtering**: Filter threats by severity level, keywords, or categories
- **Detailed Threat Views**: In-depth analysis of each detected threat with raw logs and security implications
- **RESTful API**: Simple API endpoints for integration with other security tools
- **Complete Documentation**: Includes comprehensive PDF documentation explaining all functionalities

## Technical Details

- Built with Flask and PostgreSQL for a robust, scalable backend
- Responsive frontend with clean, contextual UI design
- Detection logic based on pattern recognition and keyword frequency analysis
- Categorizes threats into types such as command execution, credential theft, and privilege escalation
- Includes PDF documentation generator for complete system explanation

## Use Cases

- Security analysts monitoring endpoint threats in small to medium environments
- Organizations requiring lightweight, privacy-focused security monitoring
- Environments with limited connectivity where cloud-based security solutions aren't feasible
- Educational environments for learning about threat detection patterns and techniques

## Getting Started

1. Clone the repository
2. Install dependencies with `pip install -r requirements.txt`
3. Start the application with `python main.py`
4. Access the dashboard at `http://localhost:5000`
5. Upload log files or paste log data to begin threat analysis

## License

[Your preferred license here]