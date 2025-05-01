from flask import render_template, request, jsonify, redirect, url_for, flash
from app import app, db
from models import Threat
from threat_detector import scan_log_for_threats
from ai_analyzer import analyze_log_with_ai, calculate_threat_level
import logging
import html

logger = logging.getLogger(__name__)

@app.route('/')
def index():
    """Render the main dashboard"""
    # Get threats from database
    threats = Threat.query.order_by(Threat.timestamp.desc()).all()
    return render_template('index.html', threats=threats)

@app.route('/upload', methods=['POST'])
def upload_log():
    """Handle log upload from form or API"""
    # Check if request is from form or API
    source = "api" if request.content_type and 'application/json' in request.content_type else "manual_upload"
    
    if source == "api":
        # API request
        data = request.get_json()
        if not data or 'log' not in data:
            return jsonify({'status': 'error', 'message': 'No log data provided'}), 400
        
        log_data = data['log']
        source_name = data.get('source', 'api')
    else:
        # Form submission
        log_data = request.form.get('log_data')
        if not log_data:
            flash('No log data provided', 'danger')
            return redirect(url_for('index'))
        source_name = "manual_upload"

    # Sanitize input to prevent XSS (for display purposes)
    sanitized_log = html.escape(log_data)
    
    # Scan for threats
    detected_keywords = scan_log_for_threats(log_data)
    
    if detected_keywords:
        # Calculate threat level
        threat_level = calculate_threat_level(detected_keywords, log_data)
        
        # Create new threat
        new_threat = Threat(
            raw_log=sanitized_log,
            threat_level=threat_level,
            source=source_name
        )
        new_threat.set_detected_keywords(detected_keywords)
        
        # Perform AI analysis if keyword detected and OPENAI_API_KEY is configured
        try:
            ai_analysis = analyze_log_with_ai(log_data, detected_keywords)
            if ai_analysis:
                new_threat.ai_summary = ai_analysis.get('summary')
                new_threat.set_ai_recommendations(ai_analysis.get('recommendations', []))
                
                # Use AI's threat level if available
                if ai_analysis.get('threat_level'):
                    new_threat.threat_level = ai_analysis.get('threat_level')
        except Exception as e:
            logger.error(f"AI analysis failed: {str(e)}")
        
        # Save to database
        db.session.add(new_threat)
        db.session.commit()
        
        # Return appropriate response based on request type
        if source == "api":
            return jsonify({
                'status': 'threat_detected', 
                'details': new_threat.to_dict()
            })
        else:
            flash(f'Threat detected! The log has been added to the threats list with level: {threat_level}', 'danger')
            return redirect(url_for('index'))
    else:
        # No threats found
        if source == "api":
            return jsonify({'status': 'clean', 'message': 'No threats found.'})
        else:
            flash('Log analyzed - No threats detected.', 'success')
            return redirect(url_for('index'))

@app.route('/api/threats', methods=['GET'])
def get_threats_api():
    """API endpoint to retrieve all threats"""
    threats = Threat.query.order_by(Threat.timestamp.desc()).all()
    return jsonify([threat.to_dict() for threat in threats])

@app.route('/view_log/<int:threat_id>')
def view_log(threat_id):
    """View the full log for a specific threat"""
    threat = Threat.query.get(threat_id)
    
    if not threat:
        flash('Threat not found', 'danger')
        return redirect(url_for('index'))
    
    return render_template('view_log.html', threat=threat)

@app.route('/api/threat/<int:threat_id>', methods=['GET'])
def get_threat_api(threat_id):
    """API endpoint to retrieve a specific threat"""
    threat = Threat.query.get(threat_id)
    
    if not threat:
        return jsonify({'status': 'error', 'message': 'Threat not found'}), 404
    
    return jsonify(threat.to_detail_dict())

@app.route('/upload_file', methods=['POST'])
def upload_file():
    """Handle file uploads"""
    if 'log_file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('index'))
        
    file = request.files['log_file']
    
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('index'))
        
    if file:
        # Read the file contents
        log_data = file.read().decode('utf-8', errors='ignore')
        
        # Sanitize input
        sanitized_log = html.escape(log_data)
        
        # Scan for threats
        detected_keywords = scan_log_for_threats(log_data)
        
        if detected_keywords:
            # Calculate threat level
            threat_level = calculate_threat_level(detected_keywords, log_data)
            
            # Create new threat
            new_threat = Threat(
                raw_log=sanitized_log,
                threat_level=threat_level,
                source=f"file_upload:{file.filename}"
            )
            new_threat.set_detected_keywords(detected_keywords)
            
            # Perform AI analysis
            try:
                ai_analysis = analyze_log_with_ai(log_data, detected_keywords)
                if ai_analysis:
                    new_threat.ai_summary = ai_analysis.get('summary')
                    new_threat.set_ai_recommendations(ai_analysis.get('recommendations', []))
                    
                    # Use AI's threat level if available
                    if ai_analysis.get('threat_level'):
                        new_threat.threat_level = ai_analysis.get('threat_level')
            except Exception as e:
                logger.error(f"AI analysis failed: {str(e)}")
            
            # Save to database
            db.session.add(new_threat)
            db.session.commit()
            
            flash(f'Threat detected in file! The log has been added with level: {threat_level}', 'danger')
        else:
            flash('File analyzed - No threats detected.', 'success')
        
        return redirect(url_for('index'))

@app.route('/filter_threats', methods=['GET'])
def filter_threats():
    """Filter threats by level or keyword"""
    level = request.args.get('level')
    keyword = request.args.get('keyword')
    
    query = Threat.query
    
    if level and level != 'All':
        query = query.filter(Threat.threat_level == level)
        
    if keyword:
        # This is a simple implementation - for production, consider a more efficient solution
        threats = query.all()
        filtered_threats = [t for t in threats if keyword.lower() in t.get_detected_keywords() or keyword.lower() in t.raw_log.lower()]
        return render_template('index.html', threats=filtered_threats, filter_active=True)
    
    threats = query.order_by(Threat.timestamp.desc()).all()
    return render_template('index.html', threats=threats, filter_active=True)
