from flask import render_template, request, jsonify, redirect, url_for, flash
from app import app, threat_storage
from threat_detector import scan_log_for_threats
import logging
import html

@app.route('/')
def index():
    """Render the main dashboard"""
    threats = threat_storage.get_all_threats()
    return render_template('index.html', threats=threats)

@app.route('/upload', methods=['POST'])
def upload_log():
    """Handle log upload from form or API"""
    # Check if request is from form or API
    if request.content_type and 'application/json' in request.content_type:
        # API request
        data = request.get_json()
        if not data or 'log' not in data:
            return jsonify({'status': 'error', 'message': 'No log data provided'}), 400
        
        log_data = data['log']
    else:
        # Form submission
        log_data = request.form.get('log_data')
        if not log_data:
            flash('No log data provided', 'danger')
            return redirect(url_for('index'))

    # Sanitize input to prevent XSS (for display purposes)
    sanitized_log = html.escape(log_data)
    
    # Scan for threats
    detected_keywords = scan_log_for_threats(log_data)
    
    if detected_keywords:
        # Store the threat if keywords were detected
        threat = threat_storage.add_threat(detected_keywords, sanitized_log)
        
        # Return appropriate response based on request type
        if request.content_type and 'application/json' in request.content_type:
            return jsonify({
                'status': 'threat_detected', 
                'details': {
                    'id': threat['id'],
                    'timestamp': threat['timestamp'].isoformat(),
                    'keywords': threat['detected_keywords']
                }
            })
        else:
            flash('Threat detected! The log has been added to the threats list.', 'danger')
            return redirect(url_for('index'))
    else:
        # No threats found
        if request.content_type and 'application/json' in request.content_type:
            return jsonify({'status': 'clean', 'message': 'No threats found.'})
        else:
            flash('Log analyzed - No threats detected.', 'success')
            return redirect(url_for('index'))

@app.route('/api/threats', methods=['GET'])
def get_threats_api():
    """API endpoint to retrieve all threats"""
    threats = threat_storage.get_all_threats()
    
    # Format data for API response
    response = []
    for threat in threats:
        response.append({
            'id': threat['id'],
            'timestamp': threat['timestamp'].isoformat(),
            'detected_keywords': threat['detected_keywords'],
            # Don't include raw log in list view to reduce payload size
        })
    
    return jsonify(response)

@app.route('/view_log/<int:threat_id>')
def view_log(threat_id):
    """View the full log for a specific threat"""
    threat = threat_storage.get_threat_by_id(threat_id)
    
    if not threat:
        flash('Threat not found', 'danger')
        return redirect(url_for('index'))
    
    return render_template('view_log.html', threat=threat)

@app.route('/api/threat/<int:threat_id>', methods=['GET'])
def get_threat_api(threat_id):
    """API endpoint to retrieve a specific threat"""
    threat = threat_storage.get_threat_by_id(threat_id)
    
    if not threat:
        return jsonify({'status': 'error', 'message': 'Threat not found'}), 404
    
    return jsonify({
        'id': threat['id'],
        'timestamp': threat['timestamp'].isoformat(),
        'detected_keywords': threat['detected_keywords'],
        'raw_log': threat['raw_log']
    })
