# app/blueprints/doppelganger.py
"""Blender + fuzzy-hash similarity analysis."""
import os
import re
from datetime import datetime

from flask import Blueprint, current_app, jsonify, render_template, request

from ..analyzers.blender import BlenderAnalyzer
from ..analyzers.fuzzy import FuzzyHashAnalyzer
from ..services.error_handling import error_handler
from ..utils import path_manager

_MD5_RE = re.compile(r'^[0-9a-fA-F]{32}$')

doppelganger_bp = Blueprint('doppelganger', __name__)


@doppelganger_bp.route('/doppelganger', methods=['GET', 'POST'])
@error_handler
def doppelganger():
    app = current_app
    app.logger.debug("Accessed doppelganger endpoint")

    data = None
    if request.method == 'GET':
        analysis_type = request.args.get('type', 'blender')
    else:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 415
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({'error': 'Request body must be a JSON object'}), 400
        analysis_type = data.get('type', 'blender')

    if analysis_type not in ['blender', 'fuzzy']:
        analysis_type = 'blender'

    if analysis_type == 'blender':
        analyzer = BlenderAnalyzer(app.config, logger=app.logger)
    else:
        analyzer = FuzzyHashAnalyzer(app.config, logger=app.logger)

    if request.method == 'GET':
        payload_hash = request.args.get('hash')
        if payload_hash:
            if not _MD5_RE.match(payload_hash):
                return jsonify({'error': 'hash must be an MD5'}), 400
            threshold, error = _parse_threshold(request.args.get('threshold', 1))
            if error:
                return jsonify({'error': error}), 400
            return _handle_doppelganger_hash_request(analyzer, analysis_type, payload_hash, threshold)

        if analysis_type == 'blender':
            return _handle_blender_initial_load()
        return _handle_fuzzy_initial_load(analyzer)

    operation = data.get('operation')

    if not operation:
        app.logger.error("Missing operation in request")
        return jsonify({'error': 'Operation type is required'}), 400

    app.logger.debug(f"POST request received. Operation: {operation}")

    if analysis_type == 'blender':
        return _handle_blender_operations(analyzer, operation, data)
    return _handle_fuzzy_operations(analyzer, operation, data)


def _parse_threshold(value):
    """Similarity threshold 0-100 from a query/JSON value -> (int, error)."""
    try:
        threshold = int(value)
    except (TypeError, ValueError):
        return None, 'threshold must be an integer 0-100'
    if not 0 <= threshold <= 100:
        return None, 'threshold must be an integer 0-100'
    return threshold, None


def _handle_doppelganger_hash_request(analyzer, analysis_type, payload_hash, threshold=1):
    if analysis_type == 'blender':
        comparison_result = analyzer.compare_payload(payload_hash)

        if isinstance(comparison_result, dict) and comparison_result.get("status") == "error":
            return jsonify({'error': comparison_result.get("message", "Unknown error")}), 400

        return jsonify({
            'status': 'success',
            'message': 'Comparison completed',
            'result': comparison_result,
        })

    file_path = _find_file_by_hash_for_fuzzy(payload_hash)
    if not file_path:
        return jsonify({'error': 'File not found'}), 404

    results = analyzer.analyze_files([file_path], threshold=threshold)
    return jsonify({
        'status': 'success',
        'message': 'Analysis completed successfully',
        'results': results,
    })


def _find_file_by_hash_for_fuzzy(payload_hash):
    """Uploads are stored as `<md5>_<name>`, so the shared hash index
    finds them without hashing every upload on each request."""
    if not isinstance(payload_hash, str) or not _MD5_RE.match(payload_hash):
        return None
    path = path_manager.find_file_by_hash(payload_hash, current_app.config['utils']['upload_folder'])
    return path if path and os.path.isfile(path) else None


def _handle_blender_initial_load():
    app = current_app
    result_folder = os.path.join(
        app.config['analysis']['doppelganger']['db']['path'],
        app.config['analysis']['doppelganger']['db']['blender'],
    )
    latest_report = None
    last_modified = None

    if os.path.exists(result_folder):
        files = [f for f in os.listdir(result_folder) if f.startswith("BlenderScan_")]
        if files:
            latest_file = max(
                files, key=lambda x: os.path.getmtime(os.path.join(result_folder, x)),
            )
            file_path = os.path.join(result_folder, latest_file)
            with open(file_path, 'r') as f:
                latest_report = f.read()
            last_modified = datetime.fromtimestamp(
                os.path.getmtime(file_path),
            ).strftime('%Y-%m-%d %H:%M:%S')

    return render_template(
        'doppelganger.html',
        analysis_type='blender',
        initial_data=latest_report,
        last_modified=last_modified,
    )


def _handle_fuzzy_initial_load(analyzer):
    db_stats = analyzer.get_db_stats()
    return render_template('doppelganger.html', analysis_type='fuzzy', db_stats=db_stats)


def _handle_blender_operations(analyzer, operation, data):
    if operation == 'scan':
        parsed_processes = analyzer.take_system_sample()
        return jsonify({
            'status': 'success',
            'message': 'System scan completed',
            'processes': parsed_processes,
        })
    return jsonify({'error': 'Invalid operation for blender analysis'}), 400


def _handle_fuzzy_operations(analyzer, operation, data):
    if operation == 'create_db':
        if 'folder_path' not in data:
            return jsonify({'error': 'Folder path is required'}), 400

        folder_path = data['folder_path']
        extensions = data.get('extensions', None)
        try:
            analyzer._validate_index_folder(folder_path)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400

        stats = analyzer.create_db_from_folder(folder_path, extensions)
        return jsonify({
            'status': 'success',
            'message': 'Database created successfully',
            'stats': stats,
        })

    if operation == 'analyze':
        if 'hash' not in data:
            return jsonify({'error': 'File hash is required'}), 400

        file_hash = data['hash']
        file_path = _find_file_by_hash_for_fuzzy(file_hash)

        if not file_path:
            return jsonify({'error': 'File not found'}), 404

        threshold, error = _parse_threshold(data.get('threshold', 1))
        if error:
            return jsonify({'error': error}), 400
        results = analyzer.analyze_files([file_path], threshold)

        return jsonify({
            'status': 'success',
            'message': 'Analysis completed successfully',
            'results': results,
        })

    return jsonify({'error': 'Invalid operation for fuzzy analysis'}), 400
