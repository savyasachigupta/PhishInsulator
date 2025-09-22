"""
PhishInsulator AI - Main API Implementation
Multilingual AI-enabled phishing detection with multi-node checking
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import logging
import asyncio
import time
from typing import Dict, List, Any
from concurrent.futures import ThreadPoolExecutor
import os
import sys

# Import our custom nodes
from url_analysis_node import URLAnalysisNode
from text_content_node import TextContentNode
from decision_fusion import DecisionFusion

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing

# Initialize AI components
url_analyzer = URLAnalysisNode()
text_analyzer = TextContentNode()
# In production, you would also initialize metadata and behavioral nodes
fusion_engine = DecisionFusion()

# Thread pool for concurrent processing
executor = ThreadPoolExecutor(max_workers=4)

class PhishInsulatorAPI:
    """Main API class for PhishInsulator AI system"""
    
    def __init__(self):
        self.stats = {
            'total_requests': 0,
            'phishing_detected': 0,
            'legitimate_detected': 0,
            'average_response_time': 0.0
        }
    
    def analyze_content(self, content: str, language: str = 'auto', 
                       analysis_type: str = 'comprehensive') -> Dict[str, Any]:
        """
        Analyze content for phishing indicators
        
        Args:
            content: Text content or URL to analyze
            language: Target language for analysis ('auto' for detection)
            analysis_type: Type of analysis ('quick', 'comprehensive')
        
        Returns:
            Analysis results with confidence scores and recommendations
        """
        start_time = time.time()
        
        try:
            # Update stats
            self.stats['total_requests'] += 1
            
            # Determine if content is URL or text
            is_url = self._is_url(content)
            
            # Collect node results
            node_results = []
            
            if is_url:
                # Analyze URL
                url_result = url_analyzer.analyze(content)
                if 'error' not in url_result:
                    node_results.append(url_result)
            
            # Always analyze text content
            text_result = text_analyzer.analyze(content)
            if 'error' not in text_result:
                node_results.append(text_result)
            
            # For comprehensive analysis, we would add more nodes here
            if analysis_type == 'comprehensive':
                # Placeholder for metadata and behavioral analysis
                # In production, these would be real implementations
                node_results.extend([
                    {
                        'node': 'metadata_analysis',
                        'confidence': 0.3,  # Simulated
                        'indicators': ['Simulated metadata analysis']
                    },
                    {
                        'node': 'behavioral_analysis', 
                        'confidence': 0.4,  # Simulated
                        'indicators': ['Simulated behavioral analysis']
                    }
                ])
            
            # Fuse decisions
            fusion_result = fusion_engine.fuse_decisions(node_results)
            
            # Update statistics
            processing_time = time.time() - start_time
            self._update_stats(fusion_result, processing_time)
            
            # Add metadata to result
            fusion_result['metadata'] = {
                'processing_time_seconds': processing_time,
                'analysis_type': analysis_type,
                'content_type': 'url' if is_url else 'text',
                'language_detected': text_result.get('language', 'unknown'),
                'api_version': '1.0'
            }
            
            return fusion_result
            
        except Exception as e:
            logger.error(f"Error in analyze_content: {e}")
            return {
                'error': str(e),
                'final_score': 0.0,
                'risk_level': 'UNKNOWN',
                'analysis': {'summary': f'Analysis failed: {e}'}
            }
    
    def _is_url(self, content: str) -> bool:
        """Check if content is a URL"""
        return (content.startswith(('http://', 'https://')) or 
                content.startswith('www.') or
                ('.' in content and ' ' not in content and len(content.split()) == 1))
    
    def _update_stats(self, result: Dict[str, Any], processing_time: float):
        """Update API statistics"""
        if result.get('final_score', 0) > 0.5:
            self.stats['phishing_detected'] += 1
        else:
            self.stats['legitimate_detected'] += 1
        
        # Update average response time
        total_requests = self.stats['total_requests']
        current_avg = self.stats['average_response_time']
        self.stats['average_response_time'] = (
            (current_avg * (total_requests - 1) + processing_time) / total_requests
        )

# Initialize API instance
phish_guard = PhishInsulatorAPI()

@app.route('/')
def home():
    """Home page with API documentation"""
    return jsonify({
        'name': 'PhishInsulator AI API',
        'version': '1.0.0',
        'description': 'Multilingual AI-enabled phishing detection with multi-node checking',
        'features': [
            'Multilingual support (English, Hindi, Arabic, Spanish, French)',
            'Multi-node analysis (URL, Text, Metadata, Behavioral)',
            'Real-time processing',
            'Ensemble decision fusion',
            'Adaptive learning'
        ],
        'endpoints': {
            '/api/analyze': 'POST - Analyze content for phishing',
            '/api/batch': 'POST - Batch analysis of multiple items',
            '/api/stats': 'GET - API usage statistics',
            '/api/health': 'GET - Health check'
        }
    })

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Main analysis endpoint"""
    try:
        data = request.get_json()
        
        if not data or 'content' not in data:
            return jsonify({
                'error': 'Missing required field: content'
            }), 400
        
        content = data['content']
        language = data.get('language', 'auto')
        analysis_type = data.get('analysis_type', 'comprehensive')
        
        # Validate inputs
        if not content.strip():
            return jsonify({
                'error': 'Content cannot be empty'
            }), 400
        
        if len(content) > 10000:
            return jsonify({
                'error': 'Content too long (max 10,000 characters)'
            }), 400
        
        # Perform analysis
        result = phish_guard.analyze_content(
            content=content,
            language=language,
            analysis_type=analysis_type
        )
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in analyze endpoint: {e}")
        return jsonify({
            'error': f'Internal server error: {str(e)}'
        }), 500

@app.route('/api/batch', methods=['POST'])
def batch_analyze():
    """Batch analysis endpoint for multiple items"""
    try:
        data = request.get_json()
        
        if not data or 'items' not in data:
            return jsonify({
                'error': 'Missing required field: items'
            }), 400
        
        items = data['items']
        
        if not isinstance(items, list):
            return jsonify({
                'error': 'Items must be a list'
            }), 400
        
        if len(items) > 50:
            return jsonify({
                'error': 'Too many items (max 50 per batch)'
            }), 400
        
        # Process items in parallel
        results = []
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            
            for i, item in enumerate(items):
                if isinstance(item, str):
                    content = item
                    language = 'auto'
                    analysis_type = 'comprehensive'
                elif isinstance(item, dict):
                    content = item.get('content', '')
                    language = item.get('language', 'auto')
                    analysis_type = item.get('analysis_type', 'comprehensive')
                else:
                    results.append({
                        'index': i,
                        'error': 'Invalid item format'
                    })
                    continue
                
                future = executor.submit(
                    phish_guard.analyze_content,
                    content, language, analysis_type
                )
                futures.append((i, future))
            
            # Collect results
            for index, future in futures:
                try:
                    result = future.result(timeout=30)  # 30 second timeout
                    result['index'] = index
                    results.append(result)
                except Exception as e:
                    results.append({
                        'index': index,
                        'error': str(e)
                    })
        
        return jsonify({
            'batch_results': results,
            'total_processed': len(results),
            'success_count': len([r for r in results if 'error' not in r])
        })
        
    except Exception as e:
        logger.error(f"Error in batch analyze endpoint: {e}")
        return jsonify({
            'error': f'Internal server error: {str(e)}'
        }), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get API usage statistics"""
    try:
        stats = phish_guard.stats.copy()
        fusion_stats = fusion_engine.get_performance_stats()
        
        return jsonify({
            'api_stats': stats,
            'fusion_engine_stats': fusion_stats,
            'system_info': {
                'python_version': sys.version,
                'total_nodes_available': 4,
                'active_nodes': 2  # URL and Text nodes are active
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({
            'error': f'Failed to retrieve stats: {str(e)}'
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Test each component
        health_status = {
            'status': 'healthy',
            'timestamp': time.time(),
            'components': {
                'url_analyzer': 'healthy',
                'text_analyzer': 'healthy', 
                'fusion_engine': 'healthy'
            }
        }
        
        # Quick test of URL analyzer
        try:
            test_url_result = url_analyzer.analyze('http://example.com')
            if 'error' in test_url_result:
                health_status['components']['url_analyzer'] = 'unhealthy'
                health_status['status'] = 'degraded'
        except:
            health_status['components']['url_analyzer'] = 'unhealthy'
            health_status['status'] = 'degraded'
        
        # Quick test of text analyzer
        try:
            test_text_result = text_analyzer.analyze('Hello world')
            if 'error' in test_text_result:
                health_status['components']['text_analyzer'] = 'unhealthy'
                health_status['status'] = 'degraded'
        except:
            health_status['components']['text_analyzer'] = 'unhealthy'
            health_status['status'] = 'degraded'
        
        status_code = 200 if health_status['status'] == 'healthy' else 503
        return jsonify(health_status), status_code
        
    except Exception as e:
        logger.error(f"Error in health check: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 503

@app.route('/api/feedback', methods=['POST'])
def submit_feedback():
    """Submit feedback for model improvement"""
    try:
        data = request.get_json()
        
        required_fields = ['content', 'predicted_result', 'actual_result']
        if not all(field in data for field in required_fields):
            return jsonify({
                'error': f'Missing required fields: {required_fields}'
            }), 400
        
        # Process feedback (in production, store in database)
        feedback = {
            'content': data['content'],
            'predicted_result': data['predicted_result'],
            'actual_result': data['actual_result'],
            'timestamp': time.time(),
            'user_id': data.get('user_id', 'anonymous')
        }
        
        # Update fusion engine with feedback
        fusion_engine.update_weights({
            'actual_result': data['actual_result'],
            'node_results': []  # Would include node results from original analysis
        })
        
        logger.info(f"Feedback received: {feedback}")
        
        return jsonify({
            'message': 'Feedback received successfully',
            'status': 'ok'
        })
        
    except Exception as e:
        logger.error(f"Error processing feedback: {e}")
        return jsonify({
            'error': f'Failed to process feedback: {str(e)}'
        }), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint not found',
        'message': 'Please check the API documentation at /'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'error': 'Internal server error',
        'message': 'Something went wrong. Please try again later.'
    }), 500

if __name__ == '__main__':
    # Load any saved state
    try:
        fusion_engine.load_state('fusion_state.json')
    except:
        logger.info("No saved state found, starting fresh")
    
    # Start the API server
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    logger.info(f"Starting PhishInsulator AI API server on port {port}")
    logger.info(f"Debug mode: {debug}")
    
    try:
        app.run(host='0.0.0.0', port=port, debug=debug)
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    finally:
        # Save state before shutdown
        try:
            fusion_engine.save_state('fusion_state.json')
            logger.info("State saved successfully")
        except Exception as e:
            logger.error(f"Failed to save state: {e}")
