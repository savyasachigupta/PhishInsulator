"""
Decision Fusion System for PhishInsulator AI
Combines outputs from multiple specialized nodes using ensemble learning
"""

import numpy as np
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import json

class DecisionFusion:
    """
    Ensemble decision-making system that combines outputs from multiple nodes
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Node weights for ensemble voting
        self.node_weights = {
            'url_analysis': 0.30,
            'text_content': 0.40,
            'metadata_analysis': 0.20,
            'behavioral_analysis': 0.10
        }
        
        # Confidence thresholds for risk levels
        self.risk_thresholds = {
            'low': 0.3,
            'medium': 0.6,
            'high': 0.8,
            'critical': 0.9
        }
        
        # Performance tracking
        self.performance_history = []
        self.feedback_data = []
        
        # Adaptive weights (can be updated based on performance)
        self.adaptive_weights = self.node_weights.copy()
        
    def fuse_decisions(self, node_results: List[Dict[str, Any]], 
                      method: str = 'weighted_average') -> Dict[str, Any]:
        """
        Fuse decisions from multiple nodes
        
        Args:
            node_results: List of results from different nodes
            method: Fusion method ('weighted_average', 'majority_vote', 'confidence_weighted')
        
        Returns:
            Fused decision with confidence score and analysis
        """
        try:
            if not node_results:
                return self._create_error_result("No node results provided")
            
            # Filter valid results
            valid_results = [result for result in node_results 
                           if 'confidence' in result and 'node' in result]
            
            if not valid_results:
                return self._create_error_result("No valid node results")
            
            # Apply fusion method
            if method == 'weighted_average':
                final_score = self._weighted_average_fusion(valid_results)
            elif method == 'majority_vote':
                final_score = self._majority_vote_fusion(valid_results)
            elif method == 'confidence_weighted':
                final_score = self._confidence_weighted_fusion(valid_results)
            else:
                final_score = self._weighted_average_fusion(valid_results)
            
            # Determine risk level
            risk_level = self._determine_risk_level(final_score)
            
            # Generate comprehensive analysis
            analysis = self._generate_analysis(valid_results, final_score, risk_level)
            
            # Create fusion result
            fusion_result = {
                'timestamp': datetime.now().isoformat(),
                'final_score': float(final_score),
                'risk_level': risk_level,
                'fusion_method': method,
                'node_count': len(valid_results),
                'node_results': valid_results,
                'analysis': analysis,
                'recommendations': self._generate_recommendations(final_score, valid_results),
                'confidence_breakdown': self._calculate_confidence_breakdown(valid_results)
            }
            
            # Track performance
            self._track_performance(fusion_result)
            
            return fusion_result
            
        except Exception as e:
            self.logger.error(f"Error in decision fusion: {e}")
            return self._create_error_result(str(e))
    
    def _weighted_average_fusion(self, results: List[Dict[str, Any]]) -> float:
        """Weighted average fusion based on predefined node weights"""
        weighted_sum = 0.0
        total_weight = 0.0
        
        for result in results:
            node_name = result['node']
            confidence = result['confidence']
            weight = self.adaptive_weights.get(node_name, 0.1)
            
            weighted_sum += confidence * weight
            total_weight += weight
        
        return weighted_sum / total_weight if total_weight > 0 else 0.0
    
    def _majority_vote_fusion(self, results: List[Dict[str, Any]]) -> float:
        """Majority vote fusion - converts to binary decisions first"""
        votes = []
        confidences = []
        
        for result in results:
            confidence = result['confidence']
            confidences.append(confidence)
            # Convert to binary vote (threshold = 0.5)
            votes.append(1 if confidence > 0.5 else 0)
        
        # Calculate majority vote
        majority_vote = 1 if sum(votes) > len(votes) / 2 else 0
        
        # If majority agrees, return average confidence of agreeing nodes
        if majority_vote == 1:
            agreeing_confidences = [conf for i, conf in enumerate(confidences) if votes[i] == 1]
            return np.mean(agreeing_confidences)
        else:
            disagreeing_confidences = [conf for i, conf in enumerate(confidences) if votes[i] == 0]
            return np.mean(disagreeing_confidences) if disagreeing_confidences else 0.0
    
    def _confidence_weighted_fusion(self, results: List[Dict[str, Any]]) -> float:
        """Fusion weighted by individual node confidence levels"""
        weighted_sum = 0.0
        total_weight = 0.0
        
        for result in results:
            confidence = result['confidence']
            # Use confidence as weight (higher confidence = more influence)
            weight = confidence
            
            weighted_sum += confidence * weight
            total_weight += weight
        
        return weighted_sum / total_weight if total_weight > 0 else 0.0
    
    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level based on confidence score"""
        if score >= self.risk_thresholds['critical']:
            return 'CRITICAL'
        elif score >= self.risk_thresholds['high']:
            return 'HIGH'
        elif score >= self.risk_thresholds['medium']:
            return 'MEDIUM'
        elif score >= self.risk_thresholds['low']:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def _generate_analysis(self, results: List[Dict[str, Any]], 
                          final_score: float, risk_level: str) -> Dict[str, Any]:
        """Generate comprehensive analysis of the decision"""
        analysis = {
            'summary': self._generate_summary(final_score, risk_level),
            'node_contributions': {},
            'key_indicators': [],
            'agreement_level': self._calculate_agreement_level(results),
            'certainty_level': self._calculate_certainty_level(results)
        }
        
        # Analyze each node's contribution
        for result in results:
            node_name = result['node']
            confidence = result['confidence']
            weight = self.adaptive_weights.get(node_name, 0.1)
            contribution = confidence * weight
            
            analysis['node_contributions'][node_name] = {
                'confidence': confidence,
                'weight': weight,
                'contribution': contribution,
                'indicators': result.get('indicators', [])
            }
            
            # Collect key indicators
            if confidence > 0.5:
                analysis['key_indicators'].extend(result.get('indicators', []))
        
        # Remove duplicate indicators
        analysis['key_indicators'] = list(set(analysis['key_indicators']))
        
        return analysis
    
    def _generate_summary(self, score: float, risk_level: str) -> str:
        """Generate human-readable summary"""
        if risk_level == 'CRITICAL':
            return f"HIGH RISK: Strong indicators of phishing detected (confidence: {score:.1%}). Immediate action recommended."
        elif risk_level == 'HIGH':
            return f"SUSPICIOUS: Multiple phishing indicators found (confidence: {score:.1%}). Exercise caution."
        elif risk_level == 'MEDIUM':
            return f"MODERATE RISK: Some suspicious elements detected (confidence: {score:.1%}). Review carefully."
        elif risk_level == 'LOW':
            return f"LOW RISK: Few concerning indicators (confidence: {score:.1%}). Likely legitimate."
        else:
            return f"MINIMAL RISK: No significant phishing indicators (confidence: {score:.1%}). Appears legitimate."
    
    def _calculate_agreement_level(self, results: List[Dict[str, Any]]) -> float:
        """Calculate how much the nodes agree with each other"""
        confidences = [result['confidence'] for result in results]
        if len(confidences) < 2:
            return 1.0
        
        # Calculate standard deviation (lower = more agreement)
        std_dev = np.std(confidences)
        # Convert to agreement score (0-1, higher = more agreement)
        agreement = max(0, 1 - (std_dev / 0.5))
        
        return float(agreement)
    
    def _calculate_certainty_level(self, results: List[Dict[str, Any]]) -> float:
        """Calculate overall certainty level of the decision"""
        confidences = [result['confidence'] for result in results]
        
        # Higher certainty if confidences are either very high or very low
        certainty_scores = [abs(conf - 0.5) * 2 for conf in confidences]
        return float(np.mean(certainty_scores))
    
    def _generate_recommendations(self, score: float, results: List[Dict[str, Any]]) -> List[str]:
        """Generate actionable recommendations based on analysis"""
        recommendations = []
        
        if score >= 0.8:
            recommendations.extend([
                "🚨 DO NOT click any links or download attachments",
                "🚨 DO NOT provide any personal information",
                "📞 Contact the sender through official channels to verify",
                "🛡️ Report this message to your IT security team"
            ])
        elif score >= 0.6:
            recommendations.extend([
                "⚠️  Exercise extreme caution with this message",
                "🔍 Verify sender identity through official channels",
                "❌ Avoid clicking links or downloading attachments",
                "📋 Check for spelling errors and suspicious language"
            ])
        elif score >= 0.3:
            recommendations.extend([
                "🔍 Review the message carefully for authenticity",
                "✅ Verify any requests through official channels",
                "🧐 Be cautious with personal information sharing"
            ])
        else:
            recommendations.extend([
                "✅ Message appears legitimate",
                "💡 Still practice general email safety",
                "🔒 Never share sensitive information via email"
            ])
        
        # Add node-specific recommendations
        for result in results:
            if result['confidence'] > 0.7:
                node_name = result['node']
                if node_name == 'url_analysis':
                    recommendations.append("🌐 URLs in this message appear suspicious")
                elif node_name == 'text_content':
                    recommendations.append("📝 Message content contains concerning language")
                elif node_name == 'metadata_analysis':
                    recommendations.append("📧 Email headers show suspicious patterns")
                elif node_name == 'behavioral_analysis':
                    recommendations.append("🎯 Message uses social engineering tactics")
        
        return list(set(recommendations))  # Remove duplicates
    
    def _calculate_confidence_breakdown(self, results: List[Dict[str, Any]]) -> Dict[str, float]:
        """Calculate confidence breakdown by node type"""
        breakdown = {}
        
        for result in results:
            node_name = result['node']
            confidence = result['confidence']
            weight = self.adaptive_weights.get(node_name, 0.1)
            
            breakdown[node_name] = {
                'confidence': confidence,
                'weight': weight,
                'weighted_contribution': confidence * weight
            }
        
        return breakdown
    
    def _create_error_result(self, error_message: str) -> Dict[str, Any]:
        """Create error result structure"""
        return {
            'timestamp': datetime.now().isoformat(),
            'final_score': 0.0,
            'risk_level': 'UNKNOWN',
            'error': error_message,
            'node_count': 0,
            'analysis': {'summary': f"Analysis failed: {error_message}"},
            'recommendations': ["⚠️  Unable to analyze - exercise caution"]
        }
    
    def _track_performance(self, result: Dict[str, Any]):
        """Track performance metrics"""
        performance_data = {
            'timestamp': result['timestamp'],
            'final_score': result['final_score'],
            'risk_level': result['risk_level'],
            'node_count': result['node_count'],
            'agreement_level': result['analysis'].get('agreement_level', 0),
            'certainty_level': result['analysis'].get('certainty_level', 0)
        }
        
        self.performance_history.append(performance_data)
        
        # Keep only last 1000 records
        if len(self.performance_history) > 1000:
            self.performance_history = self.performance_history[-1000:]
    
    def update_weights(self, feedback: Dict[str, Any]):
        """Update node weights based on feedback"""
        try:
            actual_result = feedback.get('actual_result')  # True/False
            node_results = feedback.get('node_results', [])
            
            if actual_result is None or not node_results:
                return
            
            self.feedback_data.append(feedback)
            
            # Simple weight adjustment based on individual node accuracy
            for result in node_results:
                node_name = result['node']
                node_prediction = result['confidence'] > 0.5
                
                if node_name in self.adaptive_weights:
                    if node_prediction == actual_result:
                        # Correct prediction - slightly increase weight
                        self.adaptive_weights[node_name] *= 1.05
                    else:
                        # Incorrect prediction - slightly decrease weight
                        self.adaptive_weights[node_name] *= 0.95
            
            # Normalize weights to sum to 1.0
            total_weight = sum(self.adaptive_weights.values())
            if total_weight > 0:
                for node in self.adaptive_weights:
                    self.adaptive_weights[node] /= total_weight
            
            self.logger.info(f"Updated adaptive weights: {self.adaptive_weights}")
            
        except Exception as e:
            self.logger.error(f"Error updating weights: {e}")
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        if not self.performance_history:
            return {}
        
        scores = [p['final_score'] for p in self.performance_history]
        agreement_levels = [p['agreement_level'] for p in self.performance_history]
        certainty_levels = [p['certainty_level'] for p in self.performance_history]
        
        return {
            'total_analyses': len(self.performance_history),
            'average_confidence': np.mean(scores),
            'confidence_std': np.std(scores),
            'average_agreement': np.mean(agreement_levels),
            'average_certainty': np.mean(certainty_levels),
            'current_weights': self.adaptive_weights.copy(),
            'risk_distribution': {
                'critical': len([p for p in self.performance_history if p['risk_level'] == 'CRITICAL']),
                'high': len([p for p in self.performance_history if p['risk_level'] == 'HIGH']),
                'medium': len([p for p in self.performance_history if p['risk_level'] == 'MEDIUM']),
                'low': len([p for p in self.performance_history if p['risk_level'] == 'LOW']),
                'minimal': len([p for p in self.performance_history if p['risk_level'] == 'MINIMAL'])
            }
        }
    
    def reset_weights(self):
        """Reset weights to original values"""
        self.adaptive_weights = self.node_weights.copy()
        self.logger.info("Weights reset to original values")
    
    def save_state(self, filepath: str):
        """Save current state to file"""
        try:
            state = {
                'adaptive_weights': self.adaptive_weights,
                'performance_history': self.performance_history[-100:],  # Save last 100
                'feedback_data': self.feedback_data[-50:]  # Save last 50
            }
            
            with open(filepath, 'w') as f:
                json.dump(state, f, indent=2)
            
            self.logger.info(f"State saved to {filepath}")
            
        except Exception as e:
            self.logger.error(f"Error saving state: {e}")
    
    def load_state(self, filepath: str):
        """Load state from file"""
        try:
            with open(filepath, 'r') as f:
                state = json.load(f)
            
            self.adaptive_weights = state.get('adaptive_weights', self.node_weights.copy())
            self.performance_history = state.get('performance_history', [])
            self.feedback_data = state.get('feedback_data', [])
            
            self.logger.info(f"State loaded from {filepath}")
            
        except Exception as e:
            self.logger.error(f"Error loading state: {e}")
