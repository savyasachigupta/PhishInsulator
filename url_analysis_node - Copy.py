"""
URL Analysis Node for PhishInsulator AI
Analyzes URL structure, domain reputation, and suspicious patterns
"""

import re
import requests
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from urllib.parse import urlparse
import whois
from typing import Dict, List, Any
import logging

class URLAnalysisNode:
    """
    Specialized node for analyzing URLs and domains for phishing indicators
    """
    
    def __init__(self, model_path: str = None):
        self.logger = logging.getLogger(__name__)
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.suspicious_domains = set()
        self.trusted_domains = set()
        self.load_domain_lists()
        
        if model_path:
            self.load_model(model_path)
    
    def load_domain_lists(self):
        """Load known suspicious and trusted domain lists"""
        # In production, load from external threat intelligence feeds
        self.suspicious_domains = {
            'paypa1.com', 'g00gle.com', 'amazom.com',
            'microsft.com', 'app1e.com', 'bank0famerica.com'
        }
        
        self.trusted_domains = {
            'paypal.com', 'google.com', 'amazon.com',
            'microsoft.com', 'apple.com', 'bankofamerica.com',
            'github.com', 'stackoverflow.com'
        }
    
    def extract_features(self, url: str) -> Dict[str, float]:
        """Extract features from URL for analysis"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            path = parsed_url.path
            
            features = {
                # Length features
                'url_length': len(url),
                'domain_length': len(domain),
                'path_length': len(path),
                
                # Character analysis
                'special_chars_count': len(re.findall(r'[^a-zA-Z0-9.-]', url)),
                'digit_count': len(re.findall(r'\d', url)),
                'hyphen_count': url.count('-'),
                'underscore_count': url.count('_'),
                'dot_count': url.count('.'),
                
                # Suspicious patterns
                'has_ip_address': 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0,
                'has_suspicious_words': self._check_suspicious_words(url),
                'subdomain_count': len(domain.split('.')) - 2 if len(domain.split('.')) > 2 else 0,
                
                # Security features
                'uses_https': 1 if parsed_url.scheme == 'https' else 0,
                'has_port': 1 if parsed_url.port else 0,
                
                # Domain reputation
                'is_suspicious_domain': 1 if domain in self.suspicious_domains else 0,
                'is_trusted_domain': 1 if domain in self.trusted_domains else 0,
                
                # URL structure
                'has_query_params': 1 if parsed_url.query else 0,
                'has_fragment': 1 if parsed_url.fragment else 0,
                'path_depth': len([p for p in path.split('/') if p]),
                
                # Typosquatting detection
                'potential_typosquatting': self._check_typosquatting(domain),
            }
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting features from URL {url}: {e}")
            return {}
    
    def _check_suspicious_words(self, url: str) -> float:
        """Check for suspicious words in URL"""
        suspicious_words = [
            'verify', 'account', 'update', 'confirm', 'secure',
            'suspended', 'limited', 'urgent', 'immediately'
        ]
        
        url_lower = url.lower()
        count = sum(1 for word in suspicious_words if word in url_lower)
        return min(count / len(suspicious_words), 1.0)
    
    def _check_typosquatting(self, domain: str) -> float:
        """Check for potential typosquatting against known brands"""
        known_brands = [
            'paypal', 'google', 'amazon', 'microsoft', 'apple',
            'facebook', 'twitter', 'linkedin', 'instagram'
        ]
        
        # Simple Levenshtein distance check
        def levenshtein_distance(s1, s2):
            if len(s1) < len(s2):
                return levenshtein_distance(s2, s1)
            
            if len(s2) == 0:
                return len(s1)
            
            previous_row = range(len(s2) + 1)
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row
            
            return previous_row[-1]
        
        domain_clean = re.sub(r'\.(com|org|net|edu|gov)$', '', domain)
        
        for brand in known_brands:
            distance = levenshtein_distance(domain_clean, brand)
            if 1 <= distance <= 2 and len(domain_clean) >= len(brand) - 1:
                return 1.0
        
        return 0.0
    
    def analyze(self, url: str) -> Dict[str, Any]:
        """Analyze URL and return phishing probability and indicators"""
        try:
            features = self.extract_features(url)
            
            if not features:
                return {
                    'node': 'url_analysis',
                    'confidence': 0.0,
                    'error': 'Failed to extract features'
                }
            
            # Convert features to array for model prediction
            feature_vector = np.array(list(features.values())).reshape(1, -1)
            
            # Get prediction probability
            if hasattr(self.model, 'predict_proba'):
                confidence = self.model.predict_proba(feature_vector)[0][1]
            else:
                confidence = float(self.model.predict(feature_vector)[0])
            
            # Generate indicators based on features
            indicators = self._generate_indicators(features)
            
            return {
                'node': 'url_analysis',
                'confidence': float(confidence),
                'features': features,
                'indicators': indicators,
                'url': url
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing URL {url}: {e}")
            return {
                'node': 'url_analysis',
                'confidence': 0.0,
                'error': str(e)
            }
    
    def _generate_indicators(self, features: Dict[str, float]) -> List[str]:
        """Generate human-readable indicators based on features"""
        indicators = []
        
        if features.get('is_suspicious_domain', 0) > 0:
            indicators.append('Known suspicious domain')
        
        if features.get('has_ip_address', 0) > 0:
            indicators.append('Uses IP address instead of domain')
        
        if features.get('potential_typosquatting', 0) > 0:
            indicators.append('Potential typosquatting detected')
        
        if features.get('url_length', 0) > 100:
            indicators.append('Unusually long URL')
        
        if features.get('subdomain_count', 0) > 3:
            indicators.append('Multiple suspicious subdomains')
        
        if features.get('uses_https', 0) == 0:
            indicators.append('No HTTPS encryption')
        
        if features.get('has_suspicious_words', 0) > 0.3:
            indicators.append('Contains suspicious keywords')
        
        if features.get('special_chars_count', 0) > 10:
            indicators.append('High number of special characters')
        
        return indicators
    
    def train(self, training_data: pd.DataFrame):
        """Train the URL analysis model"""
        try:
            features = []
            labels = []
            
            for _, row in training_data.iterrows():
                url_features = self.extract_features(row['url'])
                if url_features:
                    features.append(list(url_features.values()))
                    labels.append(row['is_phishing'])
            
            if features:
                X = np.array(features)
                y = np.array(labels)
                
                self.model.fit(X, y)
                self.logger.info(f"Model trained on {len(features)} samples")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error training model: {e}")
            return False
    
    def save_model(self, path: str):
        """Save trained model"""
        import joblib
        joblib.dump(self.model, path)
    
    def load_model(self, path: str):
        """Load pre-trained model"""
        import joblib
        self.model = joblib.load(path)
