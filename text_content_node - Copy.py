"""
Text Content Analysis Node for PhishInsulator AI
Handles multilingual text analysis using BERT transformers
"""

import re
import torch
import numpy as np
from transformers import AutoTokenizer, AutoModel, pipeline
from langdetect import detect, DetectorFactory
import logging
from typing import Dict, List, Any, Tuple
import unicodedata

# Set seed for consistent language detection
DetectorFactory.seed = 0

class TextContentNode:
    """
    Specialized node for multilingual text content analysis
    """
    
    def __init__(self, model_name: str = 'bert-base-multilingual-cased'):
        self.logger = logging.getLogger(__name__)
        self.model_name = model_name
        
        # Initialize multilingual BERT
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModel.from_pretrained(model_name)
            self.classifier = torch.nn.Sequential(
                torch.nn.Linear(768, 256),
                torch.nn.ReLU(),
                torch.nn.Dropout(0.1),
                torch.nn.Linear(256, 2)
            )
            
            # Initialize sentiment analyzer
            self.sentiment_analyzer = pipeline(
                "sentiment-analysis", 
                model="nlptown/bert-base-multilingual-uncased-sentiment"
            )
        except Exception as e:
            self.logger.error(f"Error initializing models: {e}")
            
        # Supported languages
        self.supported_languages = {
            'en': 'English',
            'hi': 'Hindi', 
            'ar': 'Arabic',
            'es': 'Spanish',
            'fr': 'French',
            'de': 'German',
            'pt': 'Portuguese',
            'ru': 'Russian'
        }
        
        # Multilingual phishing keywords
        self.phishing_keywords = {
            'en': [
                'urgent', 'immediate', 'verify', 'suspended', 'expired',
                'confirm', 'update', 'click here', 'limited time', 'act now',
                'congratulations', 'winner', 'prize', 'lottery', 'refund'
            ],
            'hi': [
                'तुरंत', 'जरूरी', 'सत्यापित', 'निलंबित', 'समाप्त',
                'पुष्टि', 'अपडेट', 'यहाँ क्लिक', 'सीमित समय', 'अभी करें'
            ],
            'ar': [
                'عاجل', 'فوري', 'تحقق', 'معلق', 'منتهي',
                'تأكيد', 'تحديث', 'انقر هنا', 'وقت محدود', 'تصرف الآن'
            ],
            'es': [
                'urgente', 'inmediato', 'verificar', 'suspendido', 'expirado',
                'confirmar', 'actualizar', 'haga clic aquí', 'tiempo limitado'
            ],
            'fr': [
                'urgent', 'immédiat', 'vérifier', 'suspendu', 'expiré',
                'confirmer', 'mettre à jour', 'cliquez ici', 'temps limité'
            ]
        }
        
        # Common phishing patterns (regex)
        self.phishing_patterns = [
            r'\\b(verify|confirm|update)\\s+(?:your\\s+)?account\\b',
            r'\\b(?:click|tap)\\s+(?:here|now|below)\\b',
            r'\\b(?:limited|urgent|immediate)\\s+(?:time|action)\\b',
            r'\\b(?:suspended|blocked|frozen)\\s+account\\b',
            r'\\$\\d+(?:,\\d{3})*(?:\\.\\d{2})?\\s+(?:waiting|available)',
            r'\\b(?:congratulations|winner|prize|lottery)\\b'
        ]
    
    def detect_language(self, text: str) -> str:
        """Detect language of input text"""
        try:
            # Clean text for better detection
            cleaned_text = self._clean_text(text)
            if len(cleaned_text.strip()) < 3:
                return 'en'  # Default to English for short texts
                
            detected = detect(cleaned_text)
            return detected if detected in self.supported_languages else 'en'
        except:
            return 'en'  # Default to English if detection fails
    
    def _clean_text(self, text: str) -> str:
        """Clean and normalize text"""
        # Remove URLs
        text = re.sub(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', ' ', text)
        
        # Remove email addresses
        text = re.sub(r'\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b', ' ', text)
        
        # Normalize unicode
        text = unicodedata.normalize('NFKD', text)
        
        # Remove excessive whitespace
        text = ' '.join(text.split())
        
        return text
    
    def extract_linguistic_features(self, text: str, language: str) -> Dict[str, float]:
        """Extract linguistic features from text"""
        cleaned_text = self._clean_text(text)
        words = cleaned_text.lower().split()
        
        features = {
            # Basic text statistics
            'text_length': len(text),
            'word_count': len(words),
            'sentence_count': len([s for s in re.split(r'[.!?]+', text) if s.strip()]),
            'avg_word_length': np.mean([len(word) for word in words]) if words else 0,
            
            # Character analysis
            'uppercase_ratio': sum(1 for c in text if c.isupper()) / len(text) if text else 0,
            'digit_ratio': sum(1 for c in text if c.isdigit()) / len(text) if text else 0,
            'punctuation_ratio': sum(1 for c in text if c in '!@#$%^&*()[]{}|;:,.<>?') / len(text) if text else 0,
            'exclamation_count': text.count('!'),
            'question_count': text.count('?'),
            
            # Phishing-specific features
            'phishing_keywords_count': self._count_phishing_keywords(cleaned_text, language),
            'phishing_patterns_count': self._count_phishing_patterns(cleaned_text),
            'urgency_words': self._count_urgency_words(cleaned_text, language),
            'money_mentions': len(re.findall(r'[$€£¥₹]\\d+|\\d+\\s*(?:dollar|euro|pound|rupee|usd|eur)', cleaned_text.lower())),
            
            # Email-specific features
            'has_greeting': 1 if self._has_greeting(cleaned_text, language) else 0,
            'has_signature': 1 if self._has_signature(cleaned_text) else 0,
            'personal_info_request': self._detect_info_request(cleaned_text, language),
            
            # Language-specific features
            'language_confidence': self._get_language_confidence(text, language),
            'script_mixing': self._detect_script_mixing(text),
        }
        
        return features
    
    def _count_phishing_keywords(self, text: str, language: str) -> float:
        """Count phishing keywords in the detected language"""
        keywords = self.phishing_keywords.get(language, self.phishing_keywords['en'])
        text_lower = text.lower()
        
        count = sum(1 for keyword in keywords if keyword in text_lower)
        return min(count / len(keywords), 1.0)
    
    def _count_phishing_patterns(self, text: str) -> float:
        """Count regex patterns associated with phishing"""
        count = 0
        for pattern in self.phishing_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                count += 1
        
        return min(count / len(self.phishing_patterns), 1.0)
    
    def _count_urgency_words(self, text: str, language: str) -> float:
        """Count urgency-related words"""
        urgency_words = {
            'en': ['urgent', 'immediate', 'now', 'asap', 'quickly', 'hurry', 'fast'],
            'hi': ['तुरंत', 'जल्दी', 'अभी', 'शीघ्र'],
            'ar': ['عاجل', 'فوري', 'سريع', 'الآن'],
            'es': ['urgente', 'inmediato', 'rápido', 'ahora'],
            'fr': ['urgent', 'immédiat', 'rapide', 'maintenant']
        }
        
        words = urgency_words.get(language, urgency_words['en'])
        text_lower = text.lower()
        
        count = sum(1 for word in words if word in text_lower)
        return min(count / len(words), 1.0)
    
    def _has_greeting(self, text: str, language: str) -> bool:
        """Check if text has a greeting"""
        greetings = {
            'en': ['dear', 'hello', 'hi', 'greetings'],
            'hi': ['प्रिय', 'नमस्ते', 'नमस्कार'],
            'ar': ['عزيزي', 'مرحبا', 'السلام عليكم'],
            'es': ['estimado', 'hola', 'querido'],
            'fr': ['cher', 'bonjour', 'salut']
        }
        
        greeting_words = greetings.get(language, greetings['en'])
        text_lower = text.lower()
        
        return any(greeting in text_lower for greeting in greeting_words)
    
    def _has_signature(self, text: str) -> bool:
        """Check if text has a signature-like ending"""
        signature_patterns = [
            r'(?:best|kind)\\s+regards',
            r'sincerely',
            r'thank\\s+you',
            r'customer\\s+(?:service|support)',
            r'team$'
        ]
        
        return any(re.search(pattern, text.lower()) for pattern in signature_patterns)
    
    def _detect_info_request(self, text: str, language: str) -> float:
        """Detect requests for personal information"""
        info_requests = {
            'en': [
                'password', 'ssn', 'social security', 'credit card',
                'bank account', 'pin', 'personal information'
            ],
            'hi': [
                'पासवर्ड', 'बैंक खाता', 'व्यक्तिगत जानकारी', 'पिन'
            ],
            'ar': [
                'كلمة المرور', 'حساب بنكي', 'معلومات شخصية', 'رقم سري'
            ],
            'es': [
                'contraseña', 'cuenta bancaria', 'información personal', 'pin'
            ],
            'fr': [
                'mot de passe', 'compte bancaire', 'informations personnelles', 'code pin'
            ]
        }
        
        requests = info_requests.get(language, info_requests['en'])
        text_lower = text.lower()
        
        count = sum(1 for req in requests if req in text_lower)
        return min(count / len(requests), 1.0)
    
    def _get_language_confidence(self, text: str, detected_language: str) -> float:
        """Get confidence score for language detection"""
        try:
            from langdetect import detect_langs
            langs = detect_langs(text)
            for lang in langs:
                if lang.lang == detected_language:
                    return float(lang.prob)
            return 0.0
        except:
            return 0.5  # Default confidence
    
    def _detect_script_mixing(self, text: str) -> float:
        """Detect mixing of different scripts (potential obfuscation)"""
        scripts = set()
        for char in text:
            if char.isalpha():
                script = unicodedata.name(char, '').split()[0]
                scripts.add(script)
        
        # More than 2 different scripts might indicate obfuscation
        return min(len(scripts) / 5.0, 1.0) if len(scripts) > 2 else 0.0
    
    def get_bert_embeddings(self, text: str) -> torch.Tensor:
        """Get BERT embeddings for text"""
        try:
            inputs = self.tokenizer(
                text,
                return_tensors='pt',
                truncation=True,
                padding=True,
                max_length=512
            )
            
            with torch.no_grad():
                outputs = self.model(**inputs)
                # Use [CLS] token embedding
                embeddings = outputs.last_hidden_state[:, 0, :]
            
            return embeddings
        except Exception as e:
            self.logger.error(f"Error getting BERT embeddings: {e}")
            return torch.zeros(1, 768)
    
    def analyze_sentiment(self, text: str) -> Dict[str, Any]:
        """Analyze sentiment of the text"""
        try:
            result = self.sentiment_analyzer(text)[0]
            return {
                'label': result['label'],
                'score': result['score']
            }
        except:
            return {'label': 'NEUTRAL', 'score': 0.5}
    
    def analyze(self, text: str) -> Dict[str, Any]:
        """Analyze text content and return phishing probability"""
        try:
            # Detect language
            language = self.detect_language(text)
            
            # Extract linguistic features
            features = self.extract_linguistic_features(text, language)
            
            # Get BERT embeddings
            embeddings = self.get_bert_embeddings(text)
            
            # Get sentiment
            sentiment = self.analyze_sentiment(text)
            
            # Calculate confidence score based on features
            # This is a simplified scoring - in production, use a trained classifier
            confidence = self._calculate_confidence_score(features, sentiment)
            
            # Generate indicators
            indicators = self._generate_indicators(features, language, sentiment)
            
            return {
                'node': 'text_content',
                'confidence': float(confidence),
                'language': language,
                'features': features,
                'sentiment': sentiment,
                'indicators': indicators,
                'embedding_shape': embeddings.shape
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing text content: {e}")
            return {
                'node': 'text_content',
                'confidence': 0.0,
                'error': str(e)
            }
    
    def _calculate_confidence_score(self, features: Dict[str, float], sentiment: Dict[str, Any]) -> float:
        """Calculate confidence score based on features"""
        score = 0.0
        
        # High phishing keyword presence
        score += features.get('phishing_keywords_count', 0) * 0.3
        
        # Phishing patterns detected
        score += features.get('phishing_patterns_count', 0) * 0.25
        
        # Urgency indicators
        score += features.get('urgency_words', 0) * 0.2
        
        # Personal info requests
        score += features.get('personal_info_request', 0) * 0.2
        
        # Unusual text characteristics
        if features.get('uppercase_ratio', 0) > 0.3:
            score += 0.1
        
        if features.get('exclamation_count', 0) > 2:
            score += 0.1
        
        # Script mixing (obfuscation)
        score += features.get('script_mixing', 0) * 0.15
        
        # Sentiment analysis - phishing often uses fear/urgency
        if sentiment.get('label') == 'NEGATIVE' and sentiment.get('score', 0) > 0.7:
            score += 0.1
        
        return min(score, 1.0)
    
    def _generate_indicators(self, features: Dict[str, float], language: str, sentiment: Dict[str, Any]) -> List[str]:
        """Generate human-readable indicators"""
        indicators = []
        
        if features.get('phishing_keywords_count', 0) > 0.2:
            indicators.append(f'Contains phishing keywords in {self.supported_languages.get(language, language)}')
        
        if features.get('urgency_words', 0) > 0.3:
            indicators.append('High urgency language detected')
        
        if features.get('personal_info_request', 0) > 0:
            indicators.append('Requests personal information')
        
        if features.get('uppercase_ratio', 0) > 0.3:
            indicators.append('Excessive use of capital letters')
        
        if features.get('exclamation_count', 0) > 2:
            indicators.append('Multiple exclamation marks')
        
        if features.get('script_mixing', 0) > 0.5:
            indicators.append('Mixed scripts (potential obfuscation)')
        
        if features.get('money_mentions', 0) > 0:
            indicators.append('Contains monetary references')
        
        if sentiment.get('label') == 'NEGATIVE' and sentiment.get('score', 0) > 0.7:
            indicators.append('Negative sentiment (fear/threat language)')
        
        if not features.get('has_greeting', 0) and features.get('word_count', 0) > 20:
            indicators.append('Missing proper greeting')
        
        return indicators
