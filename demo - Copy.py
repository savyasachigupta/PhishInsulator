"""
PhishInsulator AI - Demo Script
Interactive demonstration of the multilingual phishing detection system
"""

import requests
import json
import time
from typing import Dict, Any
import sys

class PhishInsulatorDemo:
    """Demo class for PhishInsulator AI system"""
    
    def __init__(self, api_url: str = "http://localhost:5000"):
        self.api_url = api_url
        self.session = requests.Session()
    
    def check_api_health(self) -> bool:
        """Check if API is running"""
        try:
            response = self.session.get(f"{self.api_url}/api/health", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def analyze_content(self, content: str, language: str = "auto") -> Dict[str, Any]:
        """Analyze content using the API"""
        try:
            payload = {
                "content": content,
                "language": language,
                "analysis_type": "comprehensive"
            }
            
            response = self.session.post(
                f"{self.api_url}/api/analyze",
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"API error: {response.status_code}"}
                
        except Exception as e:
            return {"error": f"Request failed: {str(e)}"}
    
    def display_result(self, result: Dict[str, Any], content: str):
        """Display analysis result in a formatted way"""
        print("\n" + "="*80)
        print("🔍 PHISHINSULATOR AI ANALYSIS RESULT")
        print("="*80)
        
        # Show content (truncated)
        content_preview = content[:100] + "..." if len(content) > 100 else content
        print(f"📝 Content: {content_preview}")
        
        if "error" in result:
            print(f"❌ Error: {result['error']}")
            return
        
        # Risk assessment
        score = result.get('final_score', 0)
        risk_level = result.get('risk_level', 'UNKNOWN')
        
        # Color coding for risk levels
        risk_colors = {
            'MINIMAL': '🟢',
            'LOW': '🟡', 
            'MEDIUM': '🟠',
            'HIGH': '🔴',
            'CRITICAL': '🚨'
        }
        
        risk_icon = risk_colors.get(risk_level, '❓')
        
        print(f"\n{risk_icon} Risk Level: {risk_level}")
        print(f"📊 Confidence Score: {score:.1%}")
        
        # Analysis summary
        analysis = result.get('analysis', {})
        summary = analysis.get('summary', 'No summary available')
        print(f"\n📋 Summary: {summary}")
        
        # Node contributions
        node_contributions = analysis.get('node_contributions', {})
        if node_contributions:
            print(f"\n🤖 Node Analysis:")
            for node, info in node_contributions.items():
                confidence = info.get('confidence', 0)
                indicators = info.get('indicators', [])
                print(f"  • {node.replace('_', ' ').title()}: {confidence:.1%}")
                if indicators:
                    for indicator in indicators[:3]:  # Show first 3 indicators
                        print(f"    - {indicator}")
        
        # Recommendations
        recommendations = result.get('recommendations', [])
        if recommendations:
            print(f"\n💡 Recommendations:")
            for rec in recommendations[:5]:  # Show first 5 recommendations
                print(f"  {rec}")
        
        # Metadata
        metadata = result.get('metadata', {})
        if metadata:
            processing_time = metadata.get('processing_time_seconds', 0)
            language_detected = metadata.get('language_detected', 'unknown')
            print(f"\n⏱️  Processing Time: {processing_time:.2f}s")
            print(f"🌍 Language Detected: {language_detected}")
        
        print("="*80)

def run_demo():
    """Run interactive demo"""
    print("🛡️  Welcome to PhishInsulator AI Demo!")
    print("Multilingual AI-enabled phishing detection system\n")
    
    demo = PhishInsulatorDemo()
    
    # Check API health
    print("🔍 Checking API status...")
    if not demo.check_api_health():
        print("❌ API is not running!")
        print("Please start the API server first:")
        print("  python main_api.py")
        sys.exit(1)
    
    print("✅ API is running!\n")
    
    # Predefined examples for quick testing
    examples = {
        "1": {
            "name": "🚨 English Phishing Email",
            "content": "URGENT: Your PayPal account has been suspended! Click here immediately to verify your account: http://paypa1-security.com/verify. If you don't act within 24 hours, your account will be permanently deleted!",
            "language": "en"
        },
        "2": {
            "name": "🌍 Hindi Phishing Email", 
            "content": "तुरंत कार्रवाई आवश्यक! आपका बैंक खाता निलंबित कर दिया गया है। अपनी जानकारी की पुष्टि करने के लिए यहाँ क्लिक करें। देरी न करें!",
            "language": "hi"
        },
        "3": {
            "name": "🔗 Suspicious URL",
            "content": "http://g00gle-security-alert.com/verify-account?user=victim&urgent=true",
            "language": "en"
        },
        "4": {
            "name": "✅ Legitimate Email",
            "content": "Thank you for your recent purchase from Amazon. Your order #AMZ-123456789 has been shipped and will arrive within 2-3 business days. You can track your package using the tracking number provided. Best regards, Amazon Customer Service.",
            "language": "en"
        },
        "5": {
            "name": "🌍 Arabic Phishing Email",
            "content": "عاجل: تم تعليق حسابك المصرفي! انقر هنا فوراً لتأكيد هويتك وإعادة تفعيل الحساب. لديك 24 ساعة فقط!",
            "language": "ar"
        },
        "6": {
            "name": "🌍 Spanish Phishing Email",
            "content": "URGENTE: Su cuenta de Facebook ha sido hackeada! Haga clic aquí inmediatamente para cambiar su contraseña: http://faceb00k-security.org/recover",
            "language": "es"
        }
    }
    
    while True:
        print("\n" + "="*50)
        print("🎯 Choose an option:")
        print("="*50)
        
        for key, example in examples.items():
            print(f"{key}. {example['name']}")
        
        print("7. 📝 Enter custom content")
        print("8. 📊 Show API statistics")
        print("9. ❌ Exit")
        
        choice = input("\n👉 Enter your choice (1-9): ").strip()
        
        if choice in examples:
            example = examples[choice]
            print(f"\n🔍 Analyzing: {example['name']}")
            
            start_time = time.time()
            result = demo.analyze_content(
                content=example['content'],
                language=example['language']
            )
            
            demo.display_result(result, example['content'])
            
        elif choice == "7":
            print("\n📝 Enter your custom content:")
            custom_content = input("Content: ").strip()
            
            if custom_content:
                language = input("Language (auto/en/hi/ar/es/fr/de/pt/ru): ").strip() or "auto"
                
                print("\n🔍 Analyzing custom content...")
                result = demo.analyze_content(custom_content, language)
                demo.display_result(result, custom_content)
            else:
                print("❌ Empty content provided!")
        
        elif choice == "8":
            print("\n📊 Fetching API statistics...")
            try:
                response = demo.session.get(f"{demo.api_url}/api/stats", timeout=10)
                if response.status_code == 200:
                    stats = response.json()
                    api_stats = stats.get('api_stats', {})
                    
                    print("\n📈 API Statistics:")
                    print(f"  Total Requests: {api_stats.get('total_requests', 0)}")
                    print(f"  Phishing Detected: {api_stats.get('phishing_detected', 0)}")
                    print(f"  Legitimate Detected: {api_stats.get('legitimate_detected', 0)}")
                    print(f"  Average Response Time: {api_stats.get('average_response_time', 0):.3f}s")
                else:
                    print("❌ Failed to fetch statistics")
            except Exception as e:
                print(f"❌ Error fetching statistics: {e}")
        
        elif choice == "9":
            print("\n👋 Thank you for using PhishInsulator AI!")
            print("Stay safe online! 🛡️")
            break
        
        else:
            print("❌ Invalid choice! Please select 1-9.")
        
        # Ask if user wants to continue
        if choice in ["1", "2", "3", "4", "5", "6", "7"]:
            continue_demo = input("\n🔄 Analyze another item? (y/n): ").strip().lower()
            if continue_demo not in ['y', 'yes']:
                print("\n👋 Thank you for using PhishInsulator AI!")
                print("Stay safe online! 🛡️")
                break

def run_batch_demo():
    """Run batch analysis demo"""
    print("\n🚀 Running Batch Analysis Demo...")
    
    demo = PhishInsulatorDemo()
    
    batch_items = [
        "URGENT: Click here to verify your account: http://paypa1-verify.com",
        "Thank you for your Amazon purchase. Order #123456 shipped.",
        "Your bank account has been frozen! Call us immediately!",
        "https://google.com/search?q=phishing+detection",
        "Free lottery winner! Claim your $1,000,000 prize now!",
        "Meeting scheduled for tomorrow at 2 PM. Conference Room A."
    ]
    
    try:
        payload = {"items": batch_items}
        response = demo.session.post(
            f"{demo.api_url}/api/batch",
            json=payload,
            timeout=60
        )
        
        if response.status_code == 200:
            results = response.json()
            batch_results = results.get('batch_results', [])
            
            print(f"\n📊 Batch Analysis Results ({len(batch_results)} items):")
            print("="*80)
            
            for result in batch_results:
                index = result.get('index', 0)
                content = batch_items[index] if index < len(batch_items) else "Unknown"
                score = result.get('final_score', 0)
                risk = result.get('risk_level', 'UNKNOWN')
                
                risk_icon = {'MINIMAL': '🟢', 'LOW': '🟡', 'MEDIUM': '🟠', 
                           'HIGH': '🔴', 'CRITICAL': '🚨'}.get(risk, '❓')
                
                print(f"\n{index+1}. {content[:60]}{'...' if len(content) > 60 else ''}")
                print(f"   {risk_icon} {risk} - {score:.1%}")
            
        else:
            print(f"❌ Batch analysis failed: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Batch analysis error: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--batch":
        run_batch_demo()
    else:
        run_demo()
