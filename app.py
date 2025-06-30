from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import google.generativeai as genai
from pydantic import BaseModel, HttpUrl, field_validator
from typing import Optional, List, Dict
import os
import re
import json
import hashlib
import time
from datetime import datetime, timedelta
from pydantic_ai import Agent as PydanticAgent, RunContext
from functools import wraps
import threading
import atexit

# Set Gemini API key directly
os.environ['GOOGLE_API_KEY'] = 'AIzaSyDGnj_SMhBZzyvDsuFKOoiJeFcGblMR6HU'

# Configure Gemini
genai.configure(api_key=os.environ['GOOGLE_API_KEY'])
model = genai.GenerativeModel("gemini-1.5-flash")

# Global cache for storing analysis results
analysis_cache = {}
cache_lock = threading.Lock()

# Rate limiting storage
rate_limit_storage = {}
rate_limit_lock = threading.Lock()

# Configuration for cost optimization
MAX_CACHE_SIZE = 1000  # Maximum number of cached results
CACHE_TTL = 3600  # Cache TTL in seconds (1 hour)
MAX_REQUESTS_PER_MINUTE = 10  # Rate limiting
MAX_REQUESTS_PER_HOUR = 100

# Common phishing patterns for local analysis
PHISHING_PATTERNS = {
    'url_patterns': [
        r'bit\.ly|tinyurl\.com|goo\.gl|t\.co',  # URL shorteners
        r'paypal.*\.(?!paypal\.com)',  # Fake PayPal domains
        r'bank.*\.(?!yourbank\.com)',  # Fake bank domains
        r'secure.*\.(?!official\.com)',  # Fake secure domains
        r'login.*\.(?!official\.com)',  # Fake login domains
        r'update.*\.(?!official\.com)',  # Fake update domains
        r'verify.*\.(?!official\.com)',  # Fake verify domains
        r'account.*\.(?!official\.com)',  # Fake account domains
    ],
    'email_patterns': [
        r'urgent|immediate|action required|account suspended',
        r'verify.*account|confirm.*details|update.*information',
        r'click.*here|download.*attachment|open.*file',
        r'password.*expired|security.*alert|suspicious.*activity',
        r'limited.*time|offer.*expires|last.*chance',
        r'bank.*transfer|payment.*required|refund.*available',
        r'lottery.*winner|inheritance.*claim|prize.*won',
    ],
    'suspicious_domains': [
        'paypal-secure.com', 'paypal-verify.com', 'paypal-update.com',
        'amaz0n.com', 'amazonsecure.com', 'amazon-verify.com',
        'google-secure.com', 'google-verify.com', 'google-update.com',
        'microsoft-secure.com', 'microsoft-verify.com', 'microsoft-update.com',
        'apple-secure.com', 'apple-verify.com', 'apple-update.com',
        'netflix-secure.com', 'netflix-verify.com', 'netflix-update.com',
    ]
}

def rate_limit(f):
    """Decorator to implement rate limiting"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        current_time = time.time()
        
        with rate_limit_lock:
            if client_ip not in rate_limit_storage:
                rate_limit_storage[client_ip] = {'requests': [], 'hourly': []}
            
            # Clean old requests
            rate_limit_storage[client_ip]['requests'] = [
                req_time for req_time in rate_limit_storage[client_ip]['requests']
                if current_time - req_time < 60
            ]
            rate_limit_storage[client_ip]['hourly'] = [
                req_time for req_time in rate_limit_storage[client_ip]['hourly']
                if current_time - req_time < 3600
            ]
            
            # Check limits
            if len(rate_limit_storage[client_ip]['requests']) >= MAX_REQUESTS_PER_MINUTE:
                return jsonify({"error": "Rate limit exceeded. Please wait before making another request."}), 429
            
            if len(rate_limit_storage[client_ip]['hourly']) >= MAX_REQUESTS_PER_HOUR:
                return jsonify({"error": "Hourly rate limit exceeded. Please try again later."}), 429
            
            # Add current request
            rate_limit_storage[client_ip]['requests'].append(current_time)
            rate_limit_storage[client_ip]['hourly'].append(current_time)
        
        return f(*args, **kwargs)
    return decorated_function

def get_cache_key(content_type: str, content: str) -> str:
    """Generate a cache key for the content"""
    content_hash = hashlib.md5(content.encode()).hexdigest()
    return f"{content_type}:{content_hash}"

def get_cached_result(cache_key: str) -> Optional[Dict]:
    """Get cached result if available and not expired"""
    with cache_lock:
        if cache_key in analysis_cache:
            cached_data = analysis_cache[cache_key]
            if time.time() - cached_data['timestamp'] < CACHE_TTL:
                return cached_data['result']
            else:
                # Remove expired cache entry
                del analysis_cache[cache_key]
    return None

def cache_result(cache_key: str, result: Dict):
    """Cache the analysis result"""
    with cache_lock:
        # Implement LRU cache eviction if cache is full
        if len(analysis_cache) >= MAX_CACHE_SIZE:
            # Remove oldest entry
            oldest_key = min(analysis_cache.keys(), 
                           key=lambda k: analysis_cache[k]['timestamp'])
            del analysis_cache[oldest_key]
        
        analysis_cache[cache_key] = {
            'result': result,
            'timestamp': time.time()
        }

def local_url_analysis(url: str) -> Optional[Dict]:
    """Perform basic local analysis for common phishing patterns"""
    url_lower = url.lower()
    
    # Check for obvious phishing indicators
    risk_score = 0
    findings = []
    indicators = []
    
    # Check for HTTP (insecure)
    if url.startswith('http://'):
        risk_score += 20
        findings.append("Uses HTTP instead of HTTPS (insecure connection)")
        indicators.append("Insecure protocol")
    
    # Check for URL shorteners
    for pattern in PHISHING_PATTERNS['url_patterns']:
        if re.search(pattern, url_lower):
            risk_score += 30
            findings.append("Contains suspicious URL patterns")
            indicators.append(f"Matches pattern: {pattern}")
            break
    
    # Check for suspicious domains
    from urllib.parse import urlparse
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        for suspicious_domain in PHISHING_PATTERNS['suspicious_domains']:
            if suspicious_domain in domain:
                risk_score += 40
                findings.append(f"Suspicious domain detected: {domain}")
                indicators.append("Known phishing domain pattern")
                break
                
        # Check for typosquatting patterns
        if any(typo in domain for typo in ['amaz0n', 'g00gle', 'paypa1', 'micr0soft']):
            risk_score += 35
            findings.append("Possible typosquatting domain detected")
            indicators.append("Typosquatting pattern")
            
    except Exception:
        pass
    
    # If we have significant findings, return local analysis
    if risk_score > 30:
        return {
            "risk_score": min(risk_score, 85),
            "analysis": f"Local analysis detected {len(findings)} suspicious indicators.",
            "confidence": 0.7,
            "key_findings": findings[:3],
            "technical_indicators": indicators[:3],
            "recommendations": ["Avoid clicking this link", "Verify the domain manually"],
            "confidence_explanation": "Analysis based on known phishing patterns",
            "local_analysis": True
        }
    
    return None

def local_email_analysis(email_content: str) -> Optional[Dict]:
    """Perform basic local analysis for common phishing patterns"""
    email_lower = email_content.lower()
    
    risk_score = 0
    findings = []
    indicators = []
    
    # Check for urgency indicators
    urgency_patterns = [
        r'urgent|immediate|action required|account suspended|limited time',
        r'verify.*account|confirm.*details|update.*information',
        r'click.*here|download.*attachment|open.*file',
        r'password.*expired|security.*alert|suspicious.*activity'
    ]
    
    for pattern in urgency_patterns:
        if re.search(pattern, email_lower):
            risk_score += 15
            findings.append("Contains urgency or pressure tactics")
            indicators.append(f"Urgency pattern: {pattern}")
    
    # Check for suspicious links
    url_patterns = re.findall(r'https?://[^\s<>"]+', email_content)
    for url in url_patterns:
        if any(pattern in url.lower() for pattern in ['bit.ly', 'tinyurl', 'goo.gl']):
            risk_score += 20
            findings.append("Contains shortened URLs")
            indicators.append("URL shortener detected")
    
    # Check for poor grammar (basic check)
    grammar_issues = [
        r'\b(?:you|your|we|our)\s+(?:account|password|security|bank)',
        r'\b(?:please|kindly)\s+(?:click|verify|confirm|update)',
        r'(?:important|urgent|critical)\s+(?:message|notice|alert)'
    ]
    
    for pattern in grammar_issues:
        if re.search(pattern, email_lower):
            risk_score += 10
            findings.append("Contains suspicious language patterns")
            indicators.append("Suspicious language pattern")
    
    # If we have significant findings, return local analysis
    if risk_score > 25:
        return {
            "risk_score": min(risk_score, 80),
            "analysis": f"Local analysis detected {len(findings)} suspicious indicators.",
            "confidence": 0.6,
            "key_findings": findings[:3],
            "technical_indicators": indicators[:3],
            "recommendations": ["Do not click any links", "Verify sender manually"],
            "confidence_explanation": "Analysis based on common phishing patterns",
            "local_analysis": True
        }
    
    return None

# Local Knowledge Base
def load_knowledge_base():
    try:
        with open('knowledge_base.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        # Fallback knowledge base if file doesn't exist
        return {
            "phishing_indicators": [
                "Urgency or pressure tactics",
                "Poor grammar and spelling",
                "Suspicious links or domains",
                "Requests for sensitive information",
                "Generic greetings",
                "Mismatched sender addresses",
                "Suspicious attachments",
                "Unusual payment requests",
                "Threats or consequences",
                "Too good to be true offers"
            ],
            "security_tips": [
                "Never click suspicious links",
                "Verify sender email addresses",
                "Don't share passwords or personal info via email",
                "Use two-factor authentication",
                "Keep software updated",
                "Check for HTTPS in URLs",
                "Be wary of urgent requests",
                "Don't trust unsolicited attachments",
                "Use strong, unique passwords",
                "Report suspicious emails to IT"
            ],
            "url_analysis_tips": [
                "Check the domain name carefully",
                "Look for HTTPS protocol",
                "Avoid shortened URLs",
                "Check for typos in domain names",
                "Verify the website's SSL certificate",
                "Use URL reputation services",
                "Check for redirects",
                "Look for suspicious subdomains"
            ],
            "email_analysis_tips": [
                "Check sender's email address",
                "Look for urgency in the message",
                "Verify the company's official domain",
                "Check for poor grammar",
                "Look for suspicious attachments",
                "Verify links before clicking",
                "Check email headers",
                "Look for generic greetings"
            ]
        }

KNOWLEDGE_BASE = load_knowledge_base()

# Define PhishingResult model
class PhishingResult(BaseModel):
    risk_score: int
    analysis: str
    confidence: float

# Define Enhanced PhishingResult model with more structured fields
class EnhancedPhishingResult(BaseModel):
    risk_score: int
    analysis: str
    confidence: float
    key_findings: List[str]
    technical_indicators: List[str] = []
    recommendations: List[str] = []
    confidence_explanation: str = ""
    
    @field_validator('risk_score')
    @classmethod
    def validate_risk_score(cls, v):
        if v < 0 or v > 100:
            raise ValueError('Risk score must be between 0 and 100')
        return v
    
    @field_validator('confidence')
    @classmethod
    def validate_confidence(cls, v):
        if v < 0 or v > 1:
            raise ValueError('Confidence must be between 0 and 1')
        return v

# Create agent with the model - Legacy implementation
class Agent:
    def __init__(self, output_type, model):
        self.output_type = output_type
        self.model = model

    def extract_risk_score(self, text: str) -> int:
        score_match = re.search(r'risk\s*score:?\s*(\d+)', text.lower())
        if score_match:
            return int(score_match.group(1))
        return 50

    def calculate_confidence(self, text: str) -> float:
        confidence = 0.5  # Base confidence
        
        # Check for definitive indicators
        definitive_indicators = [
            r'definitely|clearly|certainly|confirmed|verified',
            r'high risk|severe risk|critical risk',
            r'multiple indicators|several indicators',
            r'confirmed phishing|verified scam',
            r'known phishing pattern|known scam pattern'
        ]
        
        for pattern in definitive_indicators:
            if re.search(pattern, text.lower()):
                confidence += 0.1
        
        # Check for analysis depth
        if len(text.split()) > 100:  # Detailed analysis
            confidence += 0.1
        if len(text.split('\n')) > 5:  # Well-structured analysis
            confidence += 0.1
            
        # Check for specific technical indicators
        technical_indicators = [
            r'spam score|spf|dkim|dmarc',
            r'domain mismatch|email spoofing',
            r'ssl certificate|security certificate',
            r'ip address|dns record',
            r'header analysis|email header'
        ]
        
        for pattern in technical_indicators:
            if re.search(pattern, text.lower()):
                confidence += 0.05
        
        # Check for risk score correlation
        risk_score = self.extract_risk_score(text)
        if risk_score > 80:
            confidence += 0.1
        elif risk_score > 60:
            confidence += 0.05
            
        # Ensure confidence is between 0.5 and 0.95
        return min(max(confidence, 0.5), 0.95)

    def analyze(self, prompt: str) -> PhishingResult:
        response = self.model.generate_content(prompt)
        analysis_text = response.text

        risk_score = self.extract_risk_score(analysis_text)
        confidence = self.calculate_confidence(analysis_text)

        analysis_text = re.sub(r'risk\s*score:?\s*\d+', '', analysis_text, flags=re.IGNORECASE)
        analysis_text = re.sub(r'\n+', '\n', analysis_text).strip()

        return PhishingResult(
            risk_score=risk_score,
            analysis=analysis_text,
            confidence=confidence
        )

    def chat_response(self, message: str) -> str:
        """Generate a concise, website-relevant chat response using Gemini"""
        # Get relevant context
        context = self._get_relevant_context(message.lower())
        
        # Create focused, web-relevant prompt with reduced token usage
        enhanced_prompt = f"""
        Web security assistant. Brief, practical advice only.

        Context: {context}
        User: {message}

        Respond in 1-2 sentences. Focus on web safety. Use simple language.
        """
        
        try:
            response = self.model.generate_content(enhanced_prompt)
            return response.text.strip()
        except Exception as e:
            print(f"Error in chat response: {str(e)}")
            return "I'm here to help with web security. Use our URL or Email analysis tools for detailed checks."

    def _get_relevant_context(self, message: str) -> str:
        """Get concise, web-relevant context"""
        context_parts = []
        
        # Web-focused keywords
        if any(word in message for word in ['url', 'link', 'website', 'browse']):
            context_parts.append("URL SAFETY: Check domain, look for HTTPS, avoid shortened links")
        
        if any(word in message for word in ['email', 'mail', 'inbox']):
            context_parts.append("EMAIL SAFETY: Verify sender, check for urgency, don't click suspicious links")
        
        if any(word in message for word in ['password', 'login', 'account']):
            context_parts.append("ACCOUNT SAFETY: Use 2FA, strong passwords, never share via email")
        
        if any(word in message for word in ['safe', 'protect', 'secure']):
            context_parts.append("GENERAL: Keep software updated, use HTTPS, be wary of urgent requests")
        
        return " | ".join(context_parts) if context_parts else "Web security best practices"

# Create Pydantic AI Agent
class SecurityDependencies:
    knowledge_base: Dict

# Initialize Pydantic AI agent
pydantic_agent = PydanticAgent(
    'google-gla:gemini-1.5-flash',
    output_type=PhishingResult,
    system_prompt="""
    You are a web security assistant specialized in phishing detection. 
    Analyze URLs and emails for security threats and provide concise, practical advice.
    """
)

# Initialize advanced Pydantic AI agent with enhanced output
advanced_agent = PydanticAgent(
    'google-gla:gemini-1.5-flash',
    output_type=EnhancedPhishingResult,
    system_prompt="""
    You are an advanced web security expert specialized in phishing detection and cyber threat analysis.
    Provide detailed technical analysis of URLs and emails for security threats.
    Your analysis should include risk assessment, key findings, technical indicators, and actionable recommendations.
    """
)

@pydantic_agent.tool
async def get_knowledge_base_info(ctx: RunContext, category: str) -> List[str]:
    """
    Retrieve information from the security knowledge base.
    
    Args:
        category: The category of information to retrieve (phishing_indicators, security_tips, 
                url_analysis_tips, email_analysis_tips)
    """
    if category in KNOWLEDGE_BASE:
        return KNOWLEDGE_BASE[category]
    return ["Information not found for the specified category"]

@advanced_agent.tool
async def get_detailed_knowledge(ctx: RunContext, category: str) -> List[str]:
    """
    Retrieve detailed information from the security knowledge base.
    
    Args:
        category: The category of information to retrieve (phishing_indicators, security_tips, 
                url_analysis_tips, email_analysis_tips)
    """
    if category in KNOWLEDGE_BASE:
        return KNOWLEDGE_BASE[category]
    return ["Information not found for the specified category"]

@advanced_agent.tool
async def compare_with_known_patterns(ctx: RunContext, content_type: str, content: str) -> Dict:
    """
    Compare the provided content with known phishing patterns from the knowledge base.
    
    Args:
        content_type: The type of content ('url' or 'email')
        content: The content to analyze
    """
    # Get relevant patterns based on content type
    patterns = []
    matched_patterns = []
    
    # Get phishing indicators from knowledge base
    indicators = KNOWLEDGE_BASE.get("phishing_indicators", [])
    
    # Add content-specific patterns
    if content_type == "url":
        # URL-specific patterns
        url_patterns = [
            "shortened URL",
            "misspelled domain",
            "suspicious TLD",
            "numeric IP address",
            "excessive subdomains",
            "HTTP instead of HTTPS"
        ]
        patterns.extend(url_patterns)
    else:
        # Email-specific patterns
        email_patterns = [
            "urgent request",
            "grammatical errors",
            "generic greeting",
            "mismatched sender",
            "suspicious attachment",
            "request for sensitive information"
        ]
        patterns.extend(email_patterns)
    
    # Add general phishing indicators
    patterns.extend(indicators)
    
    # Check for matches (simple substring matching for demo purposes)
    # In a real implementation, you would use more sophisticated pattern matching
    content_lower = content.lower()
    for pattern in patterns:
        pattern_lower = pattern.lower()
        if pattern_lower in content_lower:
            matched_patterns.append(pattern)
    
    # Calculate match percentage
    match_percentage = (len(matched_patterns) / len(patterns)) * 100 if patterns else 0
    
    return {
        "matched_patterns": matched_patterns,
        "total_patterns": len(patterns),
        "match_percentage": min(match_percentage, 100),  # Cap at 100%
        "risk_level": "High" if match_percentage > 50 else "Medium" if match_percentage > 20 else "Low"
    }

# Use legacy agent for now
agent = Agent(output_type=PhishingResult, model=model)

app = Flask(__name__)
CORS(app)

# Pydantic models for request validation
class URLRequest(BaseModel):
    url: HttpUrl

    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        if not v or len(str(v).strip()) == 0:
            raise ValueError('URL cannot be empty')
        return v

class EmailRequest(BaseModel):
    email_content: str

    @field_validator('email_content')
    @classmethod
    def validate_email_content(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Email content cannot be empty')
        return v.strip()

class ChatRequest(BaseModel):
    message: str

    @field_validator('message')
    @classmethod
    def validate_message(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Message cannot be empty')
        return v.strip()

def analyze_with_gemini(prompt: str) -> PhishingResult:
    try:
        return agent.analyze(prompt)
    except Exception as e:
        print(f"Error in Gemini analysis: {str(e)}")
        raise

def analyze_with_pydantic_ai(prompt: str) -> PhishingResult:
    """Use Pydantic AI agent for analysis"""
    try:
        result = pydantic_agent.run_sync(prompt)
        return result.data
    except Exception as e:
        print(f"Error in Pydantic AI analysis: {str(e)}")
        # Fall back to legacy agent
        return analyze_with_gemini(prompt)

def classify_risk(risk_score: int) -> str:
    """Classify risk score into Safe, Suspicious, or Dangerous"""
    if risk_score > 70:
        return "Dangerous"
    elif risk_score > 40:
        return "Suspicious"
    else:
        return "Safe"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/chat', methods=['POST'])
@rate_limit
def chat():
    try:
        if not request.json or 'message' not in request.json:
            return jsonify({"error": "Message is required"}), 400
            
        data = ChatRequest(**request.json)
        message_lower = data.message.lower()

        # Keywords that trigger a redirect to the URL analysis page
        url_keywords = ['analyze url', 'check a url', 'scan a url']
        if any(keyword in message_lower for keyword in url_keywords):
            return jsonify({
                "response": "Of course! Let's get that URL analyzed. I'm taking you to the URL Analysis page now.",
                "redirect": "home"
            })

        # Keywords that trigger a redirect to the email analysis page
        email_keywords = ['analyze email', 'check an email', 'scan an email']
        if any(keyword in message_lower for keyword in email_keywords):
            return jsonify({
                "response": "You got it. I'm redirecting you to the Email Analysis page so you can paste in the content.",
                "redirect": "email"
            })
        
        # Check for common questions that can be answered from knowledge base
        common_questions = {
            'phishing': ['what is phishing', 'how to spot phishing', 'phishing signs'],
            'security': ['security tips', 'how to stay safe', 'protect myself'],
            'urls': ['url safety', 'checking links', 'safe browsing'],
            'emails': ['email safety', 'suspicious emails', 'email security']
        }
        
        for category, keywords in common_questions.items():
            if any(keyword in message_lower for keyword in keywords):
                # Use knowledge base instead of AI for common questions
                if category == 'phishing':
                    tips = KNOWLEDGE_BASE.get('phishing_indicators', [])[:3]
                    response = f"Here are key phishing signs: {', '.join(tips)}. Always verify before clicking!"
                elif category == 'security':
                    tips = KNOWLEDGE_BASE.get('security_tips', [])[:3]
                    response = f"Top security tips: {', '.join(tips)}. Stay vigilant online!"
                elif category == 'urls':
                    tips = KNOWLEDGE_BASE.get('url_analysis_tips', [])[:3]
                    response = f"URL safety tips: {', '.join(tips)}. Use our URL analyzer for detailed checks!"
                elif category == 'emails':
                    tips = KNOWLEDGE_BASE.get('email_analysis_tips', [])[:3]
                    response = f"Email safety tips: {', '.join(tips)}. Use our email analyzer for suspicious messages!"
                
                return jsonify({
                    "response": response,
                    "redirect": None
                })
        
        # If no redirect or common question, generate a standard chat response
        response = agent.chat_response(data.message)
        
        return jsonify({
            "response": response,
            "redirect": None
        })
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        print(f"Error in chat: {str(e)}")
        return jsonify({"error": "An error occurred while processing your message. Please try again."}), 500

@app.route('/api/analyze/url', methods=['POST'])
@rate_limit
def analyze_url():
    try:
        if not request.json or 'url' not in request.json:
            return jsonify({"error": "URL is required"}), 400
            
        data = URLRequest(**request.json)
        url = str(data.url)
        
        # Check cache first
        cache_key = get_cache_key('url', url)
        cached_result = get_cached_result(cache_key)
        if cached_result:
            return jsonify(cached_result)
        
        # Try local analysis first (cost-free)
        local_result = local_url_analysis(url)
        if local_result:
            # Cache the local result
            cache_result(cache_key, local_result)
            return jsonify(local_result)
        
        # If local analysis doesn't find significant issues, use AI
        prompt = f"""
        Analyze this URL for web security threats: {url}

        Provide a concise analysis in this format:
        Risk Score: [0-100]
        
        Key Findings:
        - [2-3 most important findings]
        
        Indicators:
        - [specific threats found]
        
        Recommendation:
        [One sentence advice]

        Focus on: domain legitimacy, HTTPS, suspicious patterns, redirects.
        Keep analysis brief and practical for web users.
        """
        
        # Use Pydantic AI for URL analysis
        try:
            result = analyze_with_pydantic_ai(prompt)
            response_data = {
                "analysis": result.analysis,
                "risk_score": result.risk_score,
                "confidence": result.confidence,
                "classification": classify_risk(result.risk_score)
            }
        except:
            # Fall back to legacy agent if Pydantic AI fails
            result = analyze_with_gemini(prompt)
            response_data = {
                "analysis": result.analysis,
                "risk_score": result.risk_score,
                "confidence": result.confidence,
                "classification": classify_risk(result.risk_score)
            }
        
        # Cache the AI result
        cache_result(cache_key, response_data)
        return jsonify(response_data)
        
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        print(f"Error in URL analysis: {str(e)}")
        return jsonify({"error": "An error occurred while analyzing the URL. Please try again."}), 500

@app.route('/api/analyze/email', methods=['POST'])
@rate_limit
def analyze_email():
    try:
        if not request.json or 'email_content' not in request.json:
            return jsonify({"error": "Email content is required"}), 400
            
        data = EmailRequest(**request.json)
        email_content = data.email_content
        
        # Check cache first
        cache_key = get_cache_key('email', email_content)
        cached_result = get_cached_result(cache_key)
        if cached_result:
            return jsonify(cached_result)
        
        # Try local analysis first (cost-free)
        local_result = local_email_analysis(email_content)
        if local_result:
            # Cache the local result
            cache_result(cache_key, local_result)
            return jsonify(local_result)
        
        # If local analysis doesn't find significant issues, use AI
        prompt = f"""
        Analyze this email for web security threats: {email_content}

        Provide a concise analysis in this format:
        Risk Score: [0-100]
        
        Key Findings:
        - [2-3 most important findings]
        
        Indicators:
        - [specific threats found]
        
        Recommendation:
        [One sentence advice]

        Focus on: sender legitimacy, urgency tactics, suspicious links, grammar errors.
        Keep analysis brief and practical for web users.
        """
        
        # Use Pydantic AI for email analysis
        try:
            result = analyze_with_pydantic_ai(prompt)
            response_data = {
                "analysis": result.analysis,
                "risk_score": result.risk_score,
                "confidence": result.confidence,
                "classification": classify_risk(result.risk_score)
            }
        except:
            # Fall back to legacy agent if Pydantic AI fails
            result = analyze_with_gemini(prompt)
            response_data = {
                "analysis": result.analysis,
                "risk_score": result.risk_score,
                "confidence": result.confidence,
                "classification": classify_risk(result.risk_score)
            }
        
        # Cache the AI result
        cache_result(cache_key, response_data)
        return jsonify(response_data)
        
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        print(f"Error in email analysis: {str(e)}")
        return jsonify({"error": "An error occurred while analyzing the email. Please try again."}), 500

@app.route('/api/knowledge-base', methods=['GET'])
def get_knowledge_base():
    """Endpoint to get knowledge base information"""
    return jsonify(KNOWLEDGE_BASE)

@app.route('/api/advanced-analysis', methods=['POST'])
@rate_limit
def advanced_analysis():
    """Advanced analysis endpoint using Pydantic AI's full capabilities"""
    try:
        if not request.json:
            return jsonify({"error": "Request data is required"}), 400
            
        # Handle both URL and email analysis in one endpoint
        content_type = request.json.get('type', 'unknown')
        content = request.json.get('content', '')
        
        if not content:
            return jsonify({"error": "Content is required"}), 400
        
        # Check cache first
        cache_key = get_cache_key(f'advanced_{content_type}', content)
        cached_result = get_cached_result(cache_key)
        if cached_result:
            return jsonify(cached_result)
            
        if content_type == 'url':
            # Validate URL
            try:
                url_data = URLRequest(url=content)
                analysis_type = "URL"
                
                # Extract domain for reputation check
                from urllib.parse import urlparse
                parsed_url = urlparse(content)
                domain = parsed_url.netloc
            except Exception as e:
                return jsonify({"error": f"Invalid URL: {str(e)}"}), 400
        elif content_type == 'email':
            # Validate email content
            if len(content.strip()) == 0:
                return jsonify({"error": "Email content cannot be empty"}), 400
            analysis_type = "Email"
            domain = None
        else:
            return jsonify({"error": "Type must be either 'url' or 'email'"}), 400
        
        # Try local analysis first for obvious cases
        if content_type == 'url':
            local_result = local_url_analysis(content)
        else:
            local_result = local_email_analysis(content)
            
        if local_result and local_result.get('risk_score', 0) > 60:
            # If local analysis finds high-risk content, use it and skip AI
            cache_result(cache_key, local_result)
            return jsonify(local_result)
        
        # Create a structured prompt for the AI
        prompt = f"""
        Perform an advanced security analysis on this {analysis_type}: {content}

        Provide a detailed analysis with the following structure:
        Risk Score: [0-100]
        
        Key Findings:
        - [3-5 detailed findings]
        
        Technical Indicators:
        - [List all technical indicators found]
        
        Security Recommendations:
        - [2-3 specific recommendations]
        
        Confidence Assessment:
        [Explanation of confidence level]
        
        Focus on: technical details, security patterns, threat intelligence, and actionable advice.
        """
        
        # Use advanced Pydantic AI agent
        try:
            # Create a more structured analysis with advanced Pydantic AI agent
            result = advanced_agent.run_sync(prompt)
            
            # Extract additional insights
            additional_context = {}
            
            # Get relevant knowledge base information based on content type
            if content_type == 'url':
                kb_category = 'url_analysis_tips'
            else:
                kb_category = 'email_analysis_tips'
            
            # Compare with known phishing patterns
            try:
                pattern_match = compare_with_known_patterns.run_sync(None, content_type, content)
                additional_context['pattern_match'] = pattern_match
            except Exception as e:
                print(f"Error comparing with known patterns: {str(e)}")
            
            # Get relevant tips from knowledge base
            try:
                additional_context['tips'] = get_detailed_knowledge.run_sync(None, kb_category)
            except Exception as e:
                print(f"Error getting knowledge base info: {str(e)}")
                additional_context['tips'] = KNOWLEDGE_BASE.get(kb_category, [])
            
            # Format response using the enhanced model
            response_data = {
                "analysis": result.data.analysis,
                "risk_score": result.data.risk_score,
                "confidence": result.data.confidence,
                "classification": classify_risk(result.data.risk_score),
                "key_findings": result.data.key_findings,
                "technical_indicators": result.data.technical_indicators,
                "recommendations": result.data.recommendations,
                "confidence_explanation": result.data.confidence_explanation,
                "additional_context": additional_context
            }
            
            # Cache the result
            cache_result(cache_key, response_data)
            return jsonify(response_data)
            
        except Exception as e:
            print(f"Error in advanced analysis: {str(e)}")
            # Fall back to legacy agent
            result = analyze_with_gemini(prompt)
            response_data = {
                "analysis": result.analysis,
                "risk_score": result.risk_score,
                "confidence": result.confidence,
                "classification": classify_risk(result.risk_score),
                "fallback": True
            }
            
            # Cache the fallback result
            cache_result(cache_key, response_data)
            return jsonify(response_data)
            
    except Exception as e:
        print(f"Error in advanced analysis: {str(e)}")
        return jsonify({"error": "An error occurred while performing the analysis. Please try again."}), 500

@app.route('/api/cache/stats', methods=['GET'])
def cache_stats():
    """Get cache statistics for monitoring"""
    with cache_lock:
        cache_size = len(analysis_cache)
        cache_hit_rate = 0  # This would need to be tracked separately
        
    with rate_limit_lock:
        active_users = len(rate_limit_storage)
        
    return jsonify({
        "cache_size": cache_size,
        "max_cache_size": MAX_CACHE_SIZE,
        "cache_ttl_seconds": CACHE_TTL,
        "active_users": active_users,
        "rate_limit_per_minute": MAX_REQUESTS_PER_MINUTE,
        "rate_limit_per_hour": MAX_REQUESTS_PER_HOUR
    })

@app.route('/api/cache/clear', methods=['POST'])
def clear_cache():
    """Clear the analysis cache"""
    with cache_lock:
        analysis_cache.clear()
    return jsonify({"message": "Cache cleared successfully"})

def cleanup_expired_cache():
    """Clean up expired cache entries"""
    current_time = time.time()
    with cache_lock:
        expired_keys = [
            key for key, data in analysis_cache.items()
            if current_time - data['timestamp'] > CACHE_TTL
        ]
        for key in expired_keys:
            del analysis_cache[key]
        if expired_keys:
            print(f"Cleaned up {len(expired_keys)} expired cache entries")

# Schedule cache cleanup every 30 minutes
def schedule_cache_cleanup():
    """Schedule periodic cache cleanup"""
    def cleanup_loop():
        while True:
            time.sleep(1800)  # 30 minutes
            cleanup_expired_cache()
    
    cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
    cleanup_thread.start()

# Start cache cleanup on app startup
schedule_cache_cleanup()

if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=True, port=3000) 