from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import google.generativeai as genai
from pydantic import BaseModel, HttpUrl, field_validator
from typing import Optional, List, Dict
import os
import re
import json
from datetime import datetime

# Set Gemini API key directly
os.environ['GOOGLE_API_KEY'] = 'AIzaSyDDomIGM7rf41xk9Jsmx63rGMj85Uh3QKY'

# Configure Gemini
genai.configure(api_key=os.environ['GOOGLE_API_KEY'])
model = genai.GenerativeModel("gemini-1.5-flash")

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

# Create agent with the model
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
        
        # Create focused, web-relevant prompt
        enhanced_prompt = f"""
        You are a web security assistant. Provide concise, practical advice for online users.

        CONTEXT: {context}

        USER: {message}

        Respond with:
        - Brief, actionable advice (2-3 sentences max)
        - Focus on web browsing, email, and online safety
        - Use simple language
        - If they ask about analysis tools, guide them to use our URL/Email analysis pages
        - Keep responses under 100 words
        """
        
        try:
            response = self.model.generate_content(enhanced_prompt)
            return response.text.strip()
        except Exception as e:
            return "I'm having trouble right now. Please try our analysis tools directly."

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
        
        # If no redirect, generate a standard chat response
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
def analyze_url():
    try:
        if not request.json or 'url' not in request.json:
            return jsonify({"error": "URL is required"}), 400
            
        data = URLRequest(**request.json)
        prompt = f"""
        Analyze this URL for web security threats: {data.url}

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
        
        result = analyze_with_gemini(prompt)
        return jsonify({
            "analysis": result.analysis,
            "risk_score": result.risk_score,
            "confidence": result.confidence,
            "classification": classify_risk(result.risk_score)
        })
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        print(f"Error in URL analysis: {str(e)}")
        return jsonify({"error": "An error occurred while analyzing the URL. Please try again."}), 500

@app.route('/api/analyze/email', methods=['POST'])
def analyze_email():
    try:
        if not request.json or 'email_content' not in request.json:
            return jsonify({"error": "Email content is required"}), 400
            
        data = EmailRequest(**request.json)
        prompt = f"""
        Analyze this email for web security threats: {data.email_content}

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
        
        result = analyze_with_gemini(prompt)
        return jsonify({
            "analysis": result.analysis,
            "risk_score": result.risk_score,
            "confidence": result.confidence,
            "classification": classify_risk(result.risk_score)
        })
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        print(f"Error in email analysis: {str(e)}")
        return jsonify({"error": "An error occurred while analyzing the email. Please try again."}), 500

@app.route('/api/knowledge-base', methods=['GET'])
def get_knowledge_base():
    """Endpoint to get knowledge base information"""
    return jsonify(KNOWLEDGE_BASE)

if __name__ == '__main__':
    app.run(debug=True, port=3000) 