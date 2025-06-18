from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import google.generativeai as genai
from pydantic import BaseModel, HttpUrl
from typing import Optional, List
import os
import re
from pydantic import validator

# Set Gemini API key directly
os.environ['GOOGLE_API_KEY'] = 'AIzaSyDDomIGM7rf41xk9Jsmx63rGMj85Uh3QKY'

# Configure Gemini
genai.configure(api_key=os.environ['GOOGLE_API_KEY'])
model = genai.GenerativeModel("gemini-1.5-flash")

# Define PhishingResult model
class PhishingResult(BaseModel):
    risk_score: int
    analysis: str
    indicators: List[str]
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

    def extract_indicators(self, text: str) -> List[str]:
        indicators = []
        indicator_patterns = [
            r'urgency',
            r'suspicious',
            r'grammar',
            r'spelling',
            r'domain',
            r'certificate',
            r'legitimate',
            r'branding',
            r'inconsistencies',
            r'pressure tactics',
            r'phishing',
            r'scam',
            r'fake',
            r'fraudulent'
        ]
        
        for pattern in indicator_patterns:
            if re.search(pattern, text.lower()):
                sentences = text.split('.')
                for sentence in sentences:
                    if pattern in sentence.lower():
                        indicators.append(sentence.strip())
        
        return indicators[:5]

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
        indicators = self.extract_indicators(analysis_text)
        confidence = self.calculate_confidence(analysis_text)

        analysis_text = re.sub(r'risk\s*score:?\s*\d+', '', analysis_text, flags=re.IGNORECASE)
        analysis_text = re.sub(r'\n+', '\n', analysis_text).strip()

        return PhishingResult(
            risk_score=risk_score,
            analysis=analysis_text,
            indicators=indicators,
            confidence=confidence
        )

agent = Agent(output_type=PhishingResult, model=model)

app = Flask(__name__)
CORS(app)

# Pydantic models for request validation
class URLRequest(BaseModel):
    url: HttpUrl

    @validator('url')
    def validate_url(cls, v):
        if not v or len(str(v).strip()) == 0:
            raise ValueError('URL cannot be empty')
        return v

class EmailRequest(BaseModel):
    email_content: str

    @validator('email_content')
    def validate_email_content(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Email content cannot be empty')
        return v.strip()

def analyze_with_gemini(prompt: str) -> PhishingResult:
    try:
        return agent.analyze(prompt)
    except Exception as e:
        print(f"Error in Gemini analysis: {str(e)}")
        raise

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/analyze/url', methods=['POST'])
def analyze_url():
    try:
        if not request.json or 'url' not in request.json:
            return jsonify({"error": "URL is required"}), 400
            
        data = URLRequest(**request.json)
        prompt = f"""
        Analyze this URL for phishing: {data.url}

        Provide a concise analysis in this exact format:
        Risk Score: [0-100]
        
        Key Findings:
        - [List 3-4 most important findings]
        
        Indicators:
        - [List specific phishing indicators found]
        
        Recommendation:
        [One sentence recommendation]

        Keep the analysis brief and focused on critical security aspects.
        """
        
        result = analyze_with_gemini(prompt)
        return jsonify({
            "analysis": result.analysis,
            "risk_score": result.risk_score,
            "indicators": result.indicators,
            "confidence": result.confidence
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
        Analyze this email for phishing: {data.email_content}

        Provide a concise analysis in this exact format:
        Risk Score: [0-100]
        
        Key Findings:
        - [List 3-4 most important findings]
        
        Indicators:
        - [List specific phishing indicators found]
        
        Recommendation:
        [One sentence recommendation]

        Focus on:
        1. Sender information and email address legitimacy
        2. Urgency or pressure tactics in the content
        3. Suspicious links or attachments
        4. Grammar and spelling errors
        5. Request for sensitive information
        6. Email header analysis
        7. Domain and email address mismatches
        8. Generic greetings or poor personalization
        """
        
        result = analyze_with_gemini(prompt)
        return jsonify({
            "analysis": result.analysis,
            "risk_score": result.risk_score,
            "indicators": result.indicators,
            "confidence": result.confidence
        })
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        print(f"Error in email analysis: {str(e)}")
        return jsonify({"error": "An error occurred while analyzing the email. Please try again."}), 500

if __name__ == '__main__':
    app.run(debug=True) 