# PhishGuard Pro - AI-Powered Phishing Detection

An advanced phishing detection system powered by Google's Gemini AI, featuring a chatbot interface and comprehensive knowledge base.

## Features

### 🤖 AI Chatbot Interface
- **Interactive Chat**: Chat with an AI assistant about phishing detection and security
- **Gemini Integration**: Powered by Google's Gemini 1.5 Flash model
- **Smart Redirection**: Automatically redirects to analysis tools when requested
- **Quick Actions**: Pre-built buttons for common security questions

### 🔍 Analysis Tools
- **URL Analysis**: Check any URL for phishing threats
- **Email Analysis**: Analyze email content for suspicious indicators
- **Real-time Results**: Get instant risk assessments and detailed reports
- **Risk Scoring**: 0-100 risk scores with confidence levels

### 📚 Knowledge Base
- **Local Knowledge Base**: Comprehensive security information stored locally
- **Multiple Categories**: 
  - Phishing Indicators
  - Security Tips
  - URL Analysis Tips
  - Email Analysis Tips
  - Red Flags
  - Common Phishing Scenarios
- **Easy Management**: JSON-based knowledge base for easy updates

### 🎨 Modern Interface
- **Responsive Design**: Works on desktop and mobile devices
- **Separate Pages**: Dedicated pages for different analysis types
- **Professional UI**: Clean, modern interface with smooth animations
- **Navigation**: Easy switching between chat, analysis, and information pages

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd phishguard-pro
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up API key**
   - Get a Google Gemini API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
   - Update the API key in `app.py` (line 10)

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Access the application**
   - Open your browser and go to `http://localhost:5000`

## Usage

### Chat Interface
1. Start on the home page with the chatbot
2. Ask questions about phishing detection, security tips, or how to use the tools
3. Use quick action buttons for common tasks
4. The AI will automatically redirect you to analysis tools when needed

### URL Analysis
1. Navigate to the URL Analysis page
2. Enter a complete URL (including http:// or https://)
3. Click "Analyze URL" to get detailed security analysis
4. Review risk score, indicators, and recommendations

### Email Analysis
1. Navigate to the Email Analysis page
2. Paste the complete email content (including headers if possible)
3. Click "Analyze Email" for comprehensive analysis
4. Review detailed findings and security recommendations

### Knowledge Base
1. Visit the About page to see the complete knowledge base
2. Browse different categories of security information
3. Use this information to better understand phishing threats

## Knowledge Base Management

The knowledge base is stored in `knowledge_base.json` and includes:

- **Phishing Indicators**: Common signs of phishing attempts
- **Security Tips**: Best practices for staying safe online
- **URL Analysis Tips**: How to check URLs for threats
- **Email Analysis Tips**: How to analyze emails for phishing
- **Red Flags**: Warning signs that indicate potential threats
- **Common Scenarios**: Typical phishing attack patterns

To update the knowledge base:
1. Edit `knowledge_base.json`
2. Add new entries to any category
3. Restart the application to load changes

## API Endpoints

- `GET /` - Main application interface
- `POST /api/chat` - Chat with AI assistant
- `POST /api/analyze/url` - Analyze URLs for phishing
- `POST /api/analyze/email` - Analyze emails for phishing
- `GET /api/knowledge-base` - Get knowledge base data

## Technology Stack

- **Backend**: Flask (Python)
- **AI Model**: Google Gemini 1.5 Flash
- **Frontend**: HTML, CSS (Tailwind), JavaScript
- **Validation**: Pydantic
- **Knowledge Base**: JSON

## Security Features

- **Input Validation**: All inputs are validated using Pydantic
- **Error Handling**: Comprehensive error handling and user feedback
- **No Data Storage**: Analysis results are not stored on the server
- **API Key Security**: API keys are handled securely

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support or questions, please open an issue in the repository or contact the development team.

---

**Note**: This is a development server. For production deployment, use a proper WSGI server like Gunicorn or uWSGI. 
