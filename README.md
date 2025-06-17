# Phishing Detection System

A comprehensive phishing detection system that can analyze URLs, images, and emails for potential phishing attempts using Google's Gemini 1.5 AI model.

## Features

- URL Phishing Detection
- Image Phishing Detection
- Email Phishing Detection
- Modern Web Interface
- Real-time Analysis

## Setup

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Create a `.env` file in the root directory and add your Google API key:
   ```
   GOOGLE_API_KEY=your_api_key_here
   ```
4. Run the application:
   ```bash
   python app.py
   ```

## Usage

1. Open your browser and navigate to `http://localhost:5000`
2. Choose the type of content you want to analyze (URL, Image, or Email)
3. Input the content and click "Analyze"
4. View the detailed analysis results

## Security Note

This tool is for educational and defensive purposes only. Always use it responsibly and ethically. 