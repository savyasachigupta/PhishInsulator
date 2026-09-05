# 🛡️ PhishInsulator

### AI-Powered Phishing Detection & Risk Assessment

PhishInsulator is a cybersecurity-focused phishing detection system that analyzes **URLs and message content** using machine learning, natural language processing, and multi-signal risk assessment.

The system combines URL-based machine learning with multilingual text analysis to estimate phishing risk and classify suspicious inputs into different threat levels.

---

## 🎯 Problem

Phishing attacks often combine deceptive URLs with convincing social-engineering messages.

Traditional detection approaches that inspect only one signal can miss sophisticated attacks.

PhishInsulator addresses this by analyzing multiple characteristics of a potentially malicious input and combining the resulting signals into an overall risk assessment.

---

## ⚙️ How It Works

```text
                 ┌─────────────────────┐
                 │   User Input        │
                 │ URL / Message Text  │
                 └──────────┬──────────┘
                            │
              ┌─────────────┴─────────────┐
              │                           │
              ▼                           ▼
     ┌─────────────────┐        ┌─────────────────┐
     │  URL Analysis   │        │  Text Analysis  │
     │  Random Forest  │        │ Multilingual NLP│
     └────────┬────────┘        └────────┬────────┘
              │                          │
              ▼                          ▼
        URL Risk Score             Text Risk Score
              │                          │
              └─────────────┬────────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │   Decision Fusion   │
                 │   Risk Assessment   │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │  Threat Level       │
                 │ Minimal → Critical  │
                 └─────────────────────┘
```

---

## 🔍 Detection Pipeline

### 1. URL Analysis

The URL analysis component extracts characteristics from URLs and uses a **Random Forest** machine-learning model to estimate phishing probability.

Features include URL-related structural and lexical characteristics used to distinguish suspicious URLs from legitimate ones.

**Technology:** Python · Scikit-learn · Random Forest

---

### 2. Text & NLP Analysis

The text analysis component evaluates message content for indicators commonly associated with phishing and social engineering.

The pipeline includes:

- Multilingual language detection
- BERT-based text representation
- Suspicious keyword and pattern detection
- Sentiment analysis
- Linguistic feature extraction
- Phishing-related content indicators

The project uses:

**`bert-base-multilingual-cased`**

This allows the system to process text across multiple languages.

---

### 3. Decision Fusion

The individual analysis signals are combined into an overall risk assessment.

Current configured weighting:

| Signal | Weight |
|---|---:|
| URL Analysis | 30% |
| Text Analysis | 40% |
| Metadata | 20% |
| Behavioral Analysis | 10% |

> **Note:** Metadata and behavioral components are currently represented through simulated/placeholder analysis in the existing implementation and are intended for future expansion.

---

## 🚨 Risk Classification

The resulting risk score is mapped to a threat level:

| Risk Score | Classification |
|---:|---|
| `< 0.30` | 🟢 Minimal |
| `0.30 – < 0.60` | 🔵 Low |
| `0.60 – < 0.80` | 🟡 Medium |
| `0.80 – < 0.90` | 🟠 High |
| `≥ 0.90` | 🔴 Critical |

This provides an interpretable security assessment rather than returning only a binary phishing/legitimate result.

---

## 🖥️ Application

The project contains a React-based frontend connected to a Flask backend API.

### Frontend

The frontend provides the user interface for submitting inputs and displaying the resulting security assessment.

### Backend

The Flask API processes the submitted input and coordinates the analysis pipeline.

The primary analysis endpoint is:

```text
POST /api/analyze
```

---

## 🧰 Tech Stack

### Languages

- Python
- JavaScript

### Machine Learning & NLP

- Scikit-learn
- Random Forest
- BERT
- Transformers
- Natural Language Processing

### Backend

- Flask
- Python

### Frontend

- React
- HTML
- CSS
- JavaScript

### Security Domain

- Phishing Detection
- Social Engineering Detection
- URL Analysis
- Risk Scoring
- Threat Classification

---

## 📂 Project Structure

```text
PhishInsulator/
│
├── App.js
├── App.css
├── App.test.js
├── package.json
│
├── main_api.py
├── url_analysis_node.py
├── text_content_node.py
├── decision_fusion.py
├── train_models.py
│
├── config.yaml
├── requirements.txt
│
└── README.md
```

> **Note:** The repository structure is currently being cleaned and reorganized. Some legacy or duplicate files may still be present and will be removed after validating their dependencies.

---

## 🚀 Getting Started

### Prerequisites

Make sure you have:

- Python 3.x
- Node.js
- npm
- Git

### Backend Setup

Clone the repository:

```bash
git clone https://github.com/savyasachigupta/PhishInsulator.git
cd PhishInsulator
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Start the Flask backend:

```bash
python main_api.py
```

### Frontend Setup

Open another terminal:

```bash
npm install
```

Start the React development server:

```bash
npm start
```

The frontend will communicate with the Flask API running locally.

---

## 🔬 Model Development

The project includes a model-training component for the URL analysis pipeline.

The general development workflow is:

```text
Dataset
   ↓
Feature Extraction
   ↓
Model Training
   ↓
Random Forest Model
   ↓
URL Risk Prediction
   ↓
Decision Fusion
```

---

## 🔐 Security Considerations

PhishInsulator is intended as a **defensive cybersecurity research and learning project**.

Important considerations for future production deployment include:

- Secure API communication
- Input validation and sanitization
- Rate limiting
- Model robustness testing
- Adversarial URL testing
- False-positive/false-negative evaluation
- Secure handling of submitted messages
- Authentication and authorization
- Logging and monitoring
- Protection against model abuse

---

## 🗺️ Roadmap

### Current

- [x] URL-based phishing analysis
- [x] Random Forest classification
- [x] Multilingual text analysis
- [x] BERT-based NLP processing
- [x] Phishing keyword/pattern detection
- [x] Risk scoring
- [x] Decision fusion
- [x] React frontend
- [x] Flask API

### Planned

- [ ] Replace simulated metadata analysis with real signals
- [ ] Implement behavioral analysis
- [ ] Expand phishing datasets
- [ ] Improve model evaluation metrics
- [ ] Add explainable AI for individual predictions
- [ ] Add URL reputation intelligence
- [ ] Add domain/WHOIS-based signals
- [ ] Add automated model evaluation
- [ ] Containerized deployment
- [ ] Production-grade API security

---

## 📊 Future Architecture

The long-term goal is to evolve PhishInsulator into a broader phishing intelligence platform:

```text
URL
 │
 ├── Lexical Analysis
 ├── Domain Intelligence
 ├── Reputation Signals
 └── ML Classification
          │
          ▼
Message
 │
 ├── NLP Analysis
 ├── Language Detection
 ├── Social Engineering Signals
 └── Semantic Analysis
          │
          ▼
   ┌───────────────────┐
   │  Decision Fusion  │
   └─────────┬─────────┘
             │
             ▼
      Threat Assessment
             │
             ▼
      Explainable Result
```

---

## ⚠️ Disclaimer

PhishInsulator is a cybersecurity research and educational project.

It should **not be treated as a replacement for enterprise security products, threat intelligence platforms, or professional security analysis**.

Detection results may contain false positives or false negatives.

---

## 👨‍💻 Author

**Savyasachi Gupta**

Cybersecurity · Software Development · Machine Learning

- GitHub: https://github.com/savyasachigupta
- LinkedIn: https://www.linkedin.com/in/savyasachi-gupta-a03211374/
- LeetCode: https://leetcode.com/u/code-kht/

---

<p align="center">

### 🛡️ Building. Learning. Securing.

</p>
