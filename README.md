![Python](https://img.shields.io/badge/Python-3.10-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

# 🛡️ NeuroDefender AI: Cyber Threat Classifier

**NeuroDefender** is a powerful AI-driven cybersecurity tool designed to detect and classify a wide range of cyber threats using advanced machine learning techniques.

---

## 📚 Contents

- [🚀 Features](#-features)
- [🧠 Supported Threat Categories](#-supported-threat-categories)
- [🗂️ Project Structure](#️-project-structure)
- [⚙️ Installation & Usage](#️-installation--usage)
- [🖼️ Screenshots](#️-screenshots)
- [🧪 Dataset & Training](#-dataset--training)
- [📜 License](#-license)
- [💡 Inspiration](#-inspiration)
- [👤 Author](#-author)

---

## 🚀 Features

- ✅ Detects and classifies 25+ types of cyber attacks
- 🔍 Works with real-time traffic using CICFlowMeter
- 🧠 Powered by LightGBM with noise-augmented training
- 🌐 Bilingual web interface (Flask + HTML/CSS/JS)
- 📊 Explainable AI (SHAP & LIME support)
- 🔐 Ideal for SOCs, analysts, and intelligent firewalls

---

## 🧠 Supported Threat Categories

- DDoS, DoS (GoldenEye, Hulk, Slowloris, SlowHTTPTest)
- Bruteforce (SSH, FTP, Telnet, MQTT)
- Ransomware, Bot, Infiltration
- Portscan, MITM, XSS, SQL Injection
- And more...

---

## 🗂️ Project Structure

neurodefender/
├── app.py # Flask app entry point

├── model/ # Trained ML models (joblib)

├── static/ # NeuroDefender logo & assets

├── templates/ # HTML templates, CSS, JS

├── utils/ # SHAP, LIME explainers and helpers

├── cicflowmeter/ # Traffic flow extraction (Java tool)

---

## ⚙️ Installation & Usage

### 1. Clone the Repository

```bash
git clone https://github.com/baody682/NeuroDefender-AI-Cyber-Threat-Classifier.git
cd NeuroDefender-AI-Cyber-Threat-Classifier
```

### 2. Install Requirements

```bash
pip install -r requirements.txt
```

### 3. Run the App


```bash
python app.py
```
Then visit [http://localhost:5000](http://localhost:5000) in your browser.

---

## 🖼️ Screenshots

- **Home Page**

  ![Home Screenshot](https://github.com/baody682/NeuroDefender-AI-Cyber-Threat-Classifier/blob/main/static/english/home.png?raw=true)

- **Classification Result Page**

  ![Results Screenshot](https://github.com/baody682/NeuroDefender-AI-Cyber-Threat-Classifier/blob/main/static/english/results.png)

- **Dashboard Page**

  ![Dashboard Screenshot](https://github.com/baody682/NeuroDefender-AI-Cyber-Threat-Classifier/blob/main/static/english/dashboard.png)

---

🧪 Dataset & Training

  Dataset collected using CICFlowMeter + custom lab traffic
  
  Model trained on LightGBM with noise augmentation
  
  Accuracy: 98–100% on most attack types
  
  Adversarial test (noise std=0.05): ~92% overall accuracy

---

📜 License

This project is licensed under the MIT License — see the LICENSE file

---

💡 Inspiration

Built with 💻, 💪, and 🔥 by a passionate teen to protect the digital world from cyber threats.

---

👤 Author

Abdelrahman Mahboub (aka Body)
🧠 15-year-old self-taught AI & cybersecurity developer

- 🔗 [GitHub](https://github.com/baody682)
- 📧 [Email](mailto:bodymahboub.eg@gmail.com)
- 🌐 [LinkedIn](https://www.linkedin.com/in/abdelrahman-mahboub-416499327/)

⭐ If you find this project helpful, please consider giving it a star!
