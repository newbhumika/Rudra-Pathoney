# 🛡️ Pathoney Honeypot  

A honeypot project built by **Team Rudra** (4 members) to capture and analyze malicious activities in a controlled environment.  

---

## 📌 Problem Statement  
Cyberattacks are growing in scale and sophistication; traditional defenses are often reactive.
Networks face threats like reconnaissance, automated bots, and credential theft that go undetected.
Conventional honeypots lack adaptability, realistic simulation, and structured logging, limiting actionable intelligence.
Smart Honeypot System:
Dynamically exposes select services to attract attackers.
Logs all interactions in a structured format.
Simulates realistic service banners and responses.
Provides insights for ethical hacking, threat analysis, and proactive defense.
Transforms attacks into learning opportunities, helping organizations stay ahead of evolving cyber threats.  

---
## 🛠️ Tech Stack  
- **Backend:** Python, Flask  
- **Frontend:** HTML, CSS, JavaScript, Bootstrap  
- **AI Integration:** Gemini API  
- **Containerization:** Docker  
- **Honeypot:** Pathoney Honeypot (Docker Hub image: `swarnav842/pathoney-honeypot`)  

---

## ⚙️ Installation & Usage  

### 1. Prerequisites  
Ensure your system has the following installed:  
- Python **3.11.2**  
- Flask (`pip install flask`)  
- Docker  
- Virtualenv (`pip install virtualenv`)  
- Gemini API key (saved inside `.env` file)  
- Bootstrap (via CDN)  

---

### 2. Setup Honeypot (Docker)  
1. Pull the Pathoney Honeypot image:  
   ```bash
   docker pull swarnav842/pathoney-honeypot
   ```  
2. Run the container:  
   ```bash
   docker run -d --name pathoney swarnav842/pathoney-honeypot
   ```  
3. Start the container (if stopped):  
   ```bash
   docker start <container_id>
   ```  
4. Logs from the honeypot can be viewed using:  
   ```bash
   docker logs -f pathoney
   ```  

---

### 3. Setup Backend (Flask)  
1. Create a virtual environment:  
   ```bash
   virtualenv .venv
   ```  
2. Activate the virtual environment:  
   ```bash
   source .venv/bin/activate   # Linux/Mac
   .venv\Scripts\activate      # Windows
   ```  
3. Install dependencies:  
   ```bash
   pip install -r requirements.txt
   ```  
4. Run the Flask app:  
   ```bash
   python app.py
   ```  

The app will be available at:  
- Localhost → [http://127.0.0.1:5000](http://127.0.0.1:5000)  
- Network → Accessible from other devices in the same network (e.g., mobile phone, tablet, etc.)  

---

## 📊 Features  
- Deploys honeypot in a Docker container  
- Captures attacker logs in real-time  
- Provides a **web-based graphical interface** for log analysis  
- Supports version operations for better log management  
- Accessible on multiple devices within the network  

---

## 📂 Additional Resources  
- Project PPT & UI screenshots: [Google Drive Link](https://drive.google.com/drive/folders/1yIs9KfKWY7Tw48aPzEZ5vN1Vs8XN0Ix0?usp=drive_link)  

---

## 👨‍💻 Team Rudra  
This project was developed by **Team Rudra** (4 members).  
Nikhil Dubey
Swarnav Das
Puja Chakraborty
Vaishali sharma