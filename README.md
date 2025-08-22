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
  ## UI/UX Images
![WhatsApp Image 2025-08-22 at 04 57 13_c423efe5](https://github.com/user-attachments/assets/7c88eb3a-d2e5-4d62-a1f9-f20ec1ed0ec2)
![WhatsApp Image 2025-08-22 at 05 12 14_37218298](https://github.com/user-attachments/assets/c91b29af-be6f-4e83-a36c-79eca3885919)
![WhatsApp Image 2025-08-22 at 05 12 36_da452794](https://github.com/user-attachments/assets/5b75a004-57c8-4299-b59e-e4fac2df41b3)
![WhatsApp Image 2025-08-22 at 05 14 40_1fec7a58](https://github.com/user-attachments/assets/63b0ca8a-114d-4998-8c72-37f3b9deabc3)
![WhatsApp Image 2025-08-22 at 05 15 20_567753b8](https://github.com/user-attachments/assets/82214f1b-60a0-4b79-951a-07d133902b2e)
![WhatsApp Image 2025-08-22 at 05 15 53_1274c52c](https://github.com/user-attachments/assets/b0bde7d7-af47-491f-95b3-acf4e117885a)
![WhatsApp Image 2025-08-22 at 05 20 11_85e7182d](https://github.com/user-attachments/assets/46b17cf8-260a-4f46-98ef-5d8b73cdfc3f)
![WhatsApp Image 2025-08-22 at 05 20 11_41edc1ab](https://github.com/user-attachments/assets/ec1672cb-9b81-4b8c-8738-f2dc4a14a417)
![WhatsApp Image 2025-08-22 at 05 20 12_f5fb8ac3](https://github.com/user-attachments/assets/35cdbabc-fa34-4412-a44b-0c67ec5cafe2)
![WhatsApp Image 2025-08-22 at 05 20 13_e2da596f](https://github.com/user-attachments/assets/8f42590f-6092-43d1-97f1-57482181e423)
![WhatsApp Image 2025-08-22 at 05 20 13_0d54a22c](https://github.com/user-attachments/assets/5b908437-8eeb-4c04-8304-b75910bcd6b5)
![WhatsApp Image 2025-08-22 at 05 20 14_0dd96c29](https://github.com/user-attachments/assets/357777e0-3eee-44a4-9030-00617b1bfbca)

---


## 👨‍💻 Team Rudra  
This project was developed by **Team Rudra** (4 members).  
Nikhil Dubey
Swarnav Das
Puja Chakraborty
Vaishali sharma
