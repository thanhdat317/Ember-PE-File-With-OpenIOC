<div align="center">
  <h1>🛡️ EMBER2024 Malware Scanner</h1>
  <p><strong>A high-performance machine learning based malware detection tool</strong></p>
</div>

<hr/>

## 📖 Overview

**EMBER2024 Malware Scanner** is an intelligent security solution for scanning Windows PE files (e.g., `.exe`, `.dll`, `.sys`). 

By leveraging the cutting-edge **LightGBM** models trained on the massive **EMBER2024** dataset, this application provides an intuitive web interface for static analysis. It dynamically calculates maliciousness probability without ever executing the suspect files. 

## ✨ Key Features

- **🧠 Modern AI Integration**: Powered by LightGBM models built strictly on the EMBER2024 methodologies (utilizing `thrember` and `pefile`).
- **🔍 Fast Static Analysis**: Immediate file parsing and prediction without detonating the payload.
- **🌐 VirusTotal Integration**: Augment ML predictions by querying VirusTotal API for enhanced global reputation and network IOC extraction.
- **📄 OpenIOC Export**: Automatically structures findings (Hashes, IPs, Domains) into actionable `.ioc` (XML) reports for threat hunters.
- **🖥️ Streamlit Dashboard**: A beautiful, responsive web interface—no CLI expertise required.

## 🚀 Local Installation

Ensure you have Python 3.9, 3.10, 3.11, or 3.12 installed on your computer.

**Step 1: Get the Code**
Download the project to your computer by cloning the repository:
```bash
git clone https://github.com/thanhdat317/Ember-PE-File-With-OpenIOC.git
cd Ember-PE-File-With-OpenIOC
```

**Step 2: Install Required Libraries**
Install all the necessary Python packages (including `thrember` for the EMBER AI models):
```bash
pip install -r requirements.txt
```

**Step 3: Download the AI Models (Mandatory First-Time Setup)**
Because the AI models are over 400MB, they are NOT included in the GitHub repository. **You must download them before scanning any files**.

You can let the app download it automatically, OR manually trigger the download by running this quick Python command in your terminal:
```bash
python -c "import os, thrember; os.makedirs('models', exist_ok=True); thrember.download_models('./models')"
```
*Wait for the progress bar to finish. This will place the required `EMBER2024_PE.model` into the `./models` folder.*

**Step 4: Launch the Dashboard!**
Start the Streamlit web server:
```bash
streamlit run app.py
```

## 🏁 Usage

1. **Dashboard Access**: After the server starts, navigate to `http://localhost:8501`.
2. **Scan**: Drag and drop your suspect PE file into the uploader.
3. **Analyze Score**: Observe the ML suspicion probability (e.g., `98.24% (Malicious)`). 
4. **VirusTotal (Optional)**: Input your VirusTotal API Key on the sidebar to complement the ML prediction and aggregate further networking/file indicators.
5. **Generate IOC**: Click to render and download your formatted `OpenIOC` threat intelligence report.

## ☁️ Streamlit Cloud Deployment

This project is optimized for 1-click deployments on platforms like **Streamlit Community Cloud**:
- **Automatic Models**: Huge model files are strictly ignored on GitHub to comply with 100MB limits. The provided `app.py` script automatically downloads them into the cloud container during runtime.
- **Environment**: During deployment on Streamlit Cloud, navigate to **Advanced Settings -> Select Python 3.10** to ensure maximum dependency compatibility for the `thrember` and `signify` packages.
