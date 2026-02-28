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

## 🚀 Installation

Ensure you have Python 3.9, 3.10, 3.11, or 3.12 installed (`3.13` support is experimental due to OpenSSL 3 dependencies).

**1. Clone the repository**
```bash
git clone https://github.com/thanhdat317/Ember-PE-File-With-OpenIOC.git
cd Ember-PE-File-With-OpenIOC
```

**2. Install dependencies**
Install the core requirements including the newly required `thrember` module explicitly supporting EMBER2024:
```bash
pip install -r requirements.txt
```

**3. Run the Application**
Launch the Streamlit web server:
```bash
streamlit run app.py
```
> **Important Note**: On the *first launch*, the application will automatically download the heavy EMBER2024 AI models (e.g., `EMBER2024_PE.model`) into the `./models` directory. Depending on your network, this download might take a few moments. Subsequent launches will be instantaneous.

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
