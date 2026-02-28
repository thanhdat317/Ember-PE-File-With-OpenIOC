<div align="center">
  <h1>🛡️ EMBER2024 Malware Scanner</h1>
  <p>
    <strong>A high-performance machine learning based malware detection tool</strong>
  </p>
  <p>
    Powered by the cutting-edge <a href="https://github.com/FutureComputing4AI/EMBER2024">EMBER2024 Dataset</a> and LightGBM.
  </p>
</div>

<hr/>

## 📖 Overview

The **EMBER2024 Malware Scanner** is an intelligent security solution evaluating PE (Portable Executable) files—such as `.exe`, `.sys`, and `.dll`—using advanced Machine Learning models trained on the EMBER2024 dataset.

This application provides a robust and visually interactive UI to inspect files in real-time, generate threat scores, integrate with VirusTotal for supplementary reputation context, and automatically output comprehensive **OpenIOC XML** reports for threat hunting and incident response.

## ✨ Key Features

- **🧠 Cutting-Edge ML Models**: Operates the latest LightGBM models built strictly on the EMBER2024 dataset methodologies (utilizing `thrember` and `pefile`).
- **🔍 Fast Static Analysis**: Immediate file parsing without executing the suspicious binaries.
- **🌐 VirusTotal Integration**: Seamlessly augments ML scores by querying your API token to VirusTotal for an expanded reputation footprint and networking IOCs.
- **📄 OpenIOC Export**: Automatically structures findings and extracted indicators into actionable `.ioc` format (XML).
- **🖥️ Streamlit Interface**: Beautiful, responsive, and intuitive web application setup without the complexity of deep terminal knowledge.

## 🚀 Installation

Ensure you have Python 3.8+ installed on your system.

**1. Clone the repository**
```bash
git clone https://github.com/yourusername/ember2024-scanner.git
cd ember2024-scanner
```

**2. Install dependencies**
Install the core requirements including the newly required `thrember` module explicitly supporting EMBER2024:
```bash
pip install -r requirements.txt
```

**3. Fetch the Models**
Pre-requisite LightGBM models used by the scanner must be placed in a `./models/` directory in the project root. For a PE file analysis, download the `EMBER2024_PE.model` file via the backend Python module:
```python
import thrember
import os

os.makedirs('models', exist_ok=True)
thrember.download_models('./models')
```
> *Note: By default, the app initializes the primary PE model (`models/EMBER2024_PE.model`).*

## 🏁 Usage

Run the web application locally via Streamlit:

```bash
streamlit run app.py
```

1. **Dashboard Access**: After the server starts, navigate to `http://localhost:8501` in your browser.
2. **Scan**: Drag and drop your suspect PE file into the box or browse your local file system.
3. **Analyze Score**: Observe the ML suspicion threshold out of 100%. (e.g. `98.24% (Malicious)`) 
4. **VirusTotal (Optional)**: Input your VirusTotal API Key on the sidebar to complement the ML prediction and aggregate further file/networking IOCs.
5. **Generate IOC**: Click to render and download your formatted `OpenIOC` report.

## 🛠️ Tech Stack
- **Backend / Analysis**: Python, `thrember`, `pefile`, `lightgbm`, `ioc_writer`
- **Frontend / UI**: `streamlit`, `pandas`
- **Dataset Focus**: `EMBER2024` ([Paper](https://arxiv.org/abs/2404.13110) / [Repository](https://github.com/FutureComputing4AI/EMBER2024))

## 📄 License
This original project context leverages third-party open-source components (`EMBER2024`) alongside custom detection interfaces. Review standard `thrember` licenses or applicable open-source limitations based on implementation rules.
