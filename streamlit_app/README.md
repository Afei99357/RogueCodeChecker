# RogueCheck Streamlit Web Application

Web interface for the RogueCheck security scanner.

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements-app.txt
```

### 2. Run the Application
```bash
python run_app.py
```

### 3. Open Browser
Navigate to: http://localhost:8501

## 📁 Project Structure

```
streamlit_app/
├── main.py                 # Main application entry point
├── components/             # UI components
│   ├── file_upload.py     # File upload widget
│   ├── results_table.py   # Results display table
│   └── config_panel.py    # Configuration sidebar
├── services/              # Business logic
│   └── scanner_service.py # RogueCheck adapter layer
└── utils/                 # App utilities
```

## 🔧 Features

- **Multi-file Upload**: Upload multiple Python, SQL, and Bash files
- **Real-time Scanning**: Instant security analysis using RogueCheck
- **Interactive Results**: Sortable, filterable results table
- **Export Options**: Download results as CSV
- **Configuration**: Customize scanning rules and allowlists

## 🛠️ Development

### Manual Streamlit Run
```bash
streamlit run streamlit_app/main.py
```

### CLI vs Web Interface
- **CLI**: `python -m roguecheck scan --path . --format md`
- **Web**: Upload files through browser interface

Both use the same RogueCheck core scanning engine.
