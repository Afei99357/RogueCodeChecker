#!/usr/bin/env python3
"""
OSS-only Streamlit App Launcher
Usage: python run_app_oss.py
"""
import os
import subprocess
import sys


def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    print("🚀 Starting OSS Security Scanner (Semgrep) Web App...")
    print("📍 Open your browser to: http://localhost:8501")
    print("⏹️  Press Ctrl+C to stop the application")
    print("-" * 50)
    try:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "streamlit",
                "run",
                "streamlit_app_oss/main.py",
                "--server.port=8501",
                "--server.address=localhost",
            ]
        )
    except KeyboardInterrupt:
        print("\n🛑 Application stopped by user")
    except Exception as e:
        print(f"❌ Error starting application: {e}")


if __name__ == "__main__":
    main()

