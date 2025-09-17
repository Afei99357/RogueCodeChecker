#!/usr/bin/env python3
"""
RogueCheck Streamlit App Launcher
Usage: python run_app.py
"""
import os
import subprocess
import sys


def main():
    """Launch the RogueCheck Streamlit web application"""

    # Ensure we're in the right directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    print("🚀 Starting RogueCheck Web Application...")
    print("📍 Open your browser to: http://localhost:8501")
    print("⏹️  Press Ctrl+C to stop the application")
    print("-" * 50)

    try:
        # Run streamlit
        subprocess.run(
            [
                sys.executable,
                "-m",
                "streamlit",
                "run",
                "streamlit_app/main.py",
                "--server.port=8501",
                "--server.address=localhost",
            ]
        )
    except KeyboardInterrupt:
        print("\n🛑 Application stopped by user")
    except Exception as e:
        print(f"❌ Error starting application: {e}")
        print("\n💡 Make sure you have installed the dependencies:")
        print("   pip install -r requirements-app.txt")


if __name__ == "__main__":
    main()
