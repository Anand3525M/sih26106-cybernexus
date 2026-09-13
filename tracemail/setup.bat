@echo off
echo ==> Setting up TraceMail environment (Windows)...
python -m venv venv
call venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
echo ==> Setup complete! Run: venv\Scripts\activate
pause
