# Enter Your Future — Meditation App

A personalised meditation website with user accounts, saved profiles, and session tracking.

## Setup (takes 2 minutes)

### Requirements
- Python 3.8+
- pip

### Install & run

```bash
# 1. Install dependencies
pip install flask flask-cors bcrypt pyjwt

# 2. Run the server
python app.py
```

Then open **http://localhost:5050** in your browser.

### To deploy publicly (free options)
- **Railway.app** — drag the folder in, it auto-detects Python
- **Render.com** — connect GitHub repo, set start command to `python app.py`
- **Fly.io** — run `fly launch` in the folder

### Environment variables (for production)
Set `JWT_SECRET` to a long random string:
```bash
export JWT_SECRET="your-very-long-random-secret-here"
```

## What it does
- Users create accounts with email + password
- 10-question intake questionnaire that learns who they are
- Personalised meditation generated from their answers (faith, struggle, vision, why)
- Session tracking — every completed meditation is logged
- Dashboard showing streaks, history, and profile
- Answers saved to their account — next visit goes straight to meditation

## Files
- `app.py` — Flask backend (auth, API, SQLite database)
- `templates/index.html` — Full frontend (single page app)
- `data/db.sqlite` — Created automatically on first run
