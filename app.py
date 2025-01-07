import streamlit as st
import requests
import sqlite3
import os
from datetime import datetime
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()  # Load environment variables if needed

# Function to connect to SQLite database
def connect_to_db():
    conn = sqlite3.connect("leaderboard.db")  # SQLite database file
    return conn

def create_tables():
    conn = connect_to_db()
    cursor = conn.cursor()

    # Create github_accounts table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS github_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        github_url TEXT UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    ''')

    # Create scores table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        pull_requests_opened INTEGER DEFAULT 0,
        pull_requests_merged INTEGER DEFAULT 0,
        issues_created INTEGER DEFAULT 0,
        issues_closed INTEGER DEFAULT 0,
        repos_contributed_to INTEGER DEFAULT 0,
        starred_repositories INTEGER DEFAULT 0,
        commit_changes INTEGER DEFAULT 0,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    ''')

    conn.commit()
    conn.close()

# Function to validate GitHub account existence
def validate_github_account(github_url):
    try:
        username = github_url.split("https://github.com/")[-1].strip("/")
        response = requests.get(f"https://api.github.com/users/{username}")
        if response.status_code == 200:
            return True, "GitHub account exists."
        else:
            return False, "GitHub account does not exist."
    except Exception as e:
        return False, f"Error validating GitHub account: {str(e)}"

# Function to fetch commit changes using GitHub API
def fetch_commit_changes(username):
    headers = {"Accept": "application/vnd.github.v3+json"}
    total_commits = 0

    try:
        repos_url = f"https://api.github.com/users/{username}/repos"
        repos_response = requests.get(repos_url, headers=headers)
        repos_response.raise_for_status()
        repositories = repos_response.json()

        for repo in repositories:
            owner = repo['owner']['login']
            repo_name = repo['name']
            contributors_url = f"https://api.github.com/repos/{owner}/{repo_name}/contributors"
            contributors_response = requests.get(contributors_url, headers=headers)
            contributors_response.raise_for_status()

            contributors = contributors_response.json()
            for contributor in contributors:
                if contributor['login'] == username:
                    total_commits += contributor['contributions']
                    break

        return total_commits
    except Exception as e:
        st.error(f"Error fetching commit changes: {str(e)}")
        return 0

# Function to fetch scores using GitHub API
def fetch_github_scores(username):
    headers = {"Accept": "application/vnd.github.v3+json"}

    if username.startswith("https://github.com/"):
        username = username.split("https://github.com/")[-1].strip("/")

    try:
        pr_opened = requests.get(
            f"https://api.github.com/search/issues?q=type:pr+author:{username}",
            headers=headers
        ).json().get("total_count", 0)

        pr_merged = requests.get(
            f"https://api.github.com/search/issues?q=type:pr+author:{username}+is:merged",
            headers=headers
        ).json().get("total_count", 0)

        issues_created = requests.get(
            f"https://api.github.com/search/issues?q=type:issue+author:{username}",
            headers=headers
        ).json().get("total_count", 0)

        issues_closed = requests.get(
            f"https://api.github.com/search/issues?q=type:issue+author:{username}+is:closed",
            headers=headers
        ).json().get("total_count", 0)

        repos_contributed_to = requests.get(
            f"https://api.github.com/users/{username}/repos",
            headers=headers
        ).json()
        repos_contributed_to_count = len(repos_contributed_to) if isinstance(repos_contributed_to, list) else 0

        starred_repos = requests.get(
            f"https://api.github.com/users/{username}/starred",
            headers=headers
        ).json()
        starred_repos_count = len(starred_repos) if isinstance(starred_repos, list) else 0

        commit_changes = fetch_commit_changes(username)

        return {
            "pull_requests_opened": pr_opened,
            "pull_requests_merged": pr_merged,
            "issues_created": issues_created,
            "issues_closed": issues_closed,
            "repos_contributed_to": repos_contributed_to_count,
            "starred_repositories": starred_repos_count,
            "commit_changes": commit_changes
        }
    except Exception as e:
        st.error(f"Error fetching scores: {str(e)}")
        return None

# Function to insert or update scores in the database
def update_scores_in_db(username, scores):
    try:
        conn = connect_to_db()
        cursor = conn.cursor()

        query = '''
            INSERT INTO scores (
                username, pull_requests_opened, pull_requests_merged,
                issues_created, issues_closed, repos_contributed_to,
                starred_repositories, commit_changes, last_updated
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
                pull_requests_opened=excluded.pull_requests_opened,
                pull_requests_merged=excluded.pull_requests_merged,
                issues_created=excluded.issues_created,
                issues_closed=excluded.issues_closed,
                repos_contributed_to=excluded.repos_contributed_to,
                starred_repositories=excluded.starred_repositories,
                commit_changes=excluded.commit_changes,
                last_updated=excluded.last_updated;
        '''
        cursor.execute(query, (
            username,
            scores["pull_requests_opened"],
            scores["pull_requests_merged"],
            scores["issues_created"],
            scores["issues_closed"],
            scores["repos_contributed_to"],
            scores["starred_repositories"],
            scores["commit_changes"],
            datetime.now()
        ))

        conn.commit()
        cursor.close()
        conn.close()

        return True, "Scores updated successfully in the 'scores' table."
    except Exception as e:
        return False, f"Database error: {str(e)}"

# Function to fetch all usernames and scores
def fetch_leaderboard():
    try:
        conn = connect_to_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT username, (
                COALESCE(pull_requests_opened, 0) +
                COALESCE(pull_requests_merged, 0) +
                COALESCE(issues_created, 0) +
                COALESCE(issues_closed, 0) +
                COALESCE(repos_contributed_to, 0) +
                COALESCE(starred_repositories, 0) +
                COALESCE(commit_changes, 0)
            ) AS total_score
            FROM scores
            ORDER BY total_score DESC;
        ''')
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows
    except Exception as e:
        st.error(f"Error fetching leaderboard: {str(e)}")
        return []

def validate_login(username, password):
    try:
        conn = connect_to_db()
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM github_accounts WHERE username = ?", (username,))
        record = cursor.fetchone()
        cursor.close()
        conn.close()

        if record and check_password_hash(record[0], password):
            return True, "Login successful!"
        return False, "Invalid username or password."
    except Exception as e:
        return False, f"Database error: {str(e)}"

def sign_up(github_url, password):
    try:
        username = github_url.split("https://github.com/")[-1].strip("/")
        response = requests.get(f"https://api.github.com/users/{username}")
        if response.status_code != 200:
            return False, "GitHub account does not exist."

        conn = connect_to_db()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM github_accounts WHERE username = ?", (username,))
        if cursor.fetchone():
            return False, "User already exists. Please log in."
        
        password_hash = generate_password_hash(password)
        query = """
            INSERT INTO github_accounts (username, password_hash, github_url)
            VALUES (?, ?, ?)
        """
        cursor.execute(query, (username, password_hash, github_url))
        conn.commit()
        cursor.close()
        conn.close()

        return True, "User registered successfully. Please log in."
    except Exception as e:
        return False, f"Database error: {str(e)}"

# Initialize database tables
create_tables()

# Streamlit app starts here
if "page" not in st.session_state:
    st.session_state.page = "Login"

if st.session_state.page == "Login":
    st.title("GitHub Leaderboard - Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Log In"):
        success, message = validate_login(username, password)
        if success:
            st.session_state.page = "Dashboard"
            st.session_state.username = username
            st.success(message)
        else:
            st.error(message)

    if st.button("Sign Up"):
        st.session_state.page = "Sign Up"

elif st.session_state.page == "Sign Up":
    st.title("GitHub Leaderboard - Sign Up")
    github_url = st.text_input("GitHub URL")
    password = st.text_input("Password", type="password")

    if st.button("Register"):
        if github_url and password:
            success, message = sign_up(github_url, password)
            if success:
                st.session_state.page = "Login"
                st.success(message)
            else:
                st.error(message)
        else:
            st.warning("Please fill in all fields.")

    if st.button("Back to Login"):
        st.session_state.page = "Login"

elif st.session_state.page == "Dashboard":
    st.title("GitHub Leaderboard - Dashboard")

    # Fetch scores and leaderboard data
    try:
        username = st.session_state.username
        scores = fetch_github_scores(username)
        if scores:
            update_scores_in_db(username, scores)

        leaderboard = fetch_leaderboard()

        st.subheader("Leaderboard")
        if leaderboard:
            leaderboard_table = [
                {"Username": row[0], "Total Score": row[1]} for row in leaderboard
            ]
            st.table(leaderboard_table)
        else:
            st.write("No users found.")

    except Exception as e:
        st.error(f"Error loading dashboard: {str(e)}")

    if st.button("Log Out"):
        st.session_state.page = "Login"

