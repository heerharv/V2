import requests
import os
import base64
import json
import uuid
from urllib.parse import urlencode, parse_qs
from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_cors import CORS
from requests.auth import HTTPBasicAuth
from datetime import datetime, timedelta
import logging
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')  # Use environment variable
CORS(app, supports_credentials=True)

# JIRA Configuration - Use environment variables for security
JIRA_DOMAIN = os.environ.get('JIRA_DOMAIN', 'uncia-team-vmevzjmu.atlassian.net')
JIRA_EMAIL = os.environ.get('JIRA_EMAIL', 'heerha@uncia.ai')
JIRA_API_TOKEN = os.environ.get('JIRA_API_TOKEN', 'ATATT3xFfGF02Z2VPkoTxN-FQRjgHnO5aQRdEiOhioTwikHHIUNDqrMjL9n7AInkzJpHYO360PD6CY6bVsa-Y3ZwjrqrEo0rVbSpAp4DCQu3lMiBzbNvVl12X47stmCbOb_7ueiJt93fNQphmp3hgJJWf9em98ETlJufB0qcndcOFQWL9Ups6CU=0AD8157C')

# OAuth 2.0 Configuration for Jira Cloud
OAUTH_CLIENT_ID = os.environ.get('OAUTH_CLIENT_ID', 'wKPQ6BvxnTQHae7gzEcVdfeXSmhpJmUd')
OAUTH_CLIENT_SECRET = os.environ.get('OAUTH_CLIENT_SECRET', 'ATOAJGryktFzcCjG9V9py2v4wHAhT8xAPiZx5nGFfPu0ICd5XqgeBC1_wwrHV5WfjKtyD102020C')
OAUTH_REDIRECT_URI = os.environ.get('OAUTH_REDIRECT_URI', 'http://localhost:8000/oauth/callback')
OAUTH_SCOPE = 'read:jira-user read:jira-work'

# Jira OAuth 2.0 URLs
JIRA_AUTH_URL = 'https://auth.atlassian.com/authorize'
JIRA_TOKEN_URL = 'https://auth.atlassian.com/oauth/token'
JIRA_API_BASE = f'https://api.atlassian.com/ex/jira/{JIRA_DOMAIN.split(".")[0]}'

def get_jira_auth():
    """Get authentication for Jira API calls"""
    if 'access_token' in session:
        return {'Authorization': f'Bearer {session["access_token"]}'}
    elif JIRA_API_TOKEN:
        return HTTPBasicAuth(JIRA_EMAIL, JIRA_API_TOKEN)
    else:
        raise Exception("No authentication method available")

def get_jira_headers():
    """Get headers for Jira API calls"""
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    # Add OAuth token if available
    if 'access_token' in session:
        headers['Authorization'] = f'Bearer {session["access_token"]}'
    
    return headers

def make_jira_request(url, params=None, use_oauth=False):
    """Make authenticated request to Jira API with proper error handling"""
    try:
        headers = get_jira_headers()
        
        if use_oauth and 'access_token' in session:
            # Use OAuth endpoint
            if url.startswith(f"https://{JIRA_DOMAIN}"):
                url = url.replace(f"https://{JIRA_DOMAIN}", JIRA_API_BASE)
            response = requests.get(url, headers=headers, params=params)
        else:
            # Use basic auth with personal access token
            auth = HTTPBasicAuth(JIRA_EMAIL, JIRA_API_TOKEN) if JIRA_API_TOKEN else None
            if not auth:
                raise Exception("No authentication method available")
            response = requests.get(url, headers=headers, auth=auth, params=params)
        
        logger.info(f"Request to {url} returned status {response.status_code}")
        
        if response.status_code == 401:
            if 'access_token' in session:
                # Token might be expired, try to refresh
                if refresh_access_token():
                    return make_jira_request(url, params, use_oauth)
            raise Exception("Authentication failed")
        elif response.status_code == 403:
            raise Exception("Access forbidden - check permissions")
        elif response.status_code == 404:
            raise Exception("Resource not found")
        elif response.status_code >= 400:
            raise Exception(f"API request failed with status {response.status_code}: {response.text}")
        
        return response
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {str(e)}")
        raise Exception(f"Network error: {str(e)}")

# OAuth 2.0 Routes
@app.route('/oauth/login')
def oauth_login():
    """Initiate OAuth 2.0 flow"""
    if not OAUTH_CLIENT_ID:
        return jsonify({"error": "OAuth not configured"}), 500
    
    state = str(uuid.uuid4())
    session['oauth_state'] = state
    
    params = {
        'audience': 'api.atlassian.com',
        'client_id': OAUTH_CLIENT_ID,
        'scope': OAUTH_SCOPE,
        'redirect_uri': OAUTH_REDIRECT_URI,
        'state': state,
        'response_type': 'code',
        'prompt': 'consent'
    }
    
    auth_url = f"{JIRA_AUTH_URL}?{urlencode(params)}"
    return redirect(auth_url)

@app.route('/oauth/callback')
def oauth_callback():
    """Handle OAuth 2.0 callback"""
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')
    
    if error:
        return jsonify({"error": f"OAuth error: {error}"}), 400
    
    if not code or not state or state != session.get('oauth_state'):
        return jsonify({"error": "Invalid OAuth callback"}), 400
    
    try:
        # Exchange code for token
        token_data = {
            'grant_type': 'authorization_code',
            'client_id': OAUTH_CLIENT_ID,
            'client_secret': OAUTH_CLIENT_SECRET,
            'code': code,
            'redirect_uri': OAUTH_REDIRECT_URI
        }
        
        response = requests.post(JIRA_TOKEN_URL, data=token_data)
        
        if response.status_code == 200:
            token_info = response.json()
            session['access_token'] = token_info['access_token']
            session['refresh_token'] = token_info.get('refresh_token')
            session['expires_at'] = datetime.now() + timedelta(seconds=token_info.get('expires_in', 3600))
            
            # Get accessible resources
            accessible_resources = get_accessible_resources()
            if accessible_resources:
                session['cloud_id'] = accessible_resources[0]['id']
            
            return redirect('/')
        else:
            return jsonify({"error": "Failed to exchange code for token"}), 400
            
    except Exception as e:
        logger.error(f"OAuth callback error: {str(e)}")
        return jsonify({"error": f"OAuth callback failed: {str(e)}"}), 500

def refresh_access_token():
    """Refresh OAuth access token"""
    if 'refresh_token' not in session:
        return False
    
    try:
        token_data = {
            'grant_type': 'refresh_token',
            'client_id': OAUTH_CLIENT_ID,
            'client_secret': OAUTH_CLIENT_SECRET,
            'refresh_token': session['refresh_token']
        }
        
        response = requests.post(JIRA_TOKEN_URL, data=token_data)
        
        if response.status_code == 200:
            token_info = response.json()
            session['access_token'] = token_info['access_token']
            session['expires_at'] = datetime.now() + timedelta(seconds=token_info.get('expires_in', 3600))
            return True
        else:
            # Clear invalid tokens
            session.pop('access_token', None)
            session.pop('refresh_token', None)
            return False
            
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        return False

def get_accessible_resources():
    """Get accessible Atlassian resources"""
    if 'access_token' not in session:
        return []
    
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.get('https://api.atlassian.com/oauth/token/accessible-resources', headers=headers)
        
        if response.status_code == 200:
            return response.json()
        return []
    except Exception:
        return []

@app.route('/oauth/logout')
def oauth_logout():
    """Clear OAuth session"""
    session.clear()
    return jsonify({"message": "Logged out successfully"})

# Main Routes
@app.route('/')
def index():
    auth_status = {
        'oauth_available': bool(OAUTH_CLIENT_ID),
        'oauth_authenticated': 'access_token' in session,
        'basic_auth_available': bool(JIRA_API_TOKEN)
    }
    return render_template('index.html', auth_status=auth_status)

@app.route('/api/auth-status')
def auth_status():
    """Check authentication status"""
    return jsonify({
        'oauth_available': bool(OAUTH_CLIENT_ID),
        'oauth_authenticated': 'access_token' in session,
        'basic_auth_available': bool(JIRA_API_TOKEN),
        'expires_at': session.get('expires_at').isoformat() if session.get('expires_at') else None
    })

@app.route('/api/data')
def get_data():
    return jsonify({'message': 'Hello from Flask API'})

@app.route('/api/jira/test')
def test_jira_connection():
    """Test Jira API connection"""
    try:
        url = f"https://{JIRA_DOMAIN}/rest/api/3/myself"
        response = make_jira_request(url)
        
        if response.status_code == 200:
            user_data = response.json()
            return jsonify({
                "status": "success",
                "message": "Connected to Jira successfully",
                "user": {
                    "displayName": user_data.get('displayName'),
                    "emailAddress": user_data.get('emailAddress'),
                    "accountType": user_data.get('accountType')
                }
            })
        else:
            return jsonify({"error": f"Connection test failed: {response.text}"}), response.status_code
            
    except Exception as e:
        logger.error(f"Connection test failed: {str(e)}")
        return jsonify({"error": f"Connection test failed: {str(e)}"}), 500

@app.route('/api/jira/project/<project_key>')
def get_project_details(project_key):
    """Get detailed project information with better error handling"""
    try:
        url = f"https://{JIRA_DOMAIN}/rest/api/3/project/{project_key}"
        response = make_jira_request(url)
        
        if response.status_code == 200:
            project_data = response.json()
            
            # Get additional project statistics
            stats_url = f"https://{JIRA_DOMAIN}/rest/api/3/project/{project_key}/statuses"
            try:
                stats_response = make_jira_request(stats_url)
                statuses = stats_response.json() if stats_response.status_code == 200 else []
            except Exception:
                statuses = []
            
            result = {
                "project_info": project_data,
                "statuses": statuses
            }
            
            return jsonify(result)
        else:
            return jsonify({"error": f"Failed to fetch project details: {response.text}"}), response.status_code
            
    except Exception as e:
        logger.error(f"Error fetching project {project_key}: {str(e)}")
        return jsonify({"error": f"Exception occurred: {str(e)}"}), 500

@app.route('/api/jira/issues/<project_key>')
def get_project_issues(project_key):
    """Get all issues for a specific project with pagination"""
    try:
        start_at = int(request.args.get('startAt', 0))
        max_results = min(int(request.args.get('maxResults', 50)), 100)  # Limit to 100 max
        
        url = f"https://{JIRA_DOMAIN}/rest/api/3/search"
        
        jql_query = f"project = {project_key} ORDER BY created DESC"
        
        params = {
            "jql": jql_query,
            "startAt": start_at,
            "maxResults": max_results,
            "fields": [
                "summary", "description", "status", "assignee", "reporter",
                "priority", "issuetype", "created", "updated", "labels",
                "components", "fixVersions", "resolution", "resolutiondate",
                "progress", "timeestimate", "timespent", "duedate"
            ]
        }
        
        response = make_jira_request(url, params)
        
        if response.status_code == 200:
            issues_data = response.json()
            
            processed_issues = []
            for issue in issues_data.get('issues', []):
                fields = issue.get('fields', {})
                
                processed_issue = {
                    "key": issue.get('key'),
                    "id": issue.get('id'),
                    "summary": fields.get('summary'),
                    "description": fields.get('description'),
                    "status": {
                        "name": fields.get('status', {}).get('name'),
                        "category": fields.get('status', {}).get('statusCategory', {}).get('name')
                    },
                    "assignee": {
                        "name": fields.get('assignee', {}).get('displayName') if fields.get('assignee') else "Unassigned",
                        "email": fields.get('assignee', {}).get('emailAddress') if fields.get('assignee') else None
                    },
                    "reporter": {
                        "name": fields.get('reporter', {}).get('displayName') if fields.get('reporter') else None,
                        "email": fields.get('reporter', {}).get('emailAddress') if fields.get('reporter') else None
                    },
                    "priority": {
                        "name": fields.get('priority', {}).get('name') if fields.get('priority') else None,
                        "iconUrl": fields.get('priority', {}).get('iconUrl') if fields.get('priority') else None
                    },
                    "issuetype": {
                        "name": fields.get('issuetype', {}).get('name'),
                        "iconUrl": fields.get('issuetype', {}).get('iconUrl')
                    },
                    "created": fields.get('created'),
                    "updated": fields.get('updated'),
                    "labels": fields.get('labels', []),
                    "components": [comp.get('name') for comp in fields.get('components', [])],
                    "fixVersions": [version.get('name') for version in fields.get('fixVersions', [])],
                    "resolution": fields.get('resolution', {}).get('name') if fields.get('resolution') else None,
                    "resolutiondate": fields.get('resolutiondate'),
                    "progress": fields.get('progress', {}),
                    "timeestimate": fields.get('timeestimate'),
                    "timespent": fields.get('timespent'),
                    "duedate": fields.get('duedate')
                }
                processed_issues.append(processed_issue)
            
            return jsonify({
                "total": issues_data.get('total'),
                "startAt": issues_data.get('startAt'),
                "maxResults": issues_data.get('maxResults'),
                "issues": processed_issues
            })
        else:
            return jsonify({"error": f"Failed to fetch issues: {response.text}"}), response.status_code
            
    except Exception as e:
        logger.error(f"Error fetching issues for project {project_key}: {str(e)}")
        return jsonify({"error": f"Exception occurred: {str(e)}"}), 500

@app.route('/api/jira/dashboard/<project_key>')
def get_project_dashboard(project_key):
    """Get comprehensive dashboard data for the project"""
    try:
        dashboard_data = {}
        
        # Get project details
        project_url = f"https://{JIRA_DOMAIN}/rest/api/3/project/{project_key}"
        try:
            project_response = make_jira_request(project_url)
            dashboard_data["project_info"] = project_response.json() if project_response.status_code == 200 else {}
        except Exception as e:
            logger.warning(f"Failed to fetch project info: {str(e)}")
            dashboard_data["project_info"] = {}
        
        # Get issues summary by status
        search_url = f"https://{JIRA_DOMAIN}/rest/api/3/search"
        
        status_queries = {
            "todo": f"project = {project_key} AND status in ('To Do', 'Open', 'Backlog')",
            "in_progress": f"project = {project_key} AND status in ('In Progress', 'In Development')",
            "done": f"project = {project_key} AND status in ('Done', 'Closed', 'Resolved')",
            "total": f"project = {project_key}"
        }
        
        status_counts = {}
        for status_type, jql in status_queries.items():
            try:
                params = {"jql": jql, "maxResults": 0}
                response = make_jira_request(search_url, params)
                status_counts[status_type] = response.json().get('total', 0) if response.status_code == 200 else 0
            except Exception:
                status_counts[status_type] = 0
        
        dashboard_data["status_counts"] = status_counts
        
        # Get recent activity
        try:
            recent_params = {
                "jql": f"project = {project_key} ORDER BY updated DESC",
                "maxResults": 10,
                "fields": ["summary", "status", "assignee", "updated", "issuetype"]
            }
            recent_response = make_jira_request(search_url, recent_params)
            
            recent_issues = []
            if recent_response.status_code == 200:
                for issue in recent_response.json().get('issues', []):
                    fields = issue.get('fields', {})
                    recent_issues.append({
                        "key": issue.get('key'),
                        "summary": fields.get('summary'),
                        "status": fields.get('status', {}).get('name'),
                        "assignee": fields.get('assignee', {}).get('displayName') if fields.get('assignee') else "Unassigned",
                        "updated": fields.get('updated'),
                        "issuetype": fields.get('issuetype', {}).get('name')
                    })
            
            dashboard_data["recent_issues"] = recent_issues
        except Exception as e:
            logger.warning(f"Failed to fetch recent issues: {str(e)}")
            dashboard_data["recent_issues"] = []
        
        # Calculate progress
        total = max(status_counts.get('total', 1), 1)
        done = status_counts.get('done', 0)
        dashboard_data["progress_percentage"] = round((done / total) * 100, 2)
        
        return jsonify(dashboard_data)
        
    except Exception as e:
        logger.error(f"Error creating dashboard for project {project_key}: {str(e)}")
        return jsonify({"error": f"Exception occurred: {str(e)}"}), 500

@app.route('/api/jira-projects')
def get_jira_projects():
    """Get all projects with better error handling"""
    try:
        url = f"https://{JIRA_DOMAIN}/rest/api/3/project/search"
        response = make_jira_request(url)
        
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({"error": "Failed to fetch Jira projects", "details": response.text}), response.status_code
            
    except Exception as e:
        logger.error(f"Error fetching projects: {str(e)}")
        return jsonify({"error": f"Exception occurred: {str(e)}"}), 500

@app.route('/api/jira/find-projects')
def get_jira_find_projects():
    """Get all projects for the project selector"""
    try:
        url = f"https://{JIRA_DOMAIN}/rest/api/3/project/search"
        response = make_jira_request(url)
        
        if response.status_code == 200:
            projects_data = response.json()
            # Jira's /project/search returns a 'values' key for the actual projects
            # We want to return a similar structure to the old find-projects endpoint
            simplified_projects = []
            for project in projects_data.get('values', []):
                simplified_projects.append({
                    "key": project.get('key'),
                    "name": project.get('name'),
                    "projectTypeKey": project.get('projectTypeKey'),
                    "lead": project.get('lead', {}).get('displayName'),
                    "id": project.get('id')
                })
            
            return jsonify({
                "total": len(simplified_projects),
                "projects": simplified_projects,
                "message": "Use the 'key' field from these results in your API calls"
            })
        else:
            return jsonify({"error": "Failed to fetch Jira projects", "details": response.text}), response.status_code
            
    except Exception as e:
        logger.error(f"Error fetching projects from find-projects: {str(e)}")
        return jsonify({"error": f"Exception occurred: {str(e)}"}), 500

if __name__ == '__main__':
    # Check if required environment variables are set
    if not JIRA_API_TOKEN and not OAUTH_CLIENT_ID:
        logger.warning("Neither JIRA_API_TOKEN nor OAuth credentials are configured!")
        logger.info("Set JIRA_API_TOKEN for basic auth or OAUTH_CLIENT_ID/OAUTH_CLIENT_SECRET for OAuth")
    
    app.run(debug=True, port=8000)