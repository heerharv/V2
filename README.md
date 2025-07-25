# Jira Project Dashboard

A modern, interactive dashboard for Jira projects that provides real-time insights into project progress, team members, and key metrics.

## Features

- Real-time project statistics and health metrics
- Interactive Kanban board view
- Team member management
- Project timeline visualization
- Budget tracking
- Risk management
- Action items tracking
- Microsoft Teams integration

## Prerequisites

- Python 3.8 or higher
- Jira Cloud instance
- Microsoft Teams account (optional, for Teams integration)

## Installation

1. Clone the repository:
```bash
git clone <your-repository-url>
cd jira-project-dashboard
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the root directory with your configuration:
```env
JIRA_DOMAIN=your-jira-domain
JIRA_EMAIL=your-email
JIRA_API_TOKEN=your-api-token
SECRET_KEY=your-secret-key
```

## Running the Application

1. Start the Flask server:
```bash
python app.py
```

2. Open your browser and navigate to:
```
http://localhost:8000
```

## Configuration

The application requires the following environment variables:

- `JIRA_DOMAIN`: Your Jira Cloud domain (e.g., https://your-domain.atlassian.net)
- `JIRA_EMAIL`: Your Jira account email
- `JIRA_API_TOKEN`: Your Jira API token
- `SECRET_KEY`: Flask secret key for session management
- `OAUTH_CLIENT_ID`: (Optional) For OAuth authentication
- `OAUTH_CLIENT_SECRET`: (Optional) For OAuth authentication
- `TEAMS_CLIENT_ID`: (Optional) For Microsoft Teams integration
- `TEAMS_CLIENT_SECRET`: (Optional) For Microsoft Teams integration

## Project Structure

```
jira-project-dashboard/
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── static/            # Static files (CSS, JS, images)
├── templates/         # HTML templates
└── .env              # Environment variables (not in git)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
