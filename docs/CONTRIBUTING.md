# 🤝 Contribution Guidelines for PhantomNet

Welcome to **PhantomNet**! We're excited to have you contribute to our AI-driven adaptive honeypot mesh project. This document will guide you through the contribution process and help you become an effective contributor.

**Last Updated**: December 10, 2025  
**Version**: 1.0  
**Status**: Active

---

## 📋 Table of Contents

- [Welcome](#welcome)
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Types of Contributions](#types-of-contributions)
- [Development Setup](#development-setup)
- [Workflow & Process](#workflow--process)
- [Coding Standards](#coding-standards)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Code Review Checklist](#code-review-checklist)
- [Testing Requirements](#testing-requirements)
- [Documentation Standards](#documentation-standards)
- [Git Workflow](#git-workflow)
- [Communication & Support](#communication--support)
- [Recognition & Credits](#recognition--credits)
- [FAQ](#faq)

---

## 🎯 Welcome

PhantomNet is a collaborative project aimed at building the next-generation threat detection system. Whether you're a security expert, AI/ML engineer, full-stack developer, or student, **your contributions are valuable**!

### Why Contribute?

✨ **Build Something Impactful**
- Create a real-world cybersecurity solution
- Work with cutting-edge technologies

🚀 **Grow Your Skills**
- Learn enterprise-grade development practices
- Master full-stack architecture
- Understand security best practices

💼 **Build Your Portfolio**
- Add impressive projects to your GitHub
- Demonstrate professional collaboration
- Create interview-ready code examples

🎓 **Academic Recognition**
- Perfect for coursework and final projects
- Research publication opportunities
- Conference presentation potential

---

## 📜 Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inspiring community for all. We pledge to make participation in our project a harassment-free experience for everyone.

### Our Standards

✅ **DO:**
- Be respectful and inclusive of all contributors
- Provide constructive feedback
- Focus on what is best for the community
- Help others succeed
- Report concerns to project maintainers

❌ **DON'T:**
- Use offensive language or engage in harassment
- Discriminate based on any characteristic
- Post spam or promotional content
- Share credentials or sensitive data
- Steal or plagiarize work

### Enforcement

Violations of the Code of Conduct will result in actions ranging from warnings to removal from the project. All reports will be reviewed confidentially.

**Report Issues To**: [Project Maintainers] or [Discord Moderation Team]

---

## 🚀 Getting Started

### Prerequisites

Before you start contributing, ensure you have:

**Software Requirements:**
- Git (v2.30+) - [Install Guide](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)
- Python 3.9+ - [Download](https://www.python.org/downloads/)
- Node.js 16+ & npm - [Download](https://nodejs.org/)
- PostgreSQL 12+ - [Download](https://www.postgresql.org/download/)
- Docker & Docker Compose - [Download](https://www.docker.com/)
- VS Code or PyCharm (recommended) - [Download](https://code.visualstudio.com/)

**Account Requirements:**
- GitHub account - [Create free account](https://github.com/signup)
- SSH key configured for GitHub - [Setup Guide](https://docs.github.com/en/authentication/connecting-to-github-with-ssh)

**Knowledge Requirements:**
- Basic git workflow (commit, push, pull)
- Understanding of your role (Security, AIML, Backend, or Frontend)
- Familiarity with one of our tech stacks

### Step 1: Fork the Repository

```bash
# Go to https://github.com/your-team/phantomnet
# Click "Fork" button in top-right corner
# This creates a copy under your GitHub account
```

### Step 2: Clone Your Fork

```bash
git clone https://github.com/YOUR-USERNAME/phantomnet.git
cd phantomnet
```

### Step 3: Add Upstream Remote

```bash
# This allows you to sync with the official repo
git remote add upstream https://github.com/TEAM-USERNAME/phantomnet.git
git remote -v  # Verify both origin and upstream exist
```

### Step 4: Create Your Feature Branch

```bash
# Always create a new branch for each feature/fix
git checkout -b feature/your-feature-name
# OR
git checkout -b fix/bug-description
# OR
git checkout -b docs/documentation-update
```

### Step 5: Set Up Development Environment

```bash
# Install Python dependencies
cd backend && pip install -r requirements.txt

# Install frontend dependencies
cd ../frontend && npm install

# Set up environment variables
cp .env.example .env
# Edit .env with your local configuration
```

### Step 6: Verify Setup

```bash
# Run tests
pytest  # Backend tests
npm test  # Frontend tests

# Should see: All tests passed ✅
```

---

## 🎨 Types of Contributions

### 1. 🐛 Bug Fixes

**Good first issues for beginners!**

```markdown
Example:
- Title: Fix: API returns 500 error when database connection fails
- Description: Document the bug, expected behavior, actual behavior
- Steps to reproduce: Clear steps to trigger the bug
- Error logs: Full error messages and stack traces
```

**How to contribute:**
1. Find an issue labeled `bug` or `help wanted`
2. Comment: "I'd like to work on this"
3. Follow the workflow below
4. Submit PR with fixes

### 2. ✨ New Features

**Larger contributions that add functionality**

```markdown
Example:
- Add HTTP honeypot support
- Implement real-time WebSocket updates
- Create dashboard analytics view
```

**How to contribute:**
1. Check open issues for related discussions
2. Create an issue describing your feature
3. Wait for approval from maintainers
4. Implement following the workflow

### 3. 📚 Documentation

**Critical for project success!**

```markdown
Types:
- README improvements
- API documentation
- Setup guides
- Troubleshooting guides
- Architecture diagrams
- Code examples
```

**How to contribute:**
1. No approval needed for documentation
2. Submit PR with improvements
3. Use clear, beginner-friendly language

### 4. 🧪 Tests & QA

**Ensure code quality and reliability**

```markdown
Examples:
- Unit tests for new functions
- Integration tests for endpoints
- End-to-end test scenarios
- Performance tests
```

### 5. 🎨 UI/UX Improvements

**Make PhantomNet beautiful and usable**

```markdown
Examples:
- Improve dashboard design
- Add dark mode
- Better error messages
- Responsive design fixes
```

### 6. ⚡ Performance Optimizations

**Make PhantomNet faster**

```markdown
Examples:
- Optimize database queries
- Reduce API response times
- Improve frontend load time
- Memory optimization
```

### 7. 🔒 Security Improvements

**Critical for a security product!**

```markdown
Examples:
- Add input validation
- Improve authentication
- Security vulnerability fixes
- Secure coding practices
```

---

## 🔧 Development Setup

### Complete Local Setup

```bash
# 1. Clone repository
git clone https://github.com/YOUR-USERNAME/phantomnet.git
cd phantomnet

# 2. Create virtual environment (Python)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install backend dependencies
cd backend
pip install -r requirements.txt

# 4. Set up PostgreSQL
# Option A: Using Docker (recommended)
docker run --name phantomnet-db -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d postgres:15

# Option B: Local installation
createdb phantomnet
psql -U postgres -d phantomnet < schema.sql

# 5. Configure environment
cp .env.example .env
# Edit .env with database credentials

# 6. Run migrations (if applicable)
python3 manage.py migrate  # Or similar command

# 7. Start backend
python3 -m uvicorn main:app --reload

# 8. In another terminal, set up frontend
cd ../frontend
npm install
npm run dev

# 9. Open http://localhost:5173 in browser
```

### Docker Setup (Recommended)

```bash
# Build and run all services
docker-compose up --build

# Verify all containers running
docker ps

# Access services:
# - Frontend: http://localhost:5173
# - Backend API: http://localhost:8000
# - Docs: http://localhost:8000/docs
# - Database: localhost:5432
```

### Useful Commands

```bash
# Check git status
git status

# See your changes
git diff

# See staged changes
git diff --staged

# View commit history
git log --oneline -10

# View branches
git branch -a

# Pull latest from upstream
git fetch upstream
git rebase upstream/main
```

---

## 🔄 Workflow & Process

### Step 1: Identify What to Work On

**Option A: Existing Issues**
```bash
# Go to GitHub Issues
# Filter by labels: bug, enhancement, help wanted, good first issue
# Check if anyone is already working on it
# Comment: "I'd like to work on this"
# Wait for assignment confirmation
```

**Option B: Your Own Idea**
```bash
# Create an issue first! Don't start working without discussion
# Describe the problem/feature
# Wait for feedback from maintainers
# Get approval before implementing
```

### Step 2: Create Feature Branch

**Branch Naming Convention:**
```
[type]/[description]

Types:
- feature/  : New feature (feature/http-honeypot)
- fix/      : Bug fix (fix/api-timeout-issue)
- docs/     : Documentation (docs/setup-guide)
- test/     : Tests (test/add-unit-tests)
- refactor/ : Code refactoring (refactor/api-structure)
- perf/     : Performance (perf/optimize-queries)

Examples:
✅ feature/add-ftp-honeypot
✅ fix/database-connection-error
✅ docs/api-documentation
❌ my-changes
❌ test123
```

```bash
# Create and switch to branch
git checkout -b feature/your-descriptive-feature-name

# Verify you're on correct branch
git branch
# Should show: * feature/your-feature-name
```

### Step 3: Make Your Changes

**Golden Rules:**
- ✅ Make one feature/fix per branch
- ✅ Keep commits small and focused
- ✅ Write clear commit messages
- ✅ Update related documentation
- ✅ Add tests for new code
- ✅ Verify all tests pass locally

```bash
# Make your changes in your editor

# Check what you've changed
git status

# See the actual changes
git diff

# Stage changes for commit
git add .
# Or stage specific files:
git add path/to/file1 path/to/file2
```

### Step 4: Commit Your Changes

**See "Commit Guidelines" section below**

```bash
git commit -m "Type: Brief description of change"
# Example:
git commit -m "Feature: Add HTTP honeypot support with JSON logging"
```

### Step 5: Keep Your Branch Updated

```bash
# Fetch latest from upstream
git fetch upstream

# Rebase your changes on top of latest main
git rebase upstream/main

# If conflicts occur, resolve them and continue
git rebase --continue
```

### Step 6: Push to Your Fork

```bash
git push origin feature/your-feature-name
```

### Step 7: Create Pull Request

- Go to GitHub
- You'll see a suggestion to create a PR
- Click "Create Pull Request"
- Follow the PR template (see below)
- Submit!

### Step 8: Respond to Feedback

- Maintainers will review your code
- Address comments and suggestions
- Push updates to the same branch
- Don't force-push after PR is open

### Step 9: Merge and Cleanup

- Once approved, maintainers will merge
- Delete your branch:
  ```bash
  git branch -d feature/your-feature-name
  ```

---

## 📐 Coding Standards

### Python Code Standards

**Style Guide: PEP 8**

```python
# ✅ DO:
def calculate_threat_score(events: list[dict]) -> float:
    """
    Calculate overall threat score from events.
    
    Args:
        events: List of event dictionaries
        
    Returns:
        float: Threat score between 0.0 and 100.0
    """
    total_score = sum(event.get('score', 0) for event in events)
    average = total_score / len(events) if events else 0.0
    return min(average, 100.0)


class EventProcessor:
    """Process security events from honeypots."""
    
    def __init__(self, db_connection):
        self.db = db_connection
        self.logger = logging.getLogger(__name__)
    
    def process(self, event: dict) -> bool:
        """Process a single event."""
        try:
            # Implementation
            return True
        except Exception as e:
            self.logger.error(f"Processing failed: {e}")
            return False


# ❌ DON'T:
def calc(e):  # Bad: unclear name
    s = 0
    for event in e:
        s = s + event['score']  # Bad: no type hints
    return s / len(e)  # Bad: no error handling


def function_with_no_docstring(x, y):
    return x + y
```

**Formatting Requirements:**
```python
# Use 4 spaces for indentation
# Max line length: 88 characters
# Use type hints for function parameters and returns
# Add docstrings to all functions and classes
# Use meaningful variable names
# Keep functions focused and small (< 50 lines ideal)

# Recommended tools:
# - Black: Code formatter
# - Ruff: Linter
# - MyPy: Type checker
```

**Before submitting:**
```bash
# Format code
black backend/

# Lint code
ruff check backend/

# Type checking
mypy backend/

# Run tests
pytest backend/
```

### JavaScript/React Code Standards

**Style Guide: Airbnb/Standard**

```javascript
// ✅ DO:
// Use camelCase for variables and functions
const getUserData = async (userId) => {
  try {
    const response = await fetch(`/api/users/${userId}`);
    if (!response.ok) {
      throw new Error('Failed to fetch user');
    }
    return response.json();
  } catch (error) {
    console.error('Error:', error);
    throw error;
  }
};

// Use PascalCase for components
const UserDashboard = ({ userId }) => {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  
  useEffect(() => {
    fetchData();
  }, [userId]);
  
  const fetchData = async () => {
    try {
      setError(null);
      const userData = await getUserData(userId);
      setData(userData);
    } catch (err) {
      setError(err.message);
    }
  };
  
  return (
    <div className="dashboard">
      {error && <ErrorMessage message={error} />}
      {data && <DisplayData data={data} />}
    </div>
  );
};

export default UserDashboard;


// ❌ DON'T:
const GetUserData = (userid) => {  // Bad: wrong naming
  return fetch('/api/users/' + userid)  // Bad: string concat
    .then(r => r.json())  // Bad: abbreviations
    .catch(e => console.log(e));  // Bad: no error handling
};

function component() {  // Bad: no meaningful name
  // No hooks, poor structure
}
```

**Formatting Requirements:**
```javascript
// Use 2 spaces for indentation
// Max line length: 100 characters
// Use const/let, avoid var
// Use arrow functions
// Use destructuring
// Add PropTypes or TypeScript
// Write comments for complex logic

// Recommended tools:
// - Prettier: Code formatter
// - ESLint: Linter
// - TypeScript: Type safety
```

**Before submitting:**
```bash
# Format code
prettier --write frontend/src

# Lint code
npm run lint

# Run tests
npm test
```

### General Standards for All Code

```markdown
1. **Readability First**
   - Use clear variable names
   - Add comments for complex logic
   - Keep functions small and focused
   - Use meaningful function names

2. **DRY Principle** (Don't Repeat Yourself)
   - Extract reusable functions
   - Use helper modules
   - Avoid code duplication

3. **Error Handling**
   - Handle all edge cases
   - Provide meaningful error messages
   - Log errors appropriately
   - Fail gracefully

4. **Security**
   - Never hardcode secrets
   - Validate all inputs
   - Use parameterized queries
   - Follow OWASP guidelines

5. **Testing**
   - Write tests for new code
   - Aim for 80%+ code coverage
   - Test edge cases
   - Include integration tests

6. **Documentation**
   - Document public APIs
   - Add docstrings/comments
   - Update README if needed
   - Include examples
```

---

## 💬 Commit Guidelines

### Commit Message Format

```
[Type]: Brief description (50 chars max)

Detailed explanation of what and why (if needed).
Keep it concise but informative.

Fixes #123  (if fixing an issue)
```

### Types

```
feature:   New functionality
fix:       Bug fixes
docs:      Documentation changes
style:     Code style changes (formatting, etc.)
refactor:  Code restructuring without behavior change
perf:      Performance improvements
test:      Adding or updating tests
chore:     Maintenance tasks, dependencies
```

### Examples

```bash
# ✅ GOOD COMMITS:
git commit -m "Feature: Add SSH honeypot with JSON logging"
git commit -m "Fix: Resolve database connection timeout issue"
git commit -m "Docs: Add setup guide for Windows users"
git commit -m "Test: Add unit tests for threat scoring algorithm"
git commit -m "Refactor: Simplify event parser logic
- Remove redundant validation
- Improve error handling
- Fixes #42"

# ❌ BAD COMMITS:
git commit -m "Update"
git commit -m "Fixed stuff"
git commit -m "WIP: working on this"
git commit -m "asdf"
```

### Best Practices

```bash
# ✅ DO:
# - Make commits atomic (one logical change per commit)
# - Commit frequently (multiple commits per feature)
# - Write clear, descriptive messages
# - Reference issues when fixing them (#123)
# - Include context in longer messages

# ❌ DON'T:
# - Mix multiple features in one commit
# - Commit unrelated changes together
# - Write vague messages
# - Commit and push broken code
# - Commit credentials or secrets
```

### Example Workflow

```bash
# Work on feature
nano backend/honeypots/ssh.py  # Make changes

# Commit this specific change
git add backend/honeypots/ssh.py
git commit -m "Feature: Add SSH banner capture"

# Continue working
nano backend/honeypots/ssh.py  # More changes

# Commit next part
git add backend/honeypots/ssh.py
git commit -m "Feature: Add brute force detection logic"

# Update tests
nano tests/test_ssh.py

# Commit tests
git add tests/test_ssh.py
git commit -m "Test: Add unit tests for SSH honeypot"

# All pushed together in one PR, but with clear history
git push origin feature/ssh-enhancements
```

---

## 🔀 Pull Request Process

### Before Creating a PR

Ensure:
- [ ] Code follows style guidelines
- [ ] Tests pass: `pytest` and `npm test`
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] No merge conflicts
- [ ] Branch rebased on latest main
- [ ] Commits are clean and meaningful

### PR Template

```markdown
## Description
Brief description of what this PR does.

## Related Issue
Fixes #123
Related to #456

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Breaking change
- [ ] Performance improvement

## Changes Made
- Change 1
- Change 2
- Change 3

## How to Test
1. Step to test
2. Step to test
3. Expected result

## Screenshots (if applicable)
<!-- Add images for UI changes -->

## Checklist
- [ ] Code follows style guidelines
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Self-review completed
```

### Example PR

```markdown
## Description
Implement FTP honeypot with real-time logging and threat detection

## Related Issue
Fixes #15
Related to #8

## Type of Change
- [x] New feature
- [x] Database schema update
- [ ] Breaking change

## Changes Made
- Created FTP honeypot in `backend/honeypots/ftp/`
- Added logging handler for FTP events
- Extended database schema with ftp_events table
- Added API endpoint GET /events/ftp
- Updated frontend to display FTP events

## How to Test
1. Start FTP honeypot: `python3 backend/honeypots/ftp/honeypot.py`
2. Connect with FTP client: `ftp localhost 2121`
3. Try various FTP commands (login, upload, etc.)
4. Check database: `SELECT * FROM events WHERE honeypot_type='ftp'`
5. Check API: `curl http://localhost:8000/events/ftp | jq .`
6. Verify events display in dashboard

## Checklist
- [x] Code follows style guidelines (black, ruff)
- [x] 8 new unit tests added
- [x] Documentation updated in docs/
- [x] All tests passing
- [x] Self-review completed
```

### What to Expect

**Timeline:**
- 🟡 **Submitted**: Automated checks run
- 🟡 **Review**: Maintainers review code (1-3 days)
- 🔄 **Changes Requested**: You address feedback
- ✅ **Approved**: All checks pass and review approved
- ✅ **Merged**: Maintainer merges to main

**What Reviewers Look For:**
- Code quality and style
- Test coverage
- Documentation completeness
- No security issues
- Architectural alignment
- Performance impact
- Breaking changes

### Responding to Feedback

```bash
# Address feedback with new commits
nano backend/api.py  # Make suggested changes

# Commit with reference to feedback
git add backend/api.py
git commit -m "Address review feedback: Add input validation

- Add type checking for request parameters
- Improve error message clarity
- Add edge case tests"

# Push (don't force-push!)
git push origin feature/your-feature-name
```

---

## ✅ Code Review Checklist

**Use this when reviewing others' code:**

### Functionality
- [ ] Does the code do what the PR description says?
- [ ] Are there edge cases handled?
- [ ] Is error handling appropriate?
- [ ] Are there potential race conditions or thread issues?

### Code Quality
- [ ] Code follows style guidelines
- [ ] Variable names are clear
- [ ] Functions are focused (single responsibility)
- [ ] DRY principle followed
- [ ] No unnecessary complexity

### Security
- [ ] No hardcoded secrets/credentials
- [ ] Input validation present
- [ ] SQL injection prevention (parameterized queries)
- [ ] No sensitive data in logs
- [ ] Proper authentication/authorization checks

### Testing
- [ ] Tests cover new functionality
- [ ] Edge cases tested
- [ ] Tests pass locally
- [ ] No flaky tests
- [ ] Adequate coverage (80%+)

### Documentation
- [ ] Code is commented
- [ ] Docstrings are present
- [ ] README/docs updated
- [ ] API documentation updated
- [ ] Examples provided

### Performance
- [ ] No obvious performance issues
- [ ] Database queries optimized
- [ ] No memory leaks
- [ ] API response times acceptable

### Review Template Response

```markdown
## Review Summary
Overall, this looks great! A few suggestions below.

## Comments
1. ✅ Great job on the error handling
2. 🤔 Consider extracting the validation logic to a helper function
3. 🐛 I noticed a potential issue here... (explain)
4. 📚 Could you add a docstring to this function?

## Suggestions
- Use `filter()` instead of list comprehension here for clarity
- Add a test for the timeout scenario
- Update the API docs with the new endpoint

## Approval
Approving with minor suggestions above. Looks good overall!
```

---

## 🧪 Testing Requirements

### Backend Tests

**Python Testing with pytest:**

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_honeypot.py

# Run with coverage
pytest --cov=backend/ --cov-report=html

# Run only specific test
pytest tests/test_honeypot.py::test_ssh_connection

# Run tests matching pattern
pytest -k "threat"
```

**Test Examples:**

```python
# tests/test_honeypot.py
import pytest
from backend.honeypots.ssh import SSHHoneypot

class TestSSHHoneypot:
    """Test SSH honeypot functionality"""
    
    @pytest.fixture
    def honeypot(self):
        """Create honeypot instance for testing"""
        return SSHHoneypot(port=2222)
    
    def test_honeypot_initializes(self, honeypot):
        """Test that honeypot initializes correctly"""
        assert honeypot.port == 2222
        assert honeypot.is_running() is False
    
    def test_honeypot_starts(self, honeypot):
        """Test that honeypot can start"""
        honeypot.start()
        assert honeypot.is_running() is True
        honeypot.stop()
    
    def test_log_creation(self, honeypot):
        """Test that logs are created"""
        # Implementation
        pass
    
    def test_invalid_credentials(self, honeypot):
        """Test handling of invalid credentials"""
        # Implementation
        pass
```

### Frontend Tests

**JavaScript Testing with Jest/Vitest:**

```bash
# Run all tests
npm test

# Run specific test file
npm test Dashboard.test.jsx

# Run with coverage
npm test -- --coverage

# Watch mode
npm test -- --watch
```

**Test Examples:**

```javascript
// frontend/src/components/Dashboard.test.jsx
import { render, screen, waitFor } from '@testing-library/react';
import Dashboard from './Dashboard';

describe('Dashboard Component', () => {
  test('renders dashboard title', () => {
    render(<Dashboard />);
    expect(screen.getByText(/PhantomNet/i)).toBeInTheDocument();
  });
  
  test('displays loading state initially', () => {
    render(<Dashboard />);
    expect(screen.getByText(/Loading/i)).toBeInTheDocument();
  });
  
  test('displays threat level badge', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText(/HIGH/i)).toBeInTheDocument();
    });
  });
  
  test('handles API errors gracefully', async () => {
    render(<Dashboard />);
    // Mock API error
    // Verify error message displayed
  });
});
```

### Test Coverage Requirements

```markdown
- New code must have 80%+ test coverage
- All public APIs must have tests
- All bugfixes must include regression test
- Integration tests for critical paths
- End-to-end tests for user workflows
```

---

## 📖 Documentation Standards

### Code Documentation

**Python Docstrings (Google Format):**

```python
def analyze_events(events: list[dict], threshold: float = 50.0) -> dict:
    """
    Analyze security events and return threat assessment.
    
    Processes a list of security events and calculates overall
    threat metrics based on event severity and patterns.
    
    Args:
        events: List of event dictionaries with 'severity' and 'type' keys
        threshold: Threat level threshold (0-100), default 50.0
        
    Returns:
        dict: Assessment containing:
            - 'threat_level': str (LOW, MEDIUM, HIGH, CRITICAL)
            - 'score': float (0-100)
            - 'details': list of analysis details
            
    Raises:
        ValueError: If events list is empty
        TypeError: If threshold is not a number
        
    Example:
        >>> events = [{'severity': 8, 'type': 'brute_force'}]
        >>> result = analyze_events(events, threshold=50.0)
        >>> result['threat_level']
        'HIGH'
    """
    if not events:
        raise ValueError("Events list cannot be empty")
    
    # Implementation
    return {'threat_level': 'HIGH', 'score': 75.0, 'details': []}
```

**JavaScript JSDoc:**

```javascript
/**
 * Calculate threat score from attack events
 * 
 * @param {Array<Object>} events - Array of attack event objects
 * @param {number} [threshold=50] - Threat threshold (0-100)
 * @returns {Object} Threat assessment with level and score
 * @throws {Error} If events array is empty
 * 
 * @example
 * const events = [{severity: 8, type: 'brute_force'}];
 * const result = calculateThreatScore(events, 50);
 * console.log(result.level); // 'HIGH'
 */
function calculateThreatScore(events, threshold = 50) {
  // Implementation
  return { level: 'HIGH', score: 75 };
}
```

### API Documentation

**Use OpenAPI/Swagger:**

```python
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="PhantomNet API",
    description="Honeypot threat detection API",
    version="1.0.0"
)

class EventResponse(BaseModel):
    """Event data model"""
    id: int
    timestamp: str
    srcip: str
    threat_score: float

@app.get("/events", response_model=list[EventResponse])
async def get_events(limit: int = 10, hours: int = 24):
    """
    Get recent security events
    
    Retrieve list of recent security events from honeypots,
    with optional filtering by time range.
    
    **Parameters:**
    - `limit`: Maximum number of events to return (default: 10)
    - `hours`: Time range in hours (default: 24)
    
    **Returns:**
    Array of event objects
    
    **Status Codes:**
    - 200: Success
    - 400: Invalid parameters
    - 500: Server error
    
    **Example:**
    ```
    GET /events?limit=5&hours=24
    
    Response:
    [
      {
        "id": 1,
        "timestamp": "2025-12-10T12:00:00Z",
        "srcip": "192.168.1.100",
        "threat_score": 85.0
      }
    ]
    ```
    """
    # Implementation
    pass
```

### README Documentation

**What to Include:**

```markdown
# Project Name
- Brief description (1-2 sentences)
- Key features
- Architecture diagram link
- Live demo (if available)

## Quick Start
- Installation steps
- Running the project
- Basic usage example

## Project Structure
- Folder layout explanation
- Key files and their purposes

## Development
- Setup instructions
- Running tests
- Development server

## Contributing
- Link to CONTRIBUTING.md
- How to submit changes

## Documentation
- Links to detailed docs
- API reference
- Architecture guides

## Support
- Contact information
- Community channels
```

---

## 🌳 Git Workflow

### Feature Branch Workflow

```bash
# 1. Create feature branch from main
git checkout main
git pull upstream main
git checkout -b feature/my-feature

# 2. Make changes and commit
git add .
git commit -m "Feature: Add new feature"

# 3. Keep branch updated
git fetch upstream
git rebase upstream/main

# 4. Push to your fork
git push origin feature/my-feature

# 5. Create Pull Request on GitHub

# 6. Address feedback
git add .
git commit -m "Address feedback: ..."
git push origin feature/my-feature

# 7. After merge, cleanup
git checkout main
git pull upstream main
git branch -d feature/my-feature
```

### Handling Merge Conflicts

```bash
# Fetch latest
git fetch upstream

# Attempt rebase
git rebase upstream/main

# If conflicts occur, fix them
# 1. Open conflicted files
# 2. Look for <<<<<<, ======, >>>>>>
# 3. Choose correct version
# 4. Delete conflict markers
# 5. Save file

# Mark as resolved
git add conflicted-file.py

# Continue rebase
git rebase --continue

# Or abort if needed
git rebase --abort
```

### Keeping Fork Updated

```bash
# Fetch upstream changes
git fetch upstream

# Merge into your main
git checkout main
git merge upstream/main

# Push to your fork
git push origin main
```

---

## 💬 Communication & Support

### Getting Help

**Discord Channels:**
- `#general` - General discussion
- `#tech-help` - Technical questions
- `#announcements` - Important updates
- `#feature-discussion` - Feature ideas

**GitHub Discussions:**
- Use for architecture/design questions
- Ask for feedback on ideas
- Share knowledge and learn together

**Synchronous:**
- Daily standups: 9:00 AM IST
- Office hours: Wednesday 2:00 PM IST
- Team meetings: Friday 10:00 AM IST

**Asynchronous:**
- GitHub Issues for tracking
- Pull request comments for code review
- Discord for quick questions

### Discussion Etiquette

```markdown
✅ DO:
- Search existing discussions first
- Provide context and details
- Share error messages and logs
- Be specific about your question
- Thank people for helping

❌ DON'T:
- Ask the same question multiple times
- Demand immediate responses
- Share credentials or secrets
- Post off-topic content
- Be disrespectful
```

---

## 🎖️ Recognition & Credits

### Attribution

All contributors will be recognized in:
- GitHub contributors list
- `CONTRIBUTORS.md` file
- Project acknowledgments
- Release notes

### Contribution Levels

| Level | Contributions | Recognition |
|-------|---------------|-------------|
| 🥉 Bronze | 1-5 PRs | CONTRIBUTORS.md |
| 🥈 Silver | 6-15 PRs | README + Monthly highlight |
| 🥇 Gold | 15+ PRs | README + Discord role |
| 💎 Platinum | 30+ + Lead | Team member recognition |

### Getting Recognition

- Tag yourself in your PRs
- Add your GitHub username to contributions
- Share your work in Discord
- Showcase in your portfolio

---

## ❓ FAQ

### Q: I want to contribute but don't know where to start

**A:** 
1. Read the README and project overview
2. Look for issues labeled `good first issue`
3. Comment on an issue you want to work on
4. Follow the setup guide in this document
5. Ask questions in Discord if stuck!

---

### Q: What if my PR gets rejected?

**A:** 
1. Don't take it personally! Code review is constructive
2. Read the feedback carefully
3. Ask for clarification if needed
4. Make the requested changes
5. Resubmit - most PRs get approved after revision

---

### Q: Can I work on the same issue as someone else?

**A:**
1. Check the issue comments
2. If someone already claimed it, pick a different one
3. If not claimed, comment that you want to work on it
4. Wait for assignment confirmation
5. One person per issue to avoid duplication

---

### Q: What if I made a mistake in my commit?

**A:** (Before pushing)
```bash
# Amend the last commit
git commit --amend

# Or reset and redo
git reset HEAD~1
git add .
git commit -m "Correct message"
```

(After pushing)
- Create a new commit with the fix
- Don't force-push after PR is open

---

### Q: How long does code review take?

**A:**
- Small fixes: 12-24 hours
- Medium features: 2-3 days
- Large features: up to 1 week
- We prioritize based on complexity and team capacity

---

### Q: Can I ask questions about my code?

**A:**
Absolutely! It's encouraged. You can ask:
- In Discord #tech-help
- In your PR comments
- In related issues
- During office hours

---

### Q: What's the best way to learn the codebase?

**A:**
1. Read architecture documentation
2. Review existing code
3. Run the project locally
4. Start with small PRs
5. Ask questions when confused
6. Review others' PRs to learn

---

### Q: Do I need to sign anything?

**A:**
- Sign the CLA (if required by your organization)
- No other legal documents needed
- Your contributions are automatically licensed under the project's license

---

### Q: Can I contribute if I'm not a student?

**A:**
**Absolutely!** This project welcomes contributions from:
- Students (academic projects)
- Professionals (learning/portfolio)
- Hobbyists (fun and learning)
- Companies (commercial interest)

Everyone's contributions are valued equally!

---

## 🎓 Learning Resources

### Python Development
- [Python Style Guide (PEP 8)](https://pep8.org/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [SQLAlchemy Guide](https://docs.sqlalchemy.org/)

### JavaScript/React
- [React Official Docs](https://react.dev/)
- [JavaScript Style Guide](https://airbnb.io/javascript/)
- [Modern JavaScript](https://javascript.info/)

### Git & GitHub
- [Git Documentation](https://git-scm.com/doc)
- [GitHub Guides](https://guides.github.com/)
- [Branching Strategies](https://git-flow.readthedocs.io/)

### Security
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Secure Coding](https://cheatsheetseries.owasp.org/)
- [CWE/SANS](https://cwe.mitre.org/)

### DevOps
- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)
- [CI/CD Basics](https://github.com/features/actions)

---

## 📞 Contact & Support

**Questions?** Reach out to us:
- 💬 Discord: [PhantomNet Community]
- 📧 Email: [team@phantomnet.dev]
- 🌐 GitHub Issues: [Report a bug]
- 📚 Documentation: [Detailed guides]

---

## 📝 Document Information

- **Created**: December 10, 2025
- **Last Updated**: December 10, 2025
- **Version**: 1.0
- **Maintainer**: PhantomNet Team
- **License**: Same as project (MIT/Apache 2.0)

---

## 🙏 Thank You!

Your contributions make PhantomNet better every day. Whether you fix a bug, add a feature, improve documentation, or help other contributors, **you're valued and appreciated!**

**Together, we're building the future of threat detection.** 🚀

---

**Ready to contribute? Start here:**
1. Fork the repository
2. Create your feature branch
3. Make your changes
4. Submit a pull request
5. See your code merged and shipped! 🎉

