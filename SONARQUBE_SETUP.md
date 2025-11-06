# SonarQube Setup Guide

## Prerequisites
Your repository is now configured to run SonarQube analysis on SonarCloud.

## Setup Steps

### 1. Create SonarCloud Account
1. Go to [SonarCloud.io](https://sonarcloud.io)
2. Click "Log in" and authenticate with your GitHub account
3. Authorize SonarCloud to access your GitHub repositories

### 2. Import Your Project
1. Click the **"+"** icon in the top right
2. Select **"Analyze new project"**
3. Choose your organization: `github-personal-org`
4. Select the repository: `NiranjanOrgGround/AddressBook`
5. Click **"Set Up"**

### 3. Choose Analysis Method
1. Select **"With GitHub Actions"**
2. SonarCloud will guide you through the setup

### 4. Generate SonarCloud Token
1. In SonarCloud, go to **My Account** → **Security** tab
2. Under **Tokens**, enter a name (e.g., `AddressBook-GitHub-Actions`)
3. Click **Generate**
4. **Copy the token** (you won't be able to see it again!)

### 5. Add Token to GitHub Secrets
1. Go to your GitHub repository: `https://github.com/NiranjanOrgGround/AddressBook`
2. Click **Settings** → **Secrets and variables** → **Actions**
3. Click **"New repository secret"**
4. Name: `SONAR_TOKEN`
5. Value: Paste the token from SonarCloud
6. Click **"Add secret"**

### 6. Configuration Already Done ✅

The following files have been configured for you:

#### `.github/workflows/maven.yml`
- Added SonarQube job that runs after build
- Uses Java 17 for analysis (SonarQube requirement)
- Configured with your project key and organization
- Will run on push to main and pull requests

#### `pom.xml`
- Added SonarQube properties:
  - Project Key: `NiranjanOrgGround_AddressBook`
  - Organization: `github-personal-org`
  - Host URL: `https://sonarcloud.io`
  - Java version: 1.8

## Running the Analysis

### Automatic Trigger
The SonarQube analysis will run automatically when you:
- Push to the `main` branch
- Create a pull request to `main`

### Manual Trigger
1. Go to **Actions** tab in GitHub
2. Select **"Build"** workflow
3. Click **"Run workflow"**

## Viewing Results

### On SonarCloud:
1. Go to [SonarCloud.io](https://sonarcloud.io)
2. Navigate to your project: `NiranjanOrgGround_AddressBook`
3. View:
   - **Overview**: Quality Gate status, coverage, duplications
   - **Issues**: All detected vulnerabilities and code smells
   - **Security Hotspots**: Security-sensitive code requiring review
   - **Measures**: Detailed metrics

### Expected Issues from Vulnerable Code:

#### Security Vulnerabilities (High/Critical):
- SQL Injection in `findByLastNameUnsafe()`
- Command Injection in `runPing()` and `executeCommand()`
- Hardcoded credentials (passwords, API keys)
- Weak cryptographic algorithms (MD5, DES)
- Unsafe deserialization
- Path Traversal in `readFile()`
- XXE vulnerability in XML parsing
- SSRF in `fetchURL()`
- Disabled SSL certificate validation

#### Security Hotspots:
- Insecure random number generation
- Missing input validation
- Information exposure in logs
- Open redirect vulnerabilities
- XSS vulnerabilities

#### Code Smells:
- Empty catch blocks
- Resource leaks
- Null pointer risks
- Missing error handling

## Quality Gate

SonarCloud will fail the quality gate if:
- New security vulnerabilities are introduced
- Code coverage drops below threshold
- Code duplications increase
- Maintainability rating decreases

## Integration with GitHub

Once configured, you'll see:
- ✅ SonarQube status checks on pull requests
- 📊 Code quality metrics in PR comments
- 🔒 Security vulnerability notifications
- 🎯 Quality gate pass/fail status

## Troubleshooting

### Build Fails with "SONAR_TOKEN not found"
- Make sure you added the `SONAR_TOKEN` secret in GitHub repository settings

### "Project not found" error
- Verify the project key matches: `NiranjanOrgGround_AddressBook`
- Verify the organization matches: `github-personal-org`
- Make sure you've imported the project in SonarCloud first

### Analysis doesn't start
- Check the Actions tab for workflow run status
- Ensure the workflow file is in `.github/workflows/maven.yml`
- Verify the build job completes successfully before SonarQube job runs

## Cleanup After Testing

To remove vulnerable code before production:
```bash
git checkout HEAD~1 -- src/main/java/com/vaadin/tutorial/addressbook/backend/VulnerableUtils.java
git checkout HEAD~1 -- src/main/java/com/vaadin/tutorial/addressbook/backend/SecurityTestDriver.java
git checkout HEAD~1 -- src/main/java/com/vaadin/tutorial/addressbook/backend/ContactService.java
git checkout HEAD~1 -- src/main/java/com/vaadin/tutorial/addressbook/AddressbookUI.java
git rm src/main/java/com/vaadin/tutorial/addressbook/backend/VulnerableUtils.java
git rm src/main/java/com/vaadin/tutorial/addressbook/backend/SecurityTestDriver.java
git commit -m "Remove intentional vulnerabilities"
git push
```

## Resources
- [SonarCloud Documentation](https://docs.sonarcloud.io/)
- [SonarQube Maven Plugin](https://docs.sonarqube.org/latest/analyzing-source-code/scanners/sonarscanner-for-maven/)
- [GitHub Actions Integration](https://docs.sonarcloud.io/advanced-setup/ci-based-analysis/github-actions/)
