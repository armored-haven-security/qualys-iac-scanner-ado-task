# Custom Azure DevOps Server Task for Qualys Infrastructure-as-Code Scanning

## Background
The [Qualys TotalCloud IaC scanner for Azure DevOps](https://marketplace.visualstudio.com/items?itemName=Qualys-Inc.iac-build-release-task) is only compatible with Azure DevOps Services, which is the cloud version. To enable this for on-premises versions there are a few ways to approach the solution. One is a custom task extension that is available across your organization, the other is a shared repository. This solution follows the former. 

### Structure
The repo provides the overall structure for creating the extension. The commands to do so are included in the deployment instructions below. 

The directory and file structure should be:

```
qualys-iac-extension/
├── vss-extension.json                 # Extension manifest
├── README.md                          # Extension documentation
├── images/
│   └── extension-icon.png            # Extension icon (128x128 px)
└── qualys-iac-scan/                  # Task directory
    ├── task.json                     # Task definition
    ├── package.json                  # Node.js dependencies
    ├── index.js                      # Main task logic
    └── python/                       # Python scanner files
        ├── main.py                   # Your existing main.py
        ├── config.py                 # Configuration management
        ├── file_utils.py             # Your existing file_utils.py
        ├── qualys_client.py          # Your existing qualys_client.py
        └── resultParser.py           # Your existing resultParser.py
```

## Execution

### 1. Clone the repo where desired

### 2. Install Dependencies

Navigate to the task directory and install Node.js dependencies:

```bash
cd qualys-iac-extension/qualys-iac-scan
npm install
```

### 3. Install Python Dependencies

Ensure the Python environment has the required packages:

```bash
cd python
pip install requests
```

### 4. Package the Extension

Install the Azure DevOps extension packaging tool:

```bash
npm install -g tfx-cli
```

From the root directory, package your extension:

```bash
cd qualys-iac-extension
tfx extension create --manifest-globs vss-extension.json
```

### 5. Upload the extension to the ADO Server Extensions

1. Navigate to https://[your org ADO server URL]/_gallery/manage

_....TBD on the rest after testing_

## Configuration

### Task Parameters

The task accepts the following parameters:

- **Qualys Base URL**: Your Qualys API endpoint
- **Qualys Username**: API username
- **Qualys Password**: API password (use secret variables)
- **IaC Template Directory**: Directory containing IaC templates
- **Scan Name**: Name for the scan (optional)
- **Poll Interval**: How often to check for completion (seconds)
- **Poll Timeout**: Maximum wait time (seconds)
- **Custom CA Bundle Path**: Optional custom CA bundle for SSL
- **Fail Build on Security Findings**: Whether to fail the build on findings

### Pipeline YAML Example

```yaml
steps:
- task: qualys-iac-scan@1
  displayName: 'Qualys IaC Security Scan'
  inputs:
    qualysBaseUrl: 'https://qualysapi.qualys.com'
    qualysUsername: '$(QUALYS_USERNAME)'
    qualysPassword: '$(QUALYS_PASSWORD)'
    iacTemplateDir: '$(System.DefaultWorkingDirectory)/terraform'
    failOnFindings: true
```

## Requirements

- Python 3.6+ available on build agents
- Required Python packages: requests
- Azure DevOps Server or Azure DevOps Services