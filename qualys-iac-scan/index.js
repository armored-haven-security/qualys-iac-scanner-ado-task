const tl = require('azure-pipelines-task-lib/task');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

async function run() {
    try {
        // Get input parameters
        const qualysBaseUrl = tl.getInput('qualysBaseUrl', true);
        const qualysUsername = tl.getInput('qualysUsername', true);
        const qualysPassword = tl.getInput('qualysPassword', true);
        const iacTemplateDir = tl.getPathInput('iacTemplateDir', true);
        const scanName = tl.getInput('scanName', false) || `ADO-IaC-Scan-${process.env.BUILD_BUILDNUMBER || Date.now()}`;
        const pollInterval = parseInt(tl.getInput('pollInterval', false) || '30');
        const pollTimeout = parseInt(tl.getInput('pollTimeout', false) || '1800');
        const customCaBundle = tl.getPathInput('customCaBundle', false);
        const failOnFindings = tl.getBoolInput('failOnFindings', false);

        console.log('Starting Qualys IaC scan...');
        console.log(`Scan name: ${scanName}`);
        console.log(`Template directory: ${iacTemplateDir}`);
        console.log(`Poll interval: ${pollInterval}s`);
        console.log(`Poll timeout: ${pollTimeout}s`);

        // Validate inputs
        if (!fs.existsSync(iacTemplateDir)) {
            tl.setResult(tl.TaskResult.Failed, `IaC template directory does not exist: ${iacTemplateDir}`);
            return;
        }

        if (customCaBundle && !fs.existsSync(customCaBundle)) {
            tl.setResult(tl.TaskResult.Failed, `Custom CA bundle file does not exist: ${customCaBundle}`);
            return;
        }

        // Get the directory where this task is running
        const taskDir = __dirname;
        const pythonDir = path.join(taskDir, 'python');

        // Check if Python is available
        const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';
        
        // Create environment variables for the Python script
        const env = {
            ...process.env,
            QUALYS_BASE_URL: qualysBaseUrl,
            QUALYS_USERNAME: qualysUsername,
            QUALYS_PASSWORD: qualysPassword,
            IAC_TEMPLATE_DIR: iacTemplateDir,
            SCAN_NAME: scanName,
            POLL_INTERVAL: pollInterval.toString(),
            POLL_TIMEOUT: pollTimeout.toString()
        };

        if (customCaBundle) {
            env.QUALYS_CUSTOM_CA_BUNDLE = customCaBundle;
        }

        // Run the Python scanner
        console.log('Executing Qualys IaC scanner...');
        const pythonProcess = spawn(pythonCmd, [path.join(pythonDir, 'main.py')], {
            cwd: pythonDir,
            env: env,
            stdio: 'pipe'
        });

        let stdout = '';
        let stderr = '';

        pythonProcess.stdout.on('data', (data) => {
            const output = data.toString();
            stdout += output;
            console.log(output.trim());
        });

        pythonProcess.stderr.on('data', (data) => {
            const output = data.toString();
            stderr += output;
            console.error(output.trim());
        });

        const exitCode = await new Promise((resolve) => {
            pythonProcess.on('close', resolve);
        });

        if (exitCode !== 0) {
            tl.setResult(tl.TaskResult.Failed, `Python scanner failed with exit code ${exitCode}`);
            return;
        }

        console.log('Qualys IaC scan completed successfully.');

        // Check if results files exist and parse them
        const resultsJsonPath = path.join(pythonDir, 'results.json');
        const resultsSarifPath = path.join(pythonDir, 'results.sarif');

        if (fs.existsSync(resultsJsonPath)) {
            console.log('Parsing scan results...');
            
            // Run the result parser
            const parserProcess = spawn(pythonCmd, [path.join(pythonDir, 'resultParser.py'), resultsJsonPath], {
                cwd: pythonDir,
                stdio: 'pipe'
            });

            let parserStdout = '';
            let parserStderr = '';

            parserProcess.stdout.on('data', (data) => {
                parserStdout += data.toString();
            });

            parserProcess.stderr.on('data', (data) => {   
                parserStderr += data.toString();
            });

            const parserExitCode = await new Promise((resolve) => {
                parserProcess.on('close', resolve);
            });

            // Output parser results
            if (parserStdout.trim()) {
                console.log('Scan Results:');
                console.log(parserStdout);
            }

            if (parserStderr.trim()) {
                console.log('Parser Output:');
                console.log(parserStderr);
            }

            // Upload results as build artifacts
            const artifactDir = path.join(process.env.AGENT_TEMPDIRECTORY || '/tmp', 'qualys-results');
            if (!fs.existsSync(artifactDir)) {
                fs.mkdirSync(artifactDir, { recursive: true });
            }

            // Copy results to artifact directory
            fs.copyFileSync(resultsJsonPath, path.join(artifactDir, 'results.json'));
            if (fs.existsSync(resultsSarifPath)) {
                fs.copyFileSync(resultsSarifPath, path.join(artifactDir, 'results.sarif'));
            }

            // Upload as pipeline artifact
            tl.uploadArtifact('qualys-results', artifactDir, 'Qualys IaC Scan Results');

            // Determine if we should fail the build based on findings
            if (failOnFindings && parserExitCode !== 0) {
                tl.setResult(tl.TaskResult.Failed, 'Security vulnerabilities found in IaC templates. Check the scan results for details.');
                return;
            } else if (parserExitCode !== 0) {
                tl.setResult(tl.TaskResult.SucceededWithIssues, 'Security vulnerabilities found in IaC templates, but build continues as configured.');
            }
        } else {
            console.log('No results file found - scan may have completed without generating results.');
        }

        console.log('Task completed successfully.');

    } catch (err) {
        tl.setResult(tl.TaskResult.Failed, err.message);
    }
}

run();