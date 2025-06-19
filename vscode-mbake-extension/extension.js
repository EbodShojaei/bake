const vscode = require('vscode');
const { exec, spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

/**
 * Extension activation function
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    console.log('mbake Makefile Formatter extension is now active');

    // Register format command
    const formatCommand = vscode.commands.registerCommand('mbake.formatMakefile', async () => {
        await formatCurrentFile();
    });

    // Register check command
    const checkCommand = vscode.commands.registerCommand('mbake.checkMakefile', async () => {
        await checkCurrentFile();
    });

    // Register format on save
    const onSaveHandler = vscode.workspace.onWillSaveTextDocument(async (event) => {
        const config = vscode.workspace.getConfiguration('mbake');
        if (config.get('formatOnSave') && isMakefileDocument(event.document)) {
            event.waitUntil(formatDocument(event.document));
        }
    });

    // Register document formatter provider
    const formatterProvider = vscode.languages.registerDocumentFormattingEditProvider(
        { scheme: 'file', language: 'makefile' },
        {
            provideDocumentFormattingEdits(document) {
                return formatDocument(document);
            }
        }
    );

    // Register initialize configuration command
    const initCommand = vscode.commands.registerCommand('mbake.initConfig', async () => {
        await initializeConfig();
    });

    context.subscriptions.push(formatCommand, checkCommand, onSaveHandler, formatterProvider, initCommand);
}

/**
 * Initialize bake configuration
 */
async function initializeConfig() {
    try {
        const result = await runBakeCommand(null, false, ['init']);
        
        if (result.success) {
            vscode.window.showInformationMessage('mbake configuration initialized successfully');
        } else {
            const errorMsg = result.stderr || result.stdout || 'Unknown error occurred';
            vscode.window.showErrorMessage(`Failed to initialize config: ${errorMsg}`);
        }
    } catch (error) {
        vscode.window.showErrorMessage(`Error initializing config: ${error.message}`);
    }
}

/**
 * Check if document is a Makefile
 * @param {vscode.TextDocument} document
 * @returns {boolean}
 */
function isMakefileDocument(document) {
    const fileName = path.basename(document.fileName).toLowerCase();
    const extension = path.extname(document.fileName).toLowerCase();
    
    return document.languageId === 'makefile' ||
           ['makefile', 'gnumakefile'].includes(fileName) ||
           ['.mk', '.make'].includes(extension);
}

/**
 * Get mbake configuration
 * @returns {object}
 */
function getBakeConfig() {
    const config = vscode.workspace.getConfiguration('mbake');
    return {
        executablePath: config.get('executablePath', 'bake'),
        configPath: config.get('configPath', ''),
        showDiff: config.get('showDiff', false),
        verbose: config.get('verbose', false)
    };
}

/**
 * Build bake command arguments
 * @param {string} filePath
 * @param {boolean} checkOnly
 * @param {string[]} extraArgs
 * @returns {object}
 */
function buildBakeCommand(filePath, checkOnly = false, extraArgs = []) {
    const config = getBakeConfig();
    const args = ['format'];  // Always use format command
    
    if (checkOnly) {
        args.push('--check');
    }
    
    if (config.showDiff) {
        args.push('--diff');
    }
    
    if (config.verbose) {
        args.push('--verbose');
    }
    
    if (config.configPath) {
        args.push('--config', config.configPath);
    }
    
    // Add extra args (like init)
    if (extraArgs.length > 0) {
        args.splice(0, 1); // Remove 'format'
        args.unshift(...extraArgs);
    }
    
    if (filePath) {
        args.push(filePath);
    }
    
    return {
        command: config.executablePath,
        args: args
    };
}

/**
 * Run bake command
 * @param {string} filePath
 * @param {boolean} checkOnly
 * @param {string[]} extraArgs
 * @returns {Promise<object>}
 */
function runBakeCommand(filePath, checkOnly = false, extraArgs = []) {
    return new Promise((resolve, reject) => {
        const { command, args } = buildBakeCommand(filePath, checkOnly, extraArgs);
        
        // Use Python module execution for better reliability
        const pythonCommand = `python -c "from bake.cli import main; main()" ${args.join(' ')}`;
        
        exec(pythonCommand, { 
            cwd: path.dirname(filePath || process.cwd()),
            timeout: 30000 
        }, (error, stdout, stderr) => {
            const result = {
                success: error === null || error.code === 0,
                stdout: stdout,
                stderr: stderr,
                exitCode: error ? error.code : 0,
                changed: error ? error.code === 1 : false
            };
            
            resolve(result);
        });
    });
}

/**
 * Format current active file
 */
async function formatCurrentFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showErrorMessage('No active editor found');
        return;
    }

    if (!isMakefileDocument(editor.document)) {
        vscode.window.showErrorMessage('Current file is not a Makefile');
        return;
    }

    // Save the document first
    if (editor.document.isDirty) {
        const saved = await editor.document.save();
        if (!saved) {
            vscode.window.showErrorMessage('Could not save file before formatting');
            return;
        }
    }

    const filePath = editor.document.fileName;
    
    try {
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: "Formatting Makefile...",
            cancellable: false
        }, async () => {
            const result = await runBakeCommand(filePath, false);
            
            if (result.success) {
                // Use workspace edit instead of file reload
                const formattedContent = await fs.promises.readFile(filePath, 'utf8');
                const edit = new vscode.WorkspaceEdit();
                const document = editor.document;
                const fullRange = new vscode.Range(
                    document.positionAt(0),
                    document.positionAt(document.getText().length)
                );
                edit.replace(document.uri, fullRange, formattedContent);
                
                const success = await vscode.workspace.applyEdit(edit);
                
                if (success) {
                    vscode.window.showInformationMessage('Makefile formatted successfully');
                } else {
                    vscode.window.showErrorMessage('Failed to apply formatting changes');
                }
                
                if (result.stdout && getBakeConfig().verbose) {
                    console.log('Bake output:', result.stdout);
                }
            } else {
                let errorMsg = result.stderr || result.stdout || 'Unknown error occurred';
                
                // Check for common errors and provide helpful suggestions
                if (errorMsg.includes('Configuration file not found')) {
                    const action = await vscode.window.showErrorMessage(
                        'mbake configuration not found',
                        'Initialize Config',
                        'Cancel'
                    );
                    if (action === 'Initialize Config') {
                        await initializeConfig();
                    }
                } else if (errorMsg.includes('command not found') || errorMsg.includes('No module named')) {
                    vscode.window.showErrorMessage(
                        'mbake not found. Please install it with: pip install mbake',
                        'Open Settings'
                    ).then(action => {
                        if (action === 'Open Settings') {
                            vscode.commands.executeCommand('workbench.action.openSettings', 'mbake.executablePath');
                        }
                    });
                } else {
                    vscode.window.showErrorMessage(`Bake formatting failed: ${errorMsg}`);
                }
                console.error('Bake error:', errorMsg);
            }
        });
    } catch (error) {
        vscode.window.showErrorMessage(`Error running bake: ${error.message}`);
        console.error('Extension error:', error);
    }
}

/**
 * Check current active file formatting
 */
async function checkCurrentFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showErrorMessage('No active editor found');
        return;
    }

    if (!isMakefileDocument(editor.document)) {
        vscode.window.showErrorMessage('Current file is not a Makefile');
        return;
    }

    // Save the document first
    if (editor.document.isDirty) {
        const saved = await editor.document.save();
        if (!saved) {
            vscode.window.showWarningMessage('File has unsaved changes - results may not be accurate');
        }
    }

    const filePath = editor.document.fileName;
    
    try {
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: "Checking Makefile formatting...",
            cancellable: false
        }, async () => {
            const result = await runBakeCommand(filePath, true);
            
            if (result.success && !result.changed) {
                vscode.window.showInformationMessage('✓ Makefile is properly formatted');
            } else if (result.changed) {
                const action = await vscode.window.showWarningMessage(
                    'Makefile needs formatting',
                    'Format Now',
                    'Show Diff'
                );
                if (action === 'Format Now') {
                    await formatCurrentFile();
                } else if (action === 'Show Diff') {
                    // Show diff in a new document
                    const diffResult = await runBakeCommand(filePath, false, ['format', '--diff']);
                    if (diffResult.stdout) {
                        const diffDoc = await vscode.workspace.openTextDocument({
                            content: diffResult.stdout,
                            language: 'diff'
                        });
                        await vscode.window.showTextDocument(diffDoc);
                    }
                }
            } else {
                const errorMsg = result.stderr || result.stdout || 'Unknown error occurred';
                vscode.window.showErrorMessage(`Bake check failed: ${errorMsg}`);
            }
            
            if (result.stdout && getBakeConfig().verbose) {
                console.log('Bake output:', result.stdout);
            }
        });
    } catch (error) {
        vscode.window.showErrorMessage(`Error running bake: ${error.message}`);
        console.error('Extension error:', error);
    }
}

/**
 * Format document and return edit operations
 * @param {vscode.TextDocument} document
 * @returns {Promise<vscode.TextEdit[]>}
 */
async function formatDocument(document) {
    if (!isMakefileDocument(document)) {
        return [];
    }

    // Save the document first if it's dirty
    if (document.isDirty) {
        const saved = await document.save();
        if (!saved) {
            return [];
        }
    }

    const filePath = document.fileName;
    
    try {
        const result = await runBakeCommand(filePath, false);
        
        if (result.success) {
            // Read the formatted file content
            const formattedContent = await fs.promises.readFile(filePath, 'utf8');
            const fullRange = new vscode.Range(
                document.positionAt(0),
                document.positionAt(document.getText().length)
            );
            
            // Only return edit if content actually changed
            if (formattedContent !== document.getText()) {
                return [vscode.TextEdit.replace(fullRange, formattedContent)];
            }
        } else {
            const errorMsg = result.stderr || result.stdout || 'Unknown error occurred';
            console.error('Bake formatting failed:', errorMsg);
        }
    } catch (error) {
        console.error('Error running bake:', error.message);
    }
    
    return [];
}

/**
 * Deactivate the extension
 */
function deactivate() {
    console.log('mbake Makefile Formatter extension is now deactivated');
}

module.exports = {
    activate,
    deactivate
}; 