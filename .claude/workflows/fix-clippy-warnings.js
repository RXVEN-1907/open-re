export const meta = {
  name: 'fix-clippy-warnings',
  description: 'Systematically discover and fix clippy warnings across the workspace',
  phases: [
    { title: 'Discover', detail: 'Run clippy to find all warnings' },
    { title: 'Fix', detail: 'Apply automatic fixes for actionable warnings' },
    { title: 'Verify', detail: 'Verify no new warnings introduced and build still works' }
  ]
};

phase('Discover');
const { execSync } = require('child_process');
const fs = require('fs');

// Run clippy to get current warnings
let output;
try {
  output = execSync('cargo clippy --all-targets --all-features --workspace --exclude openre-cli --exclude openre-tui -- -D warnings', {
    encoding: 'utf8',
    maxBuffer: 1024 * 1024
  });
} catch (error) {
  output = error.stdout || error.stderr || String(error);
}

log(`Clippy output captured (${output.length} chars)`);

// Parse warnings to find actionable ones
const warnings = [];
const lines = output.split('\n');
let currentWarning = {};

for (const line of lines) {
  // Match warning lines like: " --> src/file.rs:123:45"
  const locationMatch = line.match(/ --> (.+?):(\d+):(\d+)/);
  if (locationMatch) {
    if (currentWarning.file) {
      warnings.push(currentWarning);
    }
    currentWarning = {
      file: locationMatch[1],
      line: parseInt(locationMatch[2]),
      column: parseInt(locationMatch[3]),
      messages: []
    };
  } else if (line.trim().startsWith('=') && line.includes('help:')) {
    // Help lines
    if (currentWarning.messages.length > 0) {
      currentWarning.help = line.trim();
    }
  } else if (line.trim() && !line.startsWith('warning:') && !line.startsWith('error:')) {
    // Message lines
    currentWarning.messages.push(line.trim());
  }
}

if (currentWarning.file) {
  warnings.push(currentWarning);
}

log(`Found ${warnings.length} warnings to process`);

// Group by file for efficient processing
const warningsByFile = {};
for (const warning of warnings) {
  if (!warningsByFile[warning.file]) {
    warningsByFile[warning.file] = [];
  }
  warningsByFile[warning.file].push(warning);
}

phase('Fix');
// Process each file with warnings
for (const [filePath, fileWarnings] of Object.entries(warningsByFile)) {
  log(`Processing ${filePath} (${fileWarnings.length} warnings)`);

  // Read the file
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    log(`Failed to read ${filePath}: ${err.message}`);
    continue;
  }

  // Apply fixes based on warning types
  let modified = false;

  // Sort warnings by line descending to avoid offset issues
  const sortedWarnings = [...fileWarnings].sort((a, b) => b.line - a.line);

  for (const warning of sortedWarnings) {
    // Check for common fixable warnings
    const helpText = warning.help || '';

    if (helpText.includes('replace it with:') && helpText.includes('redundant_field_names')) {
      // Fix redundant field names: `field: field,` -> `field,`
      const lines = content.split('\n');
      const lineIndex = warning.line - 1;
      if (lineIndex >= 0 && lineIndex < lines.length) {
        const line = lines[lineIndex];
        const match = line.match(/^(\s*)(\w+):\s*\2\s*(.*)$/);
        if (match) {
          const indentation = match[1];
          const fieldName = match[2];
          const rest = match[3];
          lines[lineIndex] = `${indentation}${fieldName},${rest}`;
          content = lines.join('\n');
          modified = true;
          log(`  Fixed redundant field ${fieldName} at line ${warning.line}`);
        }
      }
    } else if (helpText.includes('unused-variables')) {
      // Fix unused variables by prefixing with underscore
      const lines = content.split('\n');
      const lineIndex = warning.line - 1;
      if (lineIndex >= 0 && lineIndex < lines.length) {
        const line = lines[lineIndex];
        // Match variable declarations like: `let variable_name = ...` or `variable_name: Type = ...`
        const match = line.match(/(\blet\s+|\b\w+\s+:)(\w+)(\s*[=:])/);
        if (match) {
          const prefix = match[1];
          const varName = match[2];
          const suffix = match[3];
          lines[lineIndex] = line.replace(varName, `_${varName}`);
          content = lines.join('\n');
          modified = true;
          log(`  Fixed unused variable ${varName} at line ${warning.line}`);
        }
      }
    } else if (helpText.includes('empty line after doc comment')) {
      // Remove empty line after doc comment
      const lines = content.split('\n');
      const lineIndex = warning.line - 1;
      if (lineIndex >= 0 && lineIndex < lines.length && lines[lineIndex].trim() === '') {
        // Check if previous line is a doc comment
        if (lineIndex > 0 && lines[lineIndex - 1].trim().startsWith('///')) {
          lines.splice(lineIndex, 1);
          content = lines.join('\n');
          modified = true;
          log(`  Removed empty line after doc comment at line ${warning.line}`);
        }
      }
    }
  }

  // Write back if modified
  if (modified) {
    try {
      fs.writeFileSync(filePath, content);
      log(`  Wrote changes to ${filePath}`);
    } catch (err) {
      log(`  Failed to write ${filePath}: ${err.message}`);
    }
  }
}

phase('Verify');
// Run clippy again to verify
try {
  output = execSync('cargo clippy --all-targets --all-features --workspace --exclude openre-cli --exclude openre-tui -- -D warnings', {
    encoding: 'utf8',
    maxBuffer: 1024 * 1024
  });

  const warningCount = (output.match(/warning:/g) || []).length;
  log(`After fixes: ${warningCount} warnings remaining`);

  if (warningCount === 0) {
    log('✅ All clippy warnings fixed!');
  } else {
    log(`⚠️  ${warningCount} warnings remain - may require manual fixes`);
  }

} catch (error) {
  log(`Error running clippy verification: ${error.message}`);
}

// Final build check
try {
  execSync('cargo check --workspace --all-targets', {
    encoding: 'utf8',
    maxBuffer: 1024 * 1024
  });
  log('✅ Workspace still builds successfully');
} catch (error) {
  log(`❌ Build error after fixes: ${error.message}`);
}