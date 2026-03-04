const fs = require('fs');
const path = require('path');

const rootDir = path.resolve(__dirname, '..');
const sourcePath = path.join(rootDir, 'package.cjs');
const outputPath = path.join(rootDir, 'package.json');

const pkg = require(sourcePath);

fs.writeFileSync(outputPath, `${JSON.stringify(pkg, null, 2)}\n`, 'utf8');
console.log(`Generated ${outputPath} from ${sourcePath}`);
