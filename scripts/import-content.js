const fs = require("fs");
const path = require("path");

// Content source: set via CONTENT_DIR env var, or default to external-content
// In CI: CONTENT_DIR=external-content/articles (after checkout from private repo)
// Locally: CONTENT_DIR=../articles (relative to site repo, pointing at planning repo)
const sourceDir = process.env.CONTENT_DIR || "external-content/articles";
const targetDir = path.join(process.cwd(), "src", "content");

function copyRecursive(src, dest) {
  if (!fs.existsSync(src)) {
    console.error(`ERROR: Source content directory not found: ${src}`);
    console.error("Set CONTENT_DIR to the path containing your articles.");
    console.error("Local dev: CONTENT_DIR=../articles npm run dev");
    process.exit(1);
  }

  // Clean target directory
  if (fs.existsSync(dest)) {
    fs.rmSync(dest, { recursive: true, force: true });
  }

  fs.mkdirSync(dest, { recursive: true });

  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);

    if (entry.isDirectory()) {
      copyRecursive(srcPath, destPath);
    } else if (entry.name.endsWith(".md")) {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

// Copy article directories
const articlesSource = path.resolve(sourceDir);
const articlesTarget = path.join(targetDir, "articles");

// Check if source has subdirectories (category folders) or is already the articles dir
const entries = fs.readdirSync(articlesSource, { withFileTypes: true });
const hasSubdirs = entries.some(
  (e) => e.isDirectory() && !e.name.startsWith(".")
);

if (hasSubdirs) {
  // Source has category subdirectories (linux/, network/, etc.)
  // Also check for pages/ directory
  for (const entry of entries) {
    if (entry.isDirectory() && !entry.name.startsWith(".")) {
      const srcPath = path.join(articlesSource, entry.name);
      if (entry.name === "pages") {
        copyRecursive(srcPath, path.join(targetDir, "pages"));
      } else {
        copyRecursive(srcPath, path.join(articlesTarget, entry.name));
      }
    }
  }
} else {
  copyRecursive(articlesSource, articlesTarget);
}

// Count imported files
let count = 0;
function countFiles(dir) {
  if (!fs.existsSync(dir)) return;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      countFiles(path.join(dir, entry.name));
    } else if (entry.name.endsWith(".md")) {
      count++;
    }
  }
}
countFiles(targetDir);

console.log(`Imported ${count} content files from ${articlesSource} to ${targetDir}`);
