#!/usr/bin/env node

/**
 * AETHER_01 — npm postinstall script
 *
 * Downloads the pre-built Windows x64 binary from GitHub Releases
 * and places it in the package's bin/ directory.
 */

const https = require("https");
const fs = require("fs");
const path = require("path");
const { createHash } = require("crypto");

const REPO = "foursecondfivefour/aether-mcp-server";
const VERSION = "v1.0.1";
const BINARY = "aether-mcp-server.exe";
const BIN_DIR = path.join(__dirname, "bin");
const BIN_PATH = path.join(BIN_DIR, BINARY);
const MIN_SIZE = 10240; // 10 KB — catch obviously failed downloads

// ── Helpers ────────────────────────────────────────────────────────────────

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    const request = https.get(url, (response) => {
      // Follow redirects (GitHub may redirect to S3/CDN)
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        file.close();
        fs.unlinkSync(dest);
        return download(response.headers.location, dest).then(resolve).catch(reject);
      }
      if (response.statusCode !== 200) {
        file.close();
        fs.unlinkSync(dest);
        return reject(new Error(`HTTP ${response.statusCode} for ${url}`));
      }
      response.pipe(file);
      file.on("finish", () => {
        file.close();
        resolve();
      });
    });
    request.on("error", (err) => {
      file.close();
      if (fs.existsSync(dest)) fs.unlinkSync(dest);
      reject(err);
    });
    request.setTimeout(300000, () => {
      request.destroy();
      reject(new Error("Download timed out after 300s"));
    });
  });
}

function verifyBinary(path) {
  const stats = fs.statSync(path);
  if (stats.size < MIN_SIZE) {
    throw new Error(`Downloaded file too small: ${stats.size} bytes (expected >= ${MIN_SIZE})`);
  }
  // Check MZ header (Windows PE executables start with 0x4D 0x5A)
  const fd = fs.openSync(path, "r");
  const buffer = Buffer.alloc(2);
  fs.readSync(fd, buffer, 0, 2, 0);
  fs.closeSync(fd);
  if (buffer[0] !== 0x4D || buffer[1] !== 0x5A) {
    throw new Error("Downloaded file is not a valid Windows executable (missing MZ header)");
  }
}

// ── Main ───────────────────────────────────────────────────────────────────

async function main() {
  // Check if binary already exists and is valid
  if (fs.existsSync(BIN_PATH)) {
    try {
      verifyBinary(BIN_PATH);
      console.log(`[aether-mcp-server] Binary already installed: ${BIN_PATH}`);
      return;
    } catch {
      console.log(`[aether-mcp-server] Existing binary invalid, re-downloading...`);
      fs.unlinkSync(BIN_PATH);
    }
  }

  // Ensure bin directory exists
  if (!fs.existsSync(BIN_DIR)) {
    fs.mkdirSync(BIN_DIR, { recursive: true });
  }

  // Determine platform
  if (process.platform !== "win32") {
    console.error(`[aether-mcp-server] This package is for Windows x64 only (detected: ${process.platform})`);
    console.error(`[aether-mcp-server] Install on Windows or use the PowerShell installer:`);
    console.error(`[aether-mcp-server]   irm https://raw.githubusercontent.com/${REPO}/main/install.ps1 | iex`);
    process.exit(1);
  }

  // Check architecture
  if (process.arch !== "x64") {
    console.error(`[aether-mcp-server] This package supports Windows x64 only (detected: ${process.arch})`);
    process.exit(1);
  }

  const url = `https://github.com/${REPO}/releases/download/${VERSION}/${BINARY}`;
  console.log(`[aether-mcp-server] Downloading ${VERSION} (Windows x64)...`);
  console.log(`[aether-mcp-server] ${url}`);

  try {
    await download(url, BIN_PATH);
    verifyBinary(BIN_PATH);
    console.log(`[aether-mcp-server] Installed: ${BIN_PATH} (${(fs.statSync(BIN_PATH).size / 1024 / 1024).toFixed(1)} MB)`);
  } catch (err) {
    // Clean up on failure
    if (fs.existsSync(BIN_PATH)) fs.unlinkSync(BIN_PATH);
    console.error(`[aether-mcp-server] Download failed: ${err.message}`);
    console.error(`[aether-mcp-server] Alternative: install via PowerShell:`);
    console.error(`[aether-mcp-server]   irm https://raw.githubusercontent.com/${REPO}/main/install.ps1 | iex`);
    process.exit(1);
  }
}

main();
