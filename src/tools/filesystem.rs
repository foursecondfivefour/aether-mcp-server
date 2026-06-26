//! AETHER_01 — Filesystem MCP tool.
//!
//! Full-spectrum Windows filesystem operations: read/write/delete, copy/move,
//! directory listing (recursive with glob), stat, mkdir, ACL management via icacls,
//! symlinks/junctions, Alternate Data Streams (ADS), NTFS compression, EFS encryption,
//! volume enumeration, mount/unmount via NTFS mount points, and network share management.
#![allow(unsafe_code)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde_json::{json, Value};

use crate::audit;
use crate::command::{ParamType, SafeCommand};
use crate::error::{AetherError, ErrorContext};

// ---------------------------------------------------------------------------
// Windows API imports (windows crate 0.58)
// ---------------------------------------------------------------------------
use windows::core::HSTRING;
use windows::Win32::Storage::FileSystem::{
    DeleteVolumeMountPointW, GetDiskFreeSpaceExW, GetLogicalDrives, GetVolumeInformationW,
    SetVolumeMountPointW,
};

// ---------------------------------------------------------------------------
// Tool name constant used for audit logging
// ---------------------------------------------------------------------------
const TOOL: &str = "filesystem";

// ===========================================================================
// PUBLIC DISPATCH FUNCTION
// ===========================================================================

/// Dispatch filesystem actions by name.
///
/// Accepts an `action` string and a `params` JSON object, canonicalizes all
/// paths before operating, and returns a JSON string result or an `AetherError`.
#[must_use]
pub fn handle_file_system(action: &str, params: Value) -> std::result::Result<String, AetherError> {
    match action {
        "read" => fs_read(params),
        "write" => fs_write(params),
        "delete" => fs_delete(params),
        "copy" => fs_copy(params),
        "move" => fs_move(params),
        "list_dir" => fs_list_dir(params),
        "stat" => fs_stat(params),
        "mkdir" => fs_mkdir(params),
        "acl_get" => fs_acl_get(params),
        "acl_set" => fs_acl_set(params),
        "symlink" => fs_symlink(params),
        "ads_list" => fs_ads_list(params),
        "ads_read" => fs_ads_read(params),
        "ads_write" => fs_ads_write(params),
        "ads_delete" => fs_ads_delete(params),
        "compress" => fs_compress(params),
        "uncompress" => fs_uncompress(params),
        "encrypt" => fs_encrypt(params),
        "decrypt" => fs_decrypt(params),
        "volumes" => fs_volumes(),
        "mount" => fs_mount(params),
        "unmount" => fs_unmount(params),
        "shares" => fs_shares(params),
        _ => {
            let ctx = ErrorContext::new("file_system", "unknown");
            Err(AetherError::invalid_param(ctx, format!(
                "Unknown filesystem action: {action}"
            )))
        }
    }
}

// ===========================================================================
// 1. read
// ===========================================================================

fn fs_read(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("file_system", "read");
    let path_str = get_str(ctx.clone(), &params, "path")?;
    let path = canonicalize_path_required(ctx.clone(), &path_str)?;
    let content = fs::read_to_string(&path).map_err(|e| {
        AetherError::from(e)
    })?;
    audit::log_success(TOOL, "read", &format!("path={}", path.display()));
    Ok(content)
}

// ===========================================================================
// 2. write
// ===========================================================================

fn fs_write(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("file_system", "write");
    let path_str = get_str(ctx.clone(), &params, "path")?;
    let content = get_str(ctx.clone(), &params, "content")?;
    let path = canonicalize_path_for_write(ctx.clone(), &path_str)?;
    fs::write(&path, &content).map_err(AetherError::from)?;
    audit::log_success(TOOL, "write", &format!("path={}", path.display()));
    Ok(json!({ "ok": true, "path": path.to_string_lossy() }).to_string())
}

// ===========================================================================
// 3. delete — requires force: true
// ===========================================================================

fn fs_delete(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("file_system", "delete");
    let force = get_bool(ctx.clone(), &params, "force")?;
    if !force {
        return Err(AetherError::permission_denied(ctx,
            "delete requires `force: true` to confirm destructive operation",
        ));
    }
    let path_str = get_str(ctx.clone(), &params, "path")?;
    let path = canonicalize_path_required(ctx.clone(), &path_str)?;
    audit::log_forced(TOOL, "delete");

    if path.is_dir() {
        fs::remove_dir_all(&path).map_err(AetherError::from)?;
    } else {
        fs::remove_file(&path).map_err(AetherError::from)?;
    }
    audit::log_success(TOOL, "delete", &format!("path={}", path.display()));
    Ok(json!({ "ok": true, "deleted": path.to_string_lossy() }).to_string())
}

// ===========================================================================
// 4. copy / move
// ===========================================================================

fn fs_copy(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("file_system", "copy");
    let source_str = get_str(ctx.clone(), &params, "source")?;
    let dest_str = get_str(ctx.clone(), &params, "destination")?;
    let source = canonicalize_path_required(ctx.clone(), &source_str)?;
    let dest = canonicalize_path_for_write(ctx.clone(), &dest_str)?;

    if source.is_dir() {
        copy_dir_recursive(&source, &dest)?;
    } else {
        fs::copy(&source, &dest).map_err(AetherError::from)?;
    }
    audit::log_success(TOOL, "copy", &format!("{} -> {}", source.display(), dest.display()));
    Ok(json!({ "ok": true, "source": source.to_string_lossy(), "destination": dest.to_string_lossy() }).to_string())
}

fn fs_move(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("file_system", "move");
    let source_str = get_str(ctx.clone(), &params, "source")?;
    let dest_str = get_str(ctx.clone(), &params, "destination")?;
    let source = canonicalize_path_required(ctx.clone(), &source_str)?;
    let dest = canonicalize_path_for_write(ctx.clone(), &dest_str)?;
    fs::rename(&source, &dest).map_err(AetherError::from)?;
    audit::log_success(TOOL, "move", &format!("{} -> {}", source.display(), dest.display()));
    Ok(json!({ "ok": true, "source": source.to_string_lossy(), "destination": dest.to_string_lossy() }).to_string())
}

/// Recursively copy a directory and its contents.
fn copy_dir_recursive(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

// ===========================================================================
// 5. list_dir — recursive directory listing with optional glob mask
// ===========================================================================

fn fs_list_dir(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("file_system", "list_dir");
    let path_str = get_str(ctx.clone(), &params, "path")?;
    let mask = get_str_optional(&params, "mask");
    let path = canonicalize_path_required(ctx.clone(), &path_str)?;
    if !path.is_dir() {
        return Err(AetherError::invalid_param(ctx, format!(
            "Not a directory: {}",
            path.display()
        )));
    }
    let entries = list_dir_recursive(&path, mask.as_deref())?;
    let json_str = serde_json::to_string(&entries)?;
    audit::log_success(TOOL, "list_dir", &format!("path={} count={}", path.display(), entries.len()));
    Ok(json_str)
}

/// Recursively collect directory entries as JSON values, filtered by optional glob mask.
fn list_dir_recursive(root: &Path, mask: Option<&str>) -> io::Result<Vec<Value>> {
    let mut results: Vec<Value> = Vec::new();
    let mut dir_stack: Vec<PathBuf> = vec![root.to_path_buf()];

    while let Some(dir) = dir_stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let entry_path = entry.path();
            let is_dir = entry_path.is_dir();
            if is_dir {
                dir_stack.push(entry_path.clone());
            }
            if let Some(m) = mask {
                let fname = entry.file_name();
                let fname_str = fname.to_string_lossy();
                if !glob_match(m, &fname_str) {
                    continue;
                }
            }
            results.push(dir_entry_to_json(&entry));
        }
    }
    Ok(results)
}

/// Convert a `DirEntry` to a JSON object with name, path, is_dir, size, modified.
fn dir_entry_to_json(entry: &fs::DirEntry) -> Value {
    let name = entry.file_name().to_string_lossy().to_string();
    let path = entry.path().to_string_lossy().to_string();
    let metadata = entry.metadata().ok();
    let is_dir = metadata.as_ref().map(|m| m.is_dir()).unwrap_or(false);
    let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
    let modified = metadata
        .as_ref()
        .and_then(|m| m.modified().ok())
        .map(format_system_time)
        .unwrap_or_default();
    json!({
        "name": name,
        "path": path,
        "is_dir": is_dir,
        "size": size,
        "modified": modified,
    })
}

// ===========================================================================
// 6. stat — file attributes
// ===========================================================================

fn fs_stat(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("file_system", "stat");
    let path_str = get_str(ctx.clone(), &params, "path")?;
    let path = canonicalize_path_required(ctx.clone(), &path_str)?;
    let metadata = fs::metadata(&path).map_err(AetherError::from)?;

    let size = metadata.len();
    let is_dir = metadata.is_dir();
    let is_file = metadata.is_file();
    let readonly = metadata.permissions().readonly();
    let created = metadata
        .created()
        .ok()
        .map(format_system_time)
        .unwrap_or_default();
    let modified = metadata
        .modified()
        .ok()
        .map(format_system_time)
        .unwrap_or_default();
    let accessed = metadata
        .accessed()
        .ok()
        .map(format_system_time)
        .unwrap_or_default();

    let result = json!({
        "path": path.to_string_lossy(),
        "size": size,
        "is_dir": is_dir,
        "is_file": is_file,
        "readonly": readonly,
        "created": created,
        "modified": modified,
        "accessed": accessed,
    });
    audit::log_success(TOOL, "stat", &format!("path={}", path.display()));
    Ok(result.to_string())
}

// ===========================================================================
// 7. mkdir — create directory recursively
// ===========================================================================

fn fs_mkdir(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("file_system", "mkdir");
    let path_str = get_str(ctx.clone(), &params, "path")?;
    let path = canonicalize_path_for_write(ctx.clone(), &path_str)?;
    fs::create_dir_all(&path).map_err(AetherError::from)?;
    audit::log_success(TOOL, "mkdir", &format!("path={}", path.display()));
    Ok(json!({ "ok": true, "path": path.to_string_lossy() }).to_string())
}

// ===========================================================================
// 8. acl_get — get file permissions via icacls
// ===========================================================================

fn fs_acl_get(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("file_system", "acl_get");
    let path_str = get_str(ctx.clone(), &params, "path")?;
    let path = canonicalize_path_required(ctx.clone(), &path_str)?;
    let path_display = path.to_string_lossy().to_string();
    let output = SafeCommand::new("icacls", TOOL, "acl_get")
        .timeout(15)
        .arg(&path_display, ParamType::Path)?
        .output()?;
    let acl_map = parse_icacls_output(&output);
    audit::log_success(TOOL, "acl_get", &format!("path={}", path.display()));
    serde_json::to_string(&acl_map).map_err(AetherError::from)
}

/// Parse icacls output into a JSON map of `account_name -> permission_flags`.
///
/// Example icacls output:
/// ```text
/// C:\path NT AUTHORITY\SYSTEM:(I)(F)
///         BUILTIN\Administrators:(I)(F)
///         BUILTIN\Users:(I)(RX)
/// ```
fn parse_icacls_output(output: &str) -> Value {
    let mut map = serde_json::Map::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.contains("Successfully processed")
            || line.contains("Failed processing")
        {
            continue;
        }
        // Lines look like:  "C:\path   ACCOUNT:(PERM)(PERM)   ACCOUNT2:(PERM)"
        // Skip the first token (path) and parse remaining account:perm pairs
        let tokens: Vec<&str> = line.split_whitespace().collect();
        for token in tokens.iter().skip(1) {
            if let Some((account, perms)) = token.split_once(':') {
                map.insert(account.to_string(), json!(perms));
            }
        }
        // If only one token (maybe the first token IS the account:perm on a continuation line)
        if tokens.len() == 1 && !tokens.is_empty() {
            if let Some((account, perms)) = tokens[0].split_once(':') {
                map.insert(account.to_string(), json!(perms));
            }
        }
    }
    Value::Object(map)
}

// ===========================================================================
// 9. acl_set — set file permissions via icacls /grant
// ===========================================================================

fn fs_acl_set(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("file_system", "acl_set");
    let path_str = get_str(ctx.clone(), &params, "path")?;
    let user = get_str(ctx.clone(), &params, "user")?;
    let permissions = get_str(ctx.clone(), &params, "permissions")?;
    let path = canonicalize_path_required(ctx, &path_str)?;
    let grant = format!("{}:{}", user, permissions);
    let _ = SafeCommand::new("icacls", TOOL, "acl_set")
        .timeout(15)
        .arg(path.to_string_lossy().as_ref(), ParamType::Path)?
        .arg_unchecked("/grant")
        .arg(&grant, ParamType::SafeString)?
        .run()?;
    audit::log_success(TOOL, "acl_set", &format!("path={} user={user} perms={permissions}", path.display()));
    Ok(json!({ "ok": true, "path": path.to_string_lossy() }).to_string())
}

// ===========================================================================
// 10. symlink — create symbolic link, hard link, or junction
// ===========================================================================

fn fs_symlink(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("file_system", "symlink");
    let link_str = get_str(ctx.clone(), &params, "link_path")?;
    let target_str = get_str(ctx.clone(), &params, "target_path")?;
    let link_type = get_str_optional(&params, "link_type").unwrap_or_else(|| "symbolic".into());

    let link = canonicalize_path_for_write(ctx.clone(), &link_str)?;
    let target = PathBuf::from(&target_str); // target may be relative — keep as-is

    match link_type.as_str() {
        "symbolic" => {
            // Determine if target is file or directory
            let target_type = get_str_optional(&params, "target_type");
            let is_dir = match target_type.as_deref() {
                Some("dir") => true,
                Some("file") => false,
                _ => target.is_dir(),
            };
            if is_dir {
                std::os::windows::fs::symlink_dir(&target, &link)
                    .map_err(AetherError::from)?;
            } else {
                std::os::windows::fs::symlink_file(&target, &link)
                    .map_err(AetherError::from)?;
            }
        }
        "hard" => {
            fs::hard_link(&target, &link).map_err(AetherError::from)?;
        }
        "junction" => {
            // Junction requires mklink /J via cmd.exe (cmd built-in)
            SafeCommand::new("cmd", TOOL, "symlink_junction")
                .timeout(15)
                .arg_unchecked("/c")
                .arg_unchecked("mklink")
                .arg_unchecked("/J")
                .arg(&link.to_string_lossy(), ParamType::Path)?
                .arg(&target.to_string_lossy(), ParamType::Path)?
                .run()?;
        }
        other => {
            return Err(AetherError::invalid_param(ctx, format!(
                "Unknown link_type '{other}'. Use: symbolic, hard, junction"
            )));
        }
    }

    audit::log_success(
        TOOL,
        "symlink",
        &format!("link={} target={} type={link_type}", link.display(), target.display()),
    );
    Ok(json!({ "ok": true, "link": link.to_string_lossy(), "target": target.to_string_lossy(), "link_type": link_type }).to_string())
}

// ===========================================================================
// 11. ADS — Alternate Data Streams
// ===========================================================================

fn fs_ads_list(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("file_system", "ads_list");
    let path_str = get_str(ctx.clone(), &params, "path")?;
    let path = canonicalize_path_required(ctx, &path_str)?;
    let stdout = SafeCommand::new("cmd", TOOL, "ads_list")
        .timeout(15)
        .arg_unchecked("/c")
        .arg_unchecked("dir")
        .arg_unchecked("/R")
        .arg(&path.to_string_lossy(), ParamType::Path)?
        .output()?;
    let streams = parse_ads_list_output(&stdout);
    audit::log_success(TOOL, "ads_list", &format!("path={}", path.display()));
    serde_json::to_string(&streams).map_err(AetherError::from)
}

/// Parse `dir /R` output to extract ADS names and sizes.
///
/// Example output line: `            23 file.txt:stream1:$DATA`
fn parse_ads_list_output(output: &str) -> Value {
    let mut entries: Vec<Value> = Vec::new();
    for line in output.lines() {
        if !line.contains(":$DATA") {
            continue;
        }
        let line = line.trim();
        // Split into size and name parts
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let size_str = parts[0];
            let full_name = parts[1]; // "file.txt:stream1:$DATA"
            let size: u64 = size_str.parse().unwrap_or(0);
            // Extract stream name between the first ':' and ':$DATA'
            if let Some(stream_start) = full_name.find(':') {
                let stream_part = &full_name[stream_start + 1..];
                let stream_name = stream_part.strip_suffix(":$DATA").unwrap_or(stream_part);
                entries.push(json!({
                    "stream_name": stream_name,
                    "size": size,
                }));
            }
        }
    }
    json!(entries)
}

fn fs_ads_read(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("file_system", "ads_read");
    let base_path_str = get_str(ctx.clone(), &params, "path")?;
    let stream_name = get_str(ctx.clone(), &params, "stream_name")?;
    let base_path = canonicalize_path_required(ctx.clone(), &base_path_str)?;
    let ads_path = format!("{}:{}", base_path.display(), stream_name);
    // ADS paths don't canonicalize directly; try to read directly
    let content = fs::read_to_string(&ads_path).map_err(|e| {
        AetherError::NotFound(format!("ADS stream not found or unreadable: {ads_path}: {e}"))
    })?;
    audit::log_success(TOOL, "ads_read", &format!("path={ads_path}"));
    Ok(content)
}

fn fs_ads_write(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("file_system", "ads_write");
    let base_path_str = get_str(ctx.clone(), &params, "path")?;
    let stream_name = get_str(ctx.clone(), &params, "stream_name")?;
    let content = get_str(ctx.clone(), &params, "content")?;
    let base_path = canonicalize_path_required(ctx, &base_path_str)?;
    let ads_path = format!("{}:{}", base_path.display(), stream_name);
    fs::write(&ads_path, &content).map_err(AetherError::from)?;
    audit::log_success(TOOL, "ads_write", &format!("path={ads_path}"));
    Ok(json!({ "ok": true, "path": ads_path }).to_string())
}

fn fs_ads_delete(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("file_system", "ads_delete");
    let base_path_str = get_str(ctx.clone(), &params, "path")?;
    let stream_name = get_str(ctx.clone(), &params, "stream_name")?;
    let base_path = canonicalize_path_required(ctx, &base_path_str)?;
    let ads_path = format!("{}:{}", base_path.display(), stream_name);
    // Writing empty deletes the ADS on Windows
    fs::write(&ads_path, b"").map_err(AetherError::from)?;
    audit::log_success(TOOL, "ads_delete", &format!("path={ads_path}"));
    Ok(json!({ "ok": true, "deleted": ads_path }).to_string())
}

// ===========================================================================
// 12. compress / uncompress — NTFS compression via compact.exe
// ===========================================================================

fn fs_compress(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("file_system", "compress");
    let path_str = get_str(ctx.clone(), &params, "path")?;
    let path = canonicalize_path_required(ctx, &path_str)?;
    let stdout = SafeCommand::new("compact", TOOL, "compress")
        .timeout(30)
        .arg_unchecked("/C")
        .arg(&path.to_string_lossy(), ParamType::Path)?
        .output()
        .map(|s| s.trim().to_string())?;
    audit::log_success(TOOL, "compress", &format!("path={}", path.display()));
    Ok(json!({ "ok": true, "path": path.to_string_lossy(), "output": stdout }).to_string())
}

fn fs_uncompress(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("file_system", "uncompress");
    let path_str = get_str(ctx.clone(), &params, "path")?;
    let path = canonicalize_path_required(ctx, &path_str)?;
    let stdout = SafeCommand::new("compact", TOOL, "uncompress")
        .timeout(30)
        .arg_unchecked("/U")
        .arg(&path.to_string_lossy(), ParamType::Path)?
        .output()
        .map(|s| s.trim().to_string())?;
    audit::log_success(TOOL, "uncompress", &format!("path={}", path.display()));
    Ok(json!({ "ok": true, "path": path.to_string_lossy(), "output": stdout }).to_string())
}

// ===========================================================================
// 13. encrypt / decrypt — EFS encryption via cipher.exe
// ===========================================================================

fn fs_encrypt(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("file_system", "encrypt");
    let path_str = get_str(ctx.clone(), &params, "path")?;
    let path = canonicalize_path_required(ctx, &path_str)?;
    let stdout = SafeCommand::new("cipher", TOOL, "encrypt")
        .timeout(30)
        .arg_unchecked("/E")
        .arg(&path.to_string_lossy(), ParamType::Path)?
        .output()
        .map(|s| s.trim().to_string())?;
    audit::log_success(TOOL, "encrypt", &format!("path={}", path.display()));
    Ok(json!({ "ok": true, "path": path.to_string_lossy(), "output": stdout }).to_string())
}

fn fs_decrypt(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("file_system", "decrypt");
    let path_str = get_str(ctx.clone(), &params, "path")?;
    let path = canonicalize_path_required(ctx, &path_str)?;
    let stdout = SafeCommand::new("cipher", TOOL, "decrypt")
        .timeout(30)
        .arg_unchecked("/D")
        .arg(&path.to_string_lossy(), ParamType::Path)?
        .output()
        .map(|s| s.trim().to_string())?;
    audit::log_success(TOOL, "decrypt", &format!("path={}", path.display()));
    Ok(json!({ "ok": true, "path": path.to_string_lossy(), "output": stdout }).to_string())
}

// ===========================================================================
// 14. volumes — list logical drives with metadata
// ===========================================================================

fn fs_volumes() -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("file_system", "volumes");
    let drives_bitmask = unsafe { GetLogicalDrives() };
    if drives_bitmask == 0 {
        return Err(AetherError::win32(ctx, "GetLogicalDrives", "GetLogicalDrives returned 0"));
    }

    let mut volumes: Vec<Value> = Vec::new();
    for i in 0..26u32 {
        if (drives_bitmask >> i) & 1 == 0 {
            continue;
        }
        let drive_letter = (b'A' + i as u8) as char;
        let root = format!("{drive_letter}:\\");

        let (label, fs_type, serial) = get_volume_information(&root);
        let (total_bytes, free_bytes, available_bytes) = get_disk_free_space(&root);

        volumes.push(json!({
            "drive": format!("{drive_letter}:"),
            "root": root,
            "label": label,
            "fs_type": fs_type,
            "serial": serial,
            "total_bytes": total_bytes,
            "free_bytes": free_bytes,
            "available_bytes": available_bytes,
        }));
    }

    audit::log_success(TOOL, "volumes", &format!("count={}", volumes.len()));
    serde_json::to_string(&volumes).map_err(AetherError::from)
}

/// Query volume label, filesystem type, and serial number for a root path like `C:\`.
fn get_volume_information(root: &str) -> (String, String, u32) {
    let mut label_buf = [0u16; 256];
    let mut fs_buf = [0u16; 256];
    let mut serial: u32 = 0;
    let mut _max_component: u32 = 0;
    let mut _fs_flags: u32 = 0;

    let result = unsafe {
        GetVolumeInformationW(
            &HSTRING::from(root),
            Some(&mut label_buf),
            Some(&mut serial),
            Some(&mut _max_component),
            Some(&mut _fs_flags),
            Some(&mut fs_buf),
        )
    };

    if result.is_err() {
        return (String::new(), String::new(), 0);
    }

    let label = {
        let end = label_buf.iter().position(|&c| c == 0).unwrap_or(label_buf.len());
        String::from_utf16_lossy(&label_buf[..end])
    };

    let fs_type = {
        let end = fs_buf.iter().position(|&c| c == 0).unwrap_or(fs_buf.len());
        String::from_utf16_lossy(&fs_buf[..end])
    };

    (label, fs_type, serial)
}

/// Query total, free, and available-to-caller bytes for a root path like `C:\`.
fn get_disk_free_space(root: &str) -> (u64, u64, u64) {
    let mut available: u64 = 0;
    let mut total: u64 = 0;
    let mut free: u64 = 0;

    let result = unsafe {
        GetDiskFreeSpaceExW(
            &HSTRING::from(root),
            Some(&mut available),
            Some(&mut total),
            Some(&mut free),
        )
    };
    if result.is_ok() {
        (total, free, available)
    } else {
        (0, 0, 0)
    }
}

// ===========================================================================
// 15. mount / unmount — NTFS volume mount points
// ===========================================================================

fn fs_mount(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("file_system", "mount");
    let volume_guid = get_str(ctx.clone(), &params, "volume_guid")?;
    let mount_point_str = get_str(ctx.clone(), &params, "mount_point")?;

    let mount_path = PathBuf::from(&mount_point_str);
    // Mount point must be an existing empty directory
    if !mount_path.exists() {
        fs::create_dir_all(&mount_path).map_err(AetherError::from)?;
    }
    let mount_path_canon = canonicalize_path_required(ctx.clone(), &mount_point_str)?;

    let h_volume = HSTRING::from(volume_guid.as_str());
    let mount_str = mount_path_canon.to_string_lossy();
    // SetVolumeMountPointW requires a trailing backslash on the mount point
    let mount_with_slash = if mount_str.ends_with('\\') {
        mount_str.to_string()
    } else {
        format!("{mount_str}\\")
    };
    let h_mount = HSTRING::from(mount_with_slash.as_str());

    let result = unsafe { SetVolumeMountPointW(&h_mount, &h_volume) };
    if result.is_err() {
        return Err(AetherError::win32(ctx, "SetVolumeMountPointW", format!(
            "SetVolumeMountPointW failed for volume {volume_guid} at {mount_with_slash}"
        )));
    }
    audit::log_success(TOOL, "mount", &format!("volume={volume_guid} mount={mount_with_slash}"));
    Ok(json!({ "ok": true, "volume_guid": volume_guid, "mount_point": mount_with_slash }).to_string())
}

fn fs_unmount(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("file_system", "unmount");
    let mount_point_str = get_str(ctx.clone(), &params, "mount_point")?;
    let mount_path = canonicalize_path_required(ctx.clone(), &mount_point_str)?;
    let mount_str = mount_path.to_string_lossy();
    let mount_with_slash = if mount_str.ends_with('\\') {
        mount_str.to_string()
    } else {
        format!("{mount_str}\\")
    };
    let h_mount = HSTRING::from(mount_with_slash.as_str());

    let result = unsafe { DeleteVolumeMountPointW(&h_mount) };
    if result.is_err() {
        return Err(AetherError::win32(ctx, "DeleteVolumeMountPointW", format!(
            "DeleteVolumeMountPointW failed for {mount_with_slash}"
        )));
    }
    audit::log_success(TOOL, "unmount", &format!("mount={mount_with_slash}"));
    Ok(json!({ "ok": true, "mount_point": mount_with_slash }).to_string())
}

// ===========================================================================
// 16. shares — network shares (list, create, delete)
// ===========================================================================

fn fs_shares(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("file_system", "shares");
    let share_action = get_str_optional(&params, "share_action").unwrap_or_else(|| "list".into());

    match share_action.as_str() {
        "list" => shares_list(ctx.clone()),
        "create" => shares_create(ctx.clone(), params),
        "delete" => shares_delete(ctx.clone(), params),
        other => Err(AetherError::invalid_param(ctx, format!(
            "Unknown share_action '{other}'. Use: list, create, delete"
        ))),
    }
}

fn shares_list(_ctx: ErrorContext) -> std::result::Result<String, AetherError> {
    let stdout = SafeCommand::new("net", TOOL, "shares_list")
        .timeout(15)
        .arg_unchecked("share")
        .output()?;
    let shares = parse_net_share_output(&stdout);
    audit::log_success(TOOL, "shares", &format!("list count={}", shares.as_array().map_or(0, |a| a.len())));
    serde_json::to_string(&shares).map_err(AetherError::from)
}

/// Parse `net share` output into a JSON array of share objects.
///
/// Output format:
/// ```text
/// Share name   Resource                        Remark
/// -------------------------------------------------------------------------------
/// C$           C:\                             Default share
/// IPC$                                         Remote IPC
/// ADMIN$       C:\Windows                      Remote Admin
/// MyShare      D:\data
/// ```
fn parse_net_share_output(output: &str) -> Value {
    let mut shares: Vec<Value> = Vec::new();
    let mut in_body = false;

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Skip header and separator lines
        if !in_body {
            if line.contains("---") || line.starts_with("Share name") {
                in_body = true;
            }
            continue;
        }
        // Stop at footer
        if line.contains("The command completed") {
            break;
        }
        // Parse columns: Share name (fixed width), Resource, Remark
        // Column widths: name=15, resource=32, remark (rest)
        let name = line[..line.len().min(15)].trim().to_string();
        let rest = line[15..].trim();
        let (resource, remark) = if rest.len() > 32 {
            let res = rest[..32].trim();
            let rem = rest[32..].trim();
            (if res.is_empty() { None } else { Some(res.to_string()) }, if rem.is_empty() { None } else { Some(rem.to_string()) })
        } else {
            (if rest.is_empty() { None } else { Some(rest.to_string()) }, None)
        };
        if !name.is_empty() {
            shares.push(json!({
                "name": name,
                "resource": resource,
                "remark": remark,
            }));
        }
    }
    json!(shares)
}

fn shares_create(ctx: ErrorContext, params: Value) -> std::result::Result<String, AetherError> {
    let name = get_str(ctx.clone(), &params, "name")?;
    let share_path = get_str(ctx.clone(), &params, "share_path")?;
    let share_spec = format!("{name}={share_path}");
    let _ = SafeCommand::new("net", TOOL, "shares_create")
        .timeout(15)
        .arg_unchecked("share")
        .arg(&share_spec, ParamType::SafeString)?
        .run()?;
    audit::log_success(TOOL, "shares", &format!("create name={name} path={share_path}"));
    Ok(json!({ "ok": true, "name": name, "share_path": share_path }).to_string())
}

fn shares_delete(ctx: ErrorContext, params: Value) -> std::result::Result<String, AetherError> {
    let name = get_str(ctx.clone(), &params, "name")?;
    let _ = SafeCommand::new("net", TOOL, "shares_delete")
        .timeout(15)
        .arg_unchecked("share")
        .arg(&name, ParamType::Name)?
        .arg_unchecked("/delete")
        .run()?;
    audit::log_success(TOOL, "shares", &format!("delete name={name}"));
    Ok(json!({ "ok": true, "name": name }).to_string())
}

// ===========================================================================
// HELPERS — path canonicalization, param extraction, glob matching, time fmt
// ===========================================================================

/// Canonicalize a path that MUST exist (read, stat, acl_get, etc.).
fn canonicalize_path_required(ctx: ErrorContext, path_str: &str) -> std::result::Result<PathBuf, AetherError> {
    fs::canonicalize(path_str).map_err(|e| {
        AetherError::not_found(ctx, format!("Path not found or inaccessible: {path_str}: {e}"), None)
    })
}

/// Canonicalize a path for write/create operations. If the path doesn't exist
/// yet, canonicalizes the parent and appends the filename.
fn canonicalize_path_for_write(ctx: ErrorContext, path_str: &str) -> std::result::Result<PathBuf, AetherError> {
    let path = Path::new(path_str);
    match fs::canonicalize(path) {
        Ok(p) => Ok(p),
        Err(_) => {
            // Path doesn't exist — canonicalize parent
            if let Some(parent) = path.parent() {
                if parent.as_os_str().is_empty() {
                    let cwd =
                        std::env::current_dir().map_err(AetherError::from)?;
                    return Ok(cwd.join(path.file_name().unwrap_or_default()));
                }
                let parent_canon = fs::canonicalize(parent).map_err(|e| {
                    AetherError::not_found(ctx.clone(), format!("Parent directory not found: {parent:?}: {e}"), None)
                })?;
                Ok(parent_canon.join(path.file_name().unwrap_or_default()))
            } else {
                fs::canonicalize(path).map_err(|e| AetherError::not_found(ctx, format!(
                    "Path not found and has no parent: {path_str}: {e}"
                ), None))
            }
        }
    }
}

/// Extract a required string parameter from the JSON object.
fn get_str(ctx: ErrorContext, params: &Value, key: &str) -> std::result::Result<String, AetherError> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| AetherError::invalid_param(ctx, format!("Missing or invalid parameter: '{key}'")))
}

/// Extract an optional string parameter from the JSON object.
fn get_str_optional(params: &Value, key: &str) -> Option<String> {
    params.get(key).and_then(|v| v.as_str()).map(String::from)
}

/// Extract a required boolean parameter from the JSON object.
fn get_bool(ctx: ErrorContext, params: &Value, key: &str) -> std::result::Result<bool, AetherError> {
    params
        .get(key)
        .and_then(|v| v.as_bool())
        .ok_or_else(|| AetherError::invalid_param(ctx, format!("Missing or invalid boolean: '{key}'")))
}

/// Simple glob pattern matching supporting `*` (any sequence) and `?` (single char).
/// Matching is case-insensitive on Windows via ASCII lowercasing.
fn glob_match(pattern: &str, name: &str) -> bool {
    let p = pattern.as_bytes();
    let n = name.as_bytes();
    glob_match_impl(p, n, 0, 0)
}

fn glob_match_impl(p: &[u8], n: &[u8], pi: usize, ni: usize) -> bool {
    if pi == p.len() {
        return ni == n.len();
    }
    match p[pi] {
        b'*' => {
            // Match zero or more characters
            if glob_match_impl(p, n, pi + 1, ni) {
                return true;
            }
            for i in ni..n.len() {
                if glob_match_impl(p, n, pi + 1, i + 1) {
                    return true;
                }
            }
            false
        }
        b'?' => {
            if ni < n.len() {
                glob_match_impl(p, n, pi + 1, ni + 1)
            } else {
                false
            }
        }
        c => {
            if ni < n.len() && c.to_ascii_lowercase() == n[ni].to_ascii_lowercase() {
                glob_match_impl(p, n, pi + 1, ni + 1)
            } else {
                false
            }
        }
    }
}

/// Format a `SystemTime` as ISO 8601 UTC string via chrono.
fn format_system_time(t: SystemTime) -> String {
    let dt: chrono::DateTime<chrono::Utc> = t.into();
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
