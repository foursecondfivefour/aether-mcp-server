//! GUI automation tool for AETHER_01 MCP server.
//!
//! 23 GUI automation actions using Win32 APIs: mouse control, keyboard input,
//! window management, screenshot capture, clipboard access, display config,
//! audio control, screen lock, and input locale.

#![allow(unsafe_code)]

use crate::audit;
use crate::error::{AetherError, ErrorContext};

use base64::Engine as _;
use serde_json::{json, Value};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::thread;
use std::time::Duration;

use windows::core::PCWSTR;
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::Media::Audio::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Shutdown::*;
use windows::Win32::UI::HiDpi::*;
use windows::Win32::UI::Input::KeyboardAndMouse::*;
use windows::Win32::UI::WindowsAndMessaging::*;

// ═══════════════════════════════════════════════════════════════════════════════
// Raw clipboard FFI (user32.dll)
// ═══════════════════════════════════════════════════════════════════════════════
#[link(name = "user32")]
extern "system" {
    fn OpenClipboard(hWndNewOwner: isize) -> i32;
    fn CloseClipboard() -> i32;
    fn EmptyClipboard() -> i32;
    fn GetClipboardData(uFormat: u32) -> isize;
    fn SetClipboardData(uFormat: u32, hMem: isize) -> isize;
}
const CF_UNICODETEXT: u32 = 13;

// ═══════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════
const TOOL: &str = "gui";

// ═══════════════════════════════════════════════════════════════════════════════
// Public entry point
// ═══════════════════════════════════════════════════════════════════════════════

/// Dispatch a GUI automation action by name.
///
/// # Errors
/// Returns `AetherError::InvalidParameter` for unknown actions or bad params.
/// Returns `AetherError::Win32Error` when a Windows API call fails.
/// Returns `AetherError::NotFound` when a requested window cannot be located.
#[must_use]
pub fn handle_gui_automation(action: &str, params: serde_json::Value) -> std::result::Result<String, AetherError> {
    let action_static: &'static str = Box::leak(action.to_string().into_boxed_str());
    let ctx = ErrorContext::new("gui_automation", action_static);
    match action {
        "mouse_move" => mouse_move(&ctx, &params),
        "mouse_click" => mouse_click(&ctx, &params),
        "mouse_scroll" => mouse_scroll(&ctx, &params),
        "mouse_position" => mouse_position(&ctx),
        "keyboard_type" => keyboard_type(&ctx, &params),
        "keyboard_press" => keyboard_press(&ctx, &params),
        "keyboard_state" => keyboard_state(),
        "find_window" => find_window(&ctx, &params),
        "list_windows" => list_windows(&ctx),
        "set_window_pos" => set_window_pos(&ctx, &params),
        "focus_window" => focus_window(&ctx, &params),
        "get_window_rect" => get_window_rect(&ctx, &params),
        "get_window_text" => get_window_text(&ctx, &params),
        "close_window" => close_window(&ctx, &params),
        "screenshot" => screenshot(&ctx, &params),
        "clipboard_read" => clipboard_read(&ctx),
        "clipboard_write" => clipboard_write(&ctx, &params),
        "display_info" => display_info(&ctx),
        "set_resolution" => set_resolution(&ctx, &params),
        "audio_volume" => audio_volume(&ctx, &params),
        "audio_mute" => audio_mute(&ctx, &params),
        "screen_lock" => screen_lock(&ctx),
        "input_locale" => input_locale(&ctx, &params),
        other => Err(AetherError::invalid_param(ctx.clone(), format!(
            "Unknown GUI action: {other}"
        ))),
    }
}

// ===========================================================================
// 1. mouse_move — move cursor (absolute or relative)
// ===========================================================================

fn mouse_move(ctx: &ErrorContext, params: &Value) -> std::result::Result<String, AetherError> {
    if let (Some(x), Some(y)) = (params["x"].as_i64(), params["y"].as_i64()) {
        unsafe { SetCursorPos(x as i32, y as i32) }
            .map_err(|e| AetherError::win32(ctx.clone(), "SetCursorPos", e))?;
        audit::log_success(TOOL, "mouse_move", &format!("absolute x={x} y={y}"));
        return Ok(json!({"success": true, "x": x, "y": y}).to_string());
    }

    if let (Some(dx), Some(dy)) = (params["dx"].as_i64(), params["dy"].as_i64()) {
        let mut pt = POINT::default();
        unsafe { GetCursorPos(&mut pt) }.map_err(|e| AetherError::win32(ctx.clone(), "GetCursorPos", e))?;
        let new_x = pt.x + dx as i32;
        let new_y = pt.y + dy as i32;
        unsafe { SetCursorPos(new_x, new_y) }
            .map_err(|e| AetherError::win32(ctx.clone(), "SetCursorPos", e))?;
        audit::log_success(
            TOOL,
            "mouse_move",
            &format!("relative dx={dx} dy={dy} -> x={new_x} y={new_y}"),
        );
        return Ok(json!({"success": true, "x": new_x, "y": new_y}).to_string());
    }

    audit::log_failure(TOOL, "mouse_move", "missing x/y or dx/dy");
    Err(AetherError::invalid_param(
        ctx.clone(),
        "mouse_move requires x/y (absolute) or dx/dy (relative)",
    ))
}

// ===========================================================================
// 2. mouse_click — click with SendInput
// ===========================================================================

fn mouse_click(ctx: &ErrorContext, params: &Value) -> std::result::Result<String, AetherError> {
    let button = params["button"].as_str().unwrap_or("left");
    let click_type = params["type"].as_str().unwrap_or("single");

    let (down_flag, up_flag, extra_data) = button_flags(ctx, button)?;

    match click_type {
        "down" => {
            send_mouse_input(ctx, 0, 0, extra_data, down_flag)?;
            audit::log_success(TOOL, "mouse_click", &format!("{button} down"));
        }
        "up" => {
            send_mouse_input(ctx, 0, 0, extra_data, up_flag)?;
            audit::log_success(TOOL, "mouse_click", &format!("{button} up"));
        }
        "single" => {
            send_mouse_input(ctx, 0, 0, extra_data, down_flag)?;
            thread::sleep(Duration::from_millis(10));
            send_mouse_input(ctx, 0, 0, extra_data, up_flag)?;
            audit::log_success(TOOL, "mouse_click", &format!("{button} single"));
        }
        "double" => {
            for _ in 0..2 {
                send_mouse_input(ctx, 0, 0, extra_data, down_flag)?;
                thread::sleep(Duration::from_millis(10));
                send_mouse_input(ctx, 0, 0, extra_data, up_flag)?;
                thread::sleep(Duration::from_millis(10));
            }
            audit::log_success(TOOL, "mouse_click", &format!("{button} double"));
        }
        other => {
            audit::log_failure(TOOL, "mouse_click", &format!("unknown type: {other}"));
            return Err(AetherError::invalid_param(ctx.clone(), format!(
                "Unknown click type: {other}"
            )));
        }
    }

    Ok(json!({"success": true, "button": button, "type": click_type}).to_string())
}

fn button_flags(ctx: &ErrorContext, button: &str) -> std::result::Result<(MOUSE_EVENT_FLAGS, MOUSE_EVENT_FLAGS, u32), AetherError> {
    match button {
        "left" => Ok((MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, 0)),
        "right" => Ok((MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, 0)),
        "middle" => Ok((MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, 0)),
        "x1" => Ok((MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, XBUTTON1 as u32)),
        "x2" => Ok((MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, XBUTTON2 as u32)),
        other => Err(AetherError::invalid_param(ctx.clone(), format!(
            "Unknown button: {other}"
        ))),
    }
}

fn send_mouse_input(
    ctx: &ErrorContext,
    dx: i32,
    dy: i32,
    mouse_data: u32,
    flags: MOUSE_EVENT_FLAGS,
) -> std::result::Result<(), AetherError> {
    let input = INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: mouse_data,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    };

    let sent = unsafe { SendInput(&[input], size_of::<INPUT>() as i32) };
    if sent == 0 {
        return Err(AetherError::win32(ctx.clone(), "SendInput", "mouse event"));
    }
    Ok(())
}

// ===========================================================================
// 3. mouse_scroll — scroll with SendInput (WHEEL_DELTA = 120 per click)
// ===========================================================================

fn mouse_scroll(ctx: &ErrorContext, params: &Value) -> std::result::Result<String, AetherError> {
    let direction = params["direction"].as_str().unwrap_or("vertical");
    let amount = params["amount"].as_u64().unwrap_or(1) as u32;
    let wheel_delta: i32 = if (amount as u64) <= u32::MAX as u64 / 120 {
        (amount * 120) as i32
    } else {
        120
    };

    let flag = match direction {
        "vertical" => MOUSEEVENTF_WHEEL,
        "horizontal" => MOUSEEVENTF_HWHEEL,
        other => {
            return Err(AetherError::invalid_param(ctx.clone(), format!(
                "Unknown scroll direction: {other}"
            )));
        }
    };

    let input = INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx: 0,
                dy: 0,
                mouseData: wheel_delta as u32,
                dwFlags: flag,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    };

    let sent = unsafe { SendInput(&[input], size_of::<INPUT>() as i32) };
    if sent == 0 {
        return Err(AetherError::win32(ctx.clone(), "SendInput", "scroll event"));
    }

    audit::log_success(TOOL, "mouse_scroll", &format!("{direction} clicks={amount}"));
    Ok(json!({"success": true, "direction": direction, "amount": amount}).to_string())
}

// ===========================================================================
// 4. mouse_position — get cursor position
// ===========================================================================

fn mouse_position(ctx: &ErrorContext) -> std::result::Result<String, AetherError> {
    let mut pt = POINT::default();
    unsafe { GetCursorPos(&mut pt) }.map_err(|e| AetherError::win32(ctx.clone(), "GetCursorPos", e))?;
    Ok(json!({"x": pt.x, "y": pt.y}).to_string())
}

// ===========================================================================
// 5. keyboard_type — type text using KEYEVENTF_UNICODE
// ===========================================================================

fn keyboard_type(ctx: &ErrorContext, params: &Value) -> std::result::Result<String, AetherError> {
    let text = params["text"]
        .as_str()
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "keyboard_type requires 'text' parameter"))?;

    for ch in text.chars() {
        let scan_code = ch as u16;

        // Key down (Unicode)
        let input_down = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(0),
                    wScan: scan_code,
                    dwFlags: KEYEVENTF_UNICODE,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };

        // Key up (Unicode)
        let input_up = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(0),
                    wScan: scan_code,
                    dwFlags: KEYEVENTF_UNICODE | KEYEVENTF_KEYUP,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };

        let sent =
            unsafe { SendInput(&[input_down, input_up], size_of::<INPUT>() as i32) };
        if sent < 2 {
            return Err(AetherError::win32(
                ctx.clone(),
                "SendInput",
                format!("failed for char '{ch}' (sent {sent} of 2)"),
            ));
        }
        thread::sleep(Duration::from_millis(1));
    }

    audit::log_success(TOOL, "keyboard_type", &format!("{} chars", text.chars().count()));
    Ok(json!({"success": true, "length": text.chars().count()}).to_string())
}

// ===========================================================================
// 6. keyboard_press — press key combo (down in order, up in reverse)
// ===========================================================================

fn keyboard_press(ctx: &ErrorContext, params: &Value) -> std::result::Result<String, AetherError> {
    let keys = params["keys"]
        .as_array()
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "keyboard_press requires 'keys' array"))?;

    if keys.is_empty() {
        return Err(AetherError::invalid_param(ctx.clone(), "keyboard_press: 'keys' array is empty"));
    }

    let vk_codes: Vec<VIRTUAL_KEY> = keys
        .iter()
        .map(|v| v.as_str().ok_or_else(|| AetherError::invalid_param(ctx.clone(), "key name must be a string"))
            .and_then(|n| vk_from_name(ctx, n)))
        .collect::<Result<Vec<_>, _>>()?;

    let n = vk_codes.len();

    // Press all keys down in order
    for (i, &vk) in vk_codes.iter().enumerate() {
        let input = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: vk,
                    wScan: 0,
                    dwFlags: KEYBD_EVENT_FLAGS(0), // KEYDOWN (absence of KEYUP)
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        let sent = unsafe { SendInput(&[input], size_of::<INPUT>() as i32) };
        if sent == 0 {
            return Err(AetherError::win32(
                ctx.clone(),
                "SendInput",
                format!("failed pressing key {i} (vk=0x{:X})", vk.0),
            ));
        }
    }

    // Release in reverse order
    for (i, &vk) in vk_codes.iter().rev().enumerate() {
        thread::sleep(Duration::from_millis(5));
        let input = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: vk,
                    wScan: 0,
                    dwFlags: KEYEVENTF_KEYUP,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        let sent = unsafe { SendInput(&[input], size_of::<INPUT>() as i32) };
        if sent == 0 {
            return Err(AetherError::win32(
                ctx.clone(),
                "SendInput",
                format!("failed releasing key {i} (vk=0x{:X})", vk.0),
            ));
        }
    }

    audit::log_success(TOOL, "keyboard_press", &format!("{n} keys"));
    Ok(json!({"success": true, "keys_pressed": n}).to_string())
}

// ===========================================================================
// 7. keyboard_state — get modifier key state
// ===========================================================================

fn keyboard_state() -> std::result::Result<String, AetherError> {
    let ctrl = (unsafe { GetAsyncKeyState(VK_CONTROL.0 as i32) } as u16) & 0x8000 != 0;
    let alt = (unsafe { GetAsyncKeyState(VK_MENU.0 as i32) } as u16) & 0x8000 != 0;
    let shift = (unsafe { GetAsyncKeyState(VK_SHIFT.0 as i32) } as u16) & 0x8000 != 0;
    let win = (unsafe { GetAsyncKeyState(VK_LWIN.0 as i32) } as u16) & 0x8000 != 0;

    Ok(json!({
        "ctrl": ctrl,
        "alt": alt,
        "shift": shift,
        "win": win
    })
    .to_string())
}

// ===========================================================================
// 8. find_window — exact match via FindWindowW, or partial via EnumWindows
// ===========================================================================

fn find_window(ctx: &ErrorContext, params: &Value) -> std::result::Result<String, AetherError> {
    let title_str = params["title"]
        .as_str()
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "find_window requires 'title' parameter"))?;
    let class_str = params["class"].as_str();

    // Try exact match first
    let title_wide: Vec<u16> = title_str.encode_utf16().chain(std::iter::once(0)).collect();
    let class_wide: Option<Vec<u16>> = class_str
        .map(|cs| cs.encode_utf16().chain(std::iter::once(0)).collect());

    let class_pcwstr = class_wide
        .as_ref()
        .map(|v| PCWSTR(v.as_ptr()))
        .unwrap_or(PCWSTR::null());
    let title_pcwstr = PCWSTR(title_wide.as_ptr());

    let hwnd = match unsafe { FindWindowW(class_pcwstr, title_pcwstr) } {
        Ok(h) if h.0 != std::ptr::null_mut() => h,
        _ => HWND(std::ptr::null_mut()),
    };

    if hwnd.0 != std::ptr::null_mut() {
        let detail = format!("exact match hwnd=0x{:X}", hwnd.0 as usize);
        audit::log_success(TOOL, "find_window", &detail);
        return Ok(json!({
            "found": true,
            "hwnd": format!("0x{:X}", hwnd.0 as usize),
            "match_type": "exact"
        })
        .to_string());
    }

    // Partial match via EnumWindows
    let search_lower = title_str.to_lowercase();
    let search_wide: Vec<u16> = search_lower.encode_utf16().collect();
    let mut state = PartialFindState {
        search: &search_wide,
        found_hwnd: HWND(std::ptr::null_mut()),
        found_title: Vec::new(),
    };

    unsafe {
        let _ = EnumWindows(
            Some(enum_find_window_callback),
            LPARAM(std::ptr::addr_of_mut!(state) as isize),
        );
    }

    if state.found_hwnd.0 != std::ptr::null_mut() {
        let detail = format!("partial match hwnd=0x{:X}", state.found_hwnd.0 as usize);
        audit::log_success(TOOL, "find_window", &detail);
        return Ok(json!({
            "found": true,
            "hwnd": format!("0x{:X}", state.found_hwnd.0 as usize),
            "match_type": "partial",
            "matched_title": String::from_utf16_lossy(&state.found_title)
        })
        .to_string());
    }

    audit::log_success(TOOL, "find_window", "not found");
    Ok(json!({"found": false}).to_string())
}

struct PartialFindState<'a> {
    search: &'a [u16],
    found_hwnd: HWND,
    found_title: Vec<u16>,
}

unsafe extern "system" fn enum_find_window_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let state: &mut PartialFindState = unsafe { &mut *(lparam.0 as *mut PartialFindState) };
    if state.found_hwnd.0 != std::ptr::null_mut() {
        return BOOL(0); // Already found, stop enumeration
    }

    let mut buf = [0u16; 512];
    let len = unsafe { GetWindowTextW(hwnd, &mut buf) };
    if len > 0 && state.search.len() <= len as usize {
        let title_lower: Vec<u16> = buf[..len as usize]
            .iter()
            .map(|&c| if c >= 65 && c <= 90 { c + 32 } else { c })
            .collect();
        if title_lower
            .windows(state.search.len())
            .any(|w| w == state.search)
        {
            state.found_hwnd = hwnd;
            state.found_title = buf[..len as usize].to_vec();
        }
    }

    BOOL(1) // Continue enumeration
}

// ===========================================================================
// 9. list_windows — list all top-level windows
// ===========================================================================

fn list_windows(ctx: &ErrorContext) -> std::result::Result<String, AetherError> {
    let mut entries: Vec<WindowEntry> = Vec::new();

    unsafe {
        let _ = EnumWindows(
            Some(enum_list_windows_callback),
            LPARAM(std::ptr::addr_of_mut!(entries) as isize),
        );
    }

    let _ = ctx; // ctx is available but no errors to construct in this path

    audit::log_success(TOOL, "list_windows", &format!("{} windows", entries.len()));

    let json_entries: Vec<Value> = entries
        .into_iter()
        .map(|e| {
            json!({
                "hwnd": format!("0x{:X}", e.hwnd),
                "title": e.title,
                "class": e.class,
                "pid": e.pid,
                "visible": e.visible
            })
        })
        .collect();

    Ok(json!({"windows": json_entries}).to_string())
}

struct WindowEntry {
    hwnd: usize,
    title: String,
    class: String,
    pid: u32,
    visible: bool,
}

unsafe extern "system" fn enum_list_windows_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let entries: &mut Vec<WindowEntry> = unsafe { &mut *(lparam.0 as *mut Vec<WindowEntry>) };

    let mut title_buf = [0u16; 512];
    let title_len = unsafe { GetWindowTextW(hwnd, &mut title_buf) };
    let title = if title_len > 0 {
        String::from_utf16_lossy(&title_buf[..title_len as usize])
    } else {
        String::new()
    };

    let mut class_buf = [0u16; 256];
    let class_len = unsafe { GetClassNameW(hwnd, &mut class_buf) };
    let class = if class_len > 0 {
        String::from_utf16_lossy(&class_buf[..class_len as usize])
    } else {
        String::new()
    };

    let mut pid: u32 = 0;
    unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };

    let visible = unsafe { IsWindowVisible(hwnd).as_bool() };

    entries.push(WindowEntry {
        hwnd: hwnd.0 as usize,
        title,
        class,
        pid,
        visible,
    });

    BOOL(1)
}

// ===========================================================================
// 10. set_window_pos — move/resize window
// ===========================================================================

fn set_window_pos(ctx: &ErrorContext, params: &Value) -> std::result::Result<String, AetherError> {
    let hwnd = parse_hwnd(ctx, params)?;

    let x = params["x"].as_i64().unwrap_or(0) as i32;
    let y = params["y"].as_i64().unwrap_or(0) as i32;
    let width = params["width"].as_i64().unwrap_or(0) as i32;
    let height = params["height"].as_i64().unwrap_or(0) as i32;

    let mut flags = SET_WINDOW_POS_FLAGS(0);
    if params["flags"]["no_activate"].as_bool().unwrap_or(false) {
        flags |= SWP_NOACTIVATE;
    }
    if params["flags"]["no_zorder"].as_bool().unwrap_or(false) {
        flags |= SWP_NOZORDER;
    }
    if params["flags"]["no_size"].as_bool().unwrap_or(false) {
        flags |= SWP_NOSIZE;
    }
    if params["flags"]["no_move"].as_bool().unwrap_or(false) {
        flags |= SWP_NOMOVE;
    }

    unsafe { SetWindowPos(hwnd, HWND(std::ptr::null_mut()), x, y, width, height, flags) }
        .map_err(|e| AetherError::win32(ctx.clone(), "SetWindowPos", e))?;

    audit::log_success(
        TOOL,
        "set_window_pos",
        &format!("hwnd=0x{:X} x={x} y={y} w={width} h={height}", hwnd.0 as usize),
    );
    Ok(json!({"success": true}).to_string())
}

// ===========================================================================
// 11. focus_window — bring window to foreground
// ===========================================================================

fn focus_window(ctx: &ErrorContext, params: &Value) -> std::result::Result<String, AetherError> {
    let hwnd = parse_hwnd(ctx, params)?;

    // Simulate ALT key to satisfy foreground window rules (allow taskbar activation lock bypass)
    let mut alt_input = INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VK_MENU,
                wScan: 0,
                dwFlags: KEYBD_EVENT_FLAGS(0),
                time: 0,
                dwExtraInfo: 0,
            },
        },
    };
    unsafe { SendInput(&[alt_input], size_of::<INPUT>() as i32) };
    thread::sleep(Duration::from_millis(10));
    alt_input.Anonymous.ki.dwFlags = KEYEVENTF_KEYUP;
    unsafe { SendInput(&[alt_input], size_of::<INPUT>() as i32) };

    if unsafe { SetForegroundWindow(hwnd) }.0 == 0 {
        return Err(AetherError::win32(ctx.clone(), "SetForegroundWindow", "failed"));
    }

    audit::log_success(TOOL, "focus_window", &format!("hwnd=0x{:X}", hwnd.0 as usize));
    Ok(json!({"success": true}).to_string())
}

// ===========================================================================
// 12. get_window_rect — get window position/size
// ===========================================================================

fn get_window_rect(ctx: &ErrorContext, params: &Value) -> std::result::Result<String, AetherError> {
    let hwnd = parse_hwnd(ctx, params)?;

    let mut rect = RECT::default();
    unsafe { GetWindowRect(hwnd, &mut rect) }.map_err(|e| AetherError::win32(ctx.clone(), "GetWindowRect", e))?;

    Ok(json!({
        "x": rect.left,
        "y": rect.top,
        "width": rect.right - rect.left,
        "height": rect.bottom - rect.top
    })
    .to_string())
}

// ===========================================================================
// 13. get_window_text — get window title
// ===========================================================================

fn get_window_text(ctx: &ErrorContext, params: &Value) -> std::result::Result<String, AetherError> {
    let hwnd = parse_hwnd(ctx, params)?;

    let mut buf = [0u16; 1024];
    let len = unsafe { GetWindowTextW(hwnd, &mut buf) };
    let title = String::from_utf16_lossy(&buf[..len as usize]);

    Ok(json!({"title": title}).to_string())
}

// ===========================================================================
// 14. close_window — close window (requires force: true)
// ===========================================================================

fn close_window(ctx: &ErrorContext, params: &Value) -> std::result::Result<String, AetherError> {
    let is_forced = params["force"].as_bool().unwrap_or(false);
    if !is_forced {
        audit::log_security(TOOL, "close_window", "force not set");
        return Err(AetherError::invalid_param(
            ctx.clone(),
            "close_window requires 'force': true",
        ));
    }

    let hwnd = parse_hwnd(ctx, params)?;
    audit::log_forced(TOOL, "close_window");

    unsafe { PostMessageW(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0)) }
        .map_err(|e| AetherError::win32(ctx.clone(), "PostMessageW", e))?;

    Ok(json!({"success": true}).to_string())
}

// ===========================================================================
// 15. screenshot — capture screen or window, save as BMP or base64
// ===========================================================================

fn screenshot(ctx: &ErrorContext, params: &Value) -> std::result::Result<String, AetherError> {
    let output_mode = params["output"].as_str().unwrap_or("base64");
    let region = &params["region"];

    let hwnd_param = params["hwnd"].as_str();
    let target_hwnd = if let Some(hwnd_hex) = hwnd_param {
        let raw = usize::from_str_radix(hwnd_hex.trim_start_matches("0x"), 16)
            .map_err(|_| AetherError::invalid_param(ctx.clone(), "Invalid HWND hex string"))?;
        Some(HWND(raw as *mut std::ffi::c_void))
    } else {
        None
    };

    let (capture_x, capture_y, capture_w, capture_h, screen_dc, window_dc, is_window) =
        if let Some(hwnd) = target_hwnd {
            let mut rect = RECT::default();
            unsafe { GetWindowRect(hwnd, &mut rect) }.map_err(|e| AetherError::win32(ctx.clone(), "GetWindowRect", e))?;
            let dc = unsafe { GetWindowDC(hwnd) };
            if dc.0 == std::ptr::null_mut() {
                return Err(AetherError::win32(ctx.clone(), "GetWindowDC", "failed"));
            }
            (
                rect.left,
                rect.top,
                rect.right - rect.left,
                rect.bottom - rect.top,
                dc,
                dc,
                true,
            )
        } else if let (Some(x), Some(y), Some(w), Some(h)) = (
            region["x"].as_i64(),
            region["y"].as_i64(),
            region["w"].as_i64(),
            region["h"].as_i64(),
        ) {
            let dc = unsafe { GetDC(HWND(std::ptr::null_mut())) };
            if dc.0 == std::ptr::null_mut() {
                return Err(AetherError::win32(ctx.clone(), "GetDC", "failed"));
            }
            (x as i32, y as i32, w as i32, h as i32, dc, dc, false)
        } else {
            // Full screen
            let screen_w = unsafe { GetSystemMetrics(SM_CXSCREEN) };
            let screen_h = unsafe { GetSystemMetrics(SM_CYSCREEN) };
            let dc = unsafe { GetDC(HWND(std::ptr::null_mut())) };
            if dc.0 == std::ptr::null_mut() {
                return Err(AetherError::win32(ctx.clone(), "GetDC", "failed"));
            }
            (0, 0, screen_w, screen_h, dc, dc, false)
        };

    let result = capture_to_bmp(ctx, screen_dc, capture_x, capture_y, capture_w, capture_h);

    // Cleanup DCs
    if is_window {
        unsafe {
            let _ = ReleaseDC(target_hwnd.unwrap(), window_dc);
        }
    } else {
        unsafe {
            let _ = ReleaseDC(HWND(std::ptr::null_mut()), screen_dc);
        }
    }

    let bmp_bytes = result?;

    match output_mode {
        "base64" => {
            let b64 = base64::engine::general_purpose::STANDARD.encode(&bmp_bytes);
            audit::log_success(
                TOOL,
                "screenshot",
                &format!("base64 {capture_w}x{capture_h} ({} bytes)", bmp_bytes.len()),
            );
            Ok(json!({
                "format": "bmp",
                "encoding": "base64",
                "width": capture_w,
                "height": capture_h,
                "data": b64
            })
            .to_string())
        }
        file_path => {
            std::fs::write(file_path, &bmp_bytes)
                .map_err(|e| AetherError::win32(ctx.clone(), "std::fs::write", e))?;
            audit::log_success(
                TOOL,
                "screenshot",
                &format!("file {file_path} {capture_w}x{capture_h} ({} bytes)", bmp_bytes.len()),
            );
            Ok(json!({
                "format": "bmp",
                "path": file_path,
                "width": capture_w,
                "height": capture_h,
                "size_bytes": bmp_bytes.len()
            })
            .to_string())
        }
    }
}

fn capture_to_bmp(ctx: &ErrorContext, dc: HDC, x: i32, y: i32, w: i32, h: i32) -> std::result::Result<Vec<u8>, AetherError> {
    if w <= 0 || h <= 0 {
        return Err(AetherError::invalid_param(ctx.clone(), "Invalid capture dimensions"));
    }

    let mem_dc = unsafe { CreateCompatibleDC(dc) };
    if mem_dc.0 == std::ptr::null_mut() {
        return Err(AetherError::win32(ctx.clone(), "CreateCompatibleDC", "failed"));
    }

    let bitmap = unsafe { CreateCompatibleBitmap(dc, w, h) };
    if bitmap.0 == std::ptr::null_mut() {
        unsafe { let _ = DeleteDC(mem_dc); };
        return Err(AetherError::win32(ctx.clone(), "CreateCompatibleBitmap", "failed"));
    }

    let old_bitmap = unsafe { SelectObject(mem_dc, bitmap) };
    if old_bitmap.0 == std::ptr::null_mut() {
        unsafe {
            let _ = DeleteObject(bitmap);
            let _ = DeleteDC(mem_dc);
        }
        return Err(AetherError::win32(ctx.clone(), "SelectObject", "failed"));
    }

    let result = unsafe { BitBlt(mem_dc, 0, 0, w, h, dc, x, y, SRCCOPY) };
    if result.is_err() {
        unsafe {
            SelectObject(mem_dc, old_bitmap);
            let _ = DeleteObject(bitmap);
            let _ = DeleteDC(mem_dc);
        }
        return Err(AetherError::win32(ctx.clone(), "BitBlt", "failed"));
    }

    // Build BITMAPINFO for 32-bit BGRA
    let mut bi: BITMAPINFO = unsafe { zeroed() };
    bi.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as u32;
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = h; // positive = bottom-up
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB.0;

    let row_stride = (((w * 32 + 31) / 32) * 4) as usize;
    let pixel_data_size = row_stride * h as usize;
    let mut pixels: Vec<u8> = vec![0u8; pixel_data_size];

    let rows_copied = unsafe {
        GetDIBits(
            mem_dc,
            bitmap,
            0,
            h as u32,
            Some(pixels.as_mut_ptr() as *mut std::ffi::c_void),
            &mut bi,
            DIB_RGB_COLORS,
        )
    };

    // Cleanup GDI objects
    unsafe {
        SelectObject(mem_dc, old_bitmap);
        let _ = DeleteObject(bitmap);
        let _ = DeleteDC(mem_dc);
    }

    if rows_copied == 0 || rows_copied == i32::MAX {
        return Err(AetherError::win32(ctx.clone(), "GetDIBits", "failed"));
    }

    // Build BMP file in memory
    let bmp_header_size = 14usize;
    let info_header_size = size_of::<BITMAPINFOHEADER>();
    let total_size = bmp_header_size + info_header_size + pixel_data_size;

    let mut bmp: Vec<u8> = Vec::with_capacity(total_size);

    // BITMAPFILEHEADER
    bmp.extend_from_slice(b"BM"); // bfType
    bmp.extend_from_slice(&(total_size as u32).to_le_bytes()); // bfSize
    bmp.extend_from_slice(&0u16.to_le_bytes()); // bfReserved1
    bmp.extend_from_slice(&0u16.to_le_bytes()); // bfReserved2
    bmp.extend_from_slice(&((bmp_header_size + info_header_size) as u32).to_le_bytes()); // bfOffBits

    // BITMAPINFOHEADER
    bmp.extend_from_slice(&(info_header_size as u32).to_le_bytes()); // biSize
    bmp.extend_from_slice(&(w as i32).to_le_bytes()); // biWidth
    bmp.extend_from_slice(&(h as i32).to_le_bytes()); // biHeight
    bmp.extend_from_slice(&1u16.to_le_bytes()); // biPlanes
    bmp.extend_from_slice(&32u16.to_le_bytes()); // biBitCount
    bmp.extend_from_slice(&BI_RGB.0.to_le_bytes()); // biCompression
    bmp.extend_from_slice(&(pixel_data_size as u32).to_le_bytes()); // biSizeImage
    bmp.extend_from_slice(&0i32.to_le_bytes()); // biXPelsPerMeter
    bmp.extend_from_slice(&0i32.to_le_bytes()); // biYPelsPerMeter
    bmp.extend_from_slice(&0u32.to_le_bytes()); // biClrUsed
    bmp.extend_from_slice(&0u32.to_le_bytes()); // biClrImportant

    // Pixel data
    bmp.extend_from_slice(&pixels);

    Ok(bmp)
}

// ===========================================================================
// 16. clipboard_read — read clipboard text (CF_UNICODETEXT)
// ===========================================================================

fn clipboard_read(ctx: &ErrorContext) -> std::result::Result<String, AetherError> {
    if unsafe { OpenClipboard(0) } == 0 {
        return Err(AetherError::win32(ctx.clone(), "OpenClipboard", "failed"));
    }

    let result = (|| -> Result<String, AetherError> {
        let handle = unsafe { GetClipboardData(CF_UNICODETEXT) };
        if handle == 0 {
            return Err(AetherError::win32(ctx.clone(), "GetClipboardData", "no Unicode text"));
        }

        let ptr = unsafe { GlobalLock(HGLOBAL(handle as *mut c_void)) };
        if ptr.is_null() {
            return Err(AetherError::win32(ctx.clone(), "GlobalLock", "clipboard data"));
        }

        let text = unsafe {
            let len = (0..).take_while(|&i| *((ptr as *const u16).add(i)) != 0).count();
            let slice = std::slice::from_raw_parts(ptr as *const u16, len);
            String::from_utf16_lossy(slice)
        };

        unsafe { let _ = GlobalUnlock(HGLOBAL(handle as *mut c_void)); };

        Ok(text)
    })();

    let close_result = unsafe { CloseClipboard() };
    if close_result == 0 {
        return Err(AetherError::win32(ctx.clone(), "CloseClipboard", "failed"));
    }

    match &result {
        Ok(text) => {
            let preview: String = text.chars().take(80).collect();
            audit::log_success(TOOL, "clipboard_read", &preview);
        }
        Err(e) => {
            audit::log_failure(TOOL, "clipboard_read", &e.to_string());
        }
    }

    result.map(|text| json!({"text": text}).to_string())
}

// ===========================================================================
// 17. clipboard_write — write text to clipboard (CF_UNICODETEXT)
// ===========================================================================

fn clipboard_write(ctx: &ErrorContext, params: &Value) -> std::result::Result<String, AetherError> {
    let text = params["text"]
        .as_str()
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "clipboard_write requires 'text' parameter"))?;

    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let byte_count = wide.len() * 2;

    if unsafe { OpenClipboard(0) } == 0 {
        return Err(AetherError::win32(ctx.clone(), "OpenClipboard", "failed"));
    }

    let result = (|| -> Result<(), AetherError> {
        let hglobal = unsafe { GlobalAlloc(GMEM_MOVEABLE, byte_count) }
            .map_err(|e| AetherError::win32(ctx.clone(), "GlobalAlloc", e))?;
        if hglobal.0 == std::ptr::null_mut() {
            return Err(AetherError::win32(ctx.clone(), "GlobalAlloc", "clipboard write"));
        }

        let ptr = unsafe { GlobalLock(hglobal) };
        if ptr.is_null() {
            unsafe { let _ = GlobalFree(hglobal); };
            return Err(AetherError::win32(ctx.clone(), "GlobalLock", "clipboard write"));
        }

        unsafe {
            std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr as *mut u16, wide.len());
        }

        unsafe { let _ = GlobalUnlock(hglobal); };

        if unsafe { EmptyClipboard() } == 0 {
            unsafe { let _ = GlobalFree(hglobal); };
            return Err(AetherError::win32(ctx.clone(), "EmptyClipboard", "failed"));
        }

        let set_handle = unsafe { SetClipboardData(CF_UNICODETEXT, hglobal.0 as isize) };
        if set_handle == 0 {
            unsafe { let _ = GlobalFree(hglobal); };
            return Err(AetherError::win32(ctx.clone(), "SetClipboardData", "failed"));
        }
        // On success, clipboard owns the memory — do NOT free hglobal

        Ok(())
    })();

    let close_result = unsafe { CloseClipboard() };

    result?;
    if close_result == 0 {
        return Err(AetherError::win32(ctx.clone(), "CloseClipboard", "failed"));
    }

    let preview: String = text.chars().take(80).collect();
    audit::log_success(TOOL, "clipboard_write", &preview);
    Ok(json!({"success": true, "bytes": byte_count as u64}).to_string())
}

// ===========================================================================
// 18. display_info — get monitor information
// ===========================================================================

fn display_info(ctx: &ErrorContext) -> std::result::Result<String, AetherError> {
    let mut devmode: DEVMODEW = unsafe { zeroed() };
    devmode.dmSize = size_of::<DEVMODEW>() as u16;

    let result = unsafe {
        EnumDisplaySettingsW(
            PCWSTR::null(),
            ENUM_CURRENT_SETTINGS,
            &mut devmode,
        )
    };

    if result == BOOL(0) {
        return Err(AetherError::win32(ctx.clone(), "EnumDisplaySettingsW", "failed"));
    }

    let dpi = unsafe { GetDpiForSystem() };

    Ok(json!({
        "width": devmode.dmPelsWidth,
        "height": devmode.dmPelsHeight,
        "refresh_rate": devmode.dmDisplayFrequency,
        "bits_per_pixel": devmode.dmBitsPerPel,
        "dpi": dpi
    })
    .to_string())
}

// ===========================================================================
// 19. set_resolution — change display resolution (requires force: true)
// ===========================================================================

fn set_resolution(ctx: &ErrorContext, params: &Value) -> std::result::Result<String, AetherError> {
    let is_forced = params["force"].as_bool().unwrap_or(false);
    if !is_forced {
        audit::log_security(TOOL, "set_resolution", "force not set");
        return Err(AetherError::invalid_param(
            ctx.clone(),
            "set_resolution requires 'force': true",
        ));
    }

    let width = params["width"]
        .as_u64()
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "set_resolution requires 'width'"))?
        as u32;
    let height = params["height"]
        .as_u64()
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "set_resolution requires 'height'"))?
        as u32;
    let refresh = params["refresh_rate"].as_u64().unwrap_or(60) as u32;

    audit::log_forced(TOOL, "set_resolution");

    let mut devmode: DEVMODEW = unsafe { zeroed() };
    devmode.dmSize = size_of::<DEVMODEW>() as u16;
    devmode.dmPelsWidth = width;
    devmode.dmPelsHeight = height;
    devmode.dmDisplayFrequency = refresh;
    devmode.dmFields = DM_PELSWIDTH | DM_PELSHEIGHT | DM_DISPLAYFREQUENCY;

    let result = unsafe { ChangeDisplaySettingsW(Some(&devmode as *const DEVMODEW), CDS_UPDATEREGISTRY) };
    if result != DISP_CHANGE_SUCCESSFUL {
        let msg = format!("ChangeDisplaySettingsW failed: {:?}", result);
        audit::log_failure(TOOL, "set_resolution", &msg);
        return Err(AetherError::win32(ctx.clone(), "ChangeDisplaySettingsW", msg));
    }

    audit::log_success(
        TOOL,
        "set_resolution",
        &format!("{width}x{height}@{refresh}Hz"),
    );
    Ok(json!({"success": true, "width": width, "height": height, "refresh_rate": refresh})
        .to_string())
}

// ===========================================================================
// 20. audio_volume — get/set system volume (0-100 mapped to 0x0000-0xFFFF)
// ===========================================================================

fn audio_volume(ctx: &ErrorContext, params: &Value) -> std::result::Result<String, AetherError> {
    if let Some(level) = params["level"].as_u64() {
        // Set volume
        let clamped = level.min(100);
        let value = ((clamped as f64 / 100.0) * 0xFFFF as f64) as u32;
        let combined = value | (value << 16); // Both channels

        let result = unsafe { waveOutSetVolume(HWAVEOUT(usize::MAX as *mut std::ffi::c_void), combined) };
        if result != 0u32 {
            return Err(AetherError::win32(ctx.clone(), "waveOutSetVolume", format!("{:?}", result)));
        }
        audit::log_success(TOOL, "audio_volume", &format!("set to {clamped}%"));
        return Ok(json!({"success": true, "level": clamped}).to_string());
    }

    // Get volume
    let mut vol: u32 = 0;
    let result = unsafe { waveOutGetVolume(HWAVEOUT(usize::MAX as *mut std::ffi::c_void), &mut vol) };
    if result != 0u32 {
        return Err(AetherError::win32(ctx.clone(), "waveOutGetVolume", format!("{:?}", result)));
    }

    // Low word = left channel
    let left = ((vol & 0xFFFF) as f64 / 0xFFFF as f64 * 100.0) as u32;
    let right = (((vol >> 16) & 0xFFFF) as f64 / 0xFFFF as f64 * 100.0) as u32;

    Ok(json!({"left": left, "right": right}).to_string())
}

// ===========================================================================
// 21. audio_mute — get/set mute (volume == 0 = muted)
// ===========================================================================

fn audio_mute(ctx: &ErrorContext, params: &Value) -> std::result::Result<String, AetherError> {
    if let Some(_) = params.get("mute") {
        let do_mute = params["mute"].as_bool().unwrap_or(false);

        if do_mute {
            let result = unsafe { waveOutSetVolume(HWAVEOUT(usize::MAX as *mut std::ffi::c_void), 0) };
            if result != 0u32 {
                return Err(AetherError::win32(ctx.clone(), "waveOutSetVolume", format!("mute: {:?}", result)));
            }
            audit::log_success(TOOL, "audio_mute", "muted");
        } else {
            // Unmute: restore to 100% (no way to know previous volume with waveOut API)
            let value = 0xFFFFu32;
            let combined = value | (value << 16);
            let result = unsafe { waveOutSetVolume(HWAVEOUT(usize::MAX as *mut std::ffi::c_void), combined) };
            if result != 0u32 {
                return Err(AetherError::win32(ctx.clone(), "waveOutSetVolume", format!("unmute: {:?}", result)));
            }
            audit::log_success(TOOL, "audio_mute", "unmuted (restored 100%)");
        }

        return Ok(json!({"muted": do_mute}).to_string());
    }

    // Get mute state
    let mut vol: u32 = 0;
    let result = unsafe { waveOutGetVolume(HWAVEOUT(usize::MAX as *mut std::ffi::c_void), &mut vol) };
    if result != 0u32 {
        return Err(AetherError::win32(ctx.clone(), "waveOutGetVolume", format!("mute check: {:?}", result)));
    }

    let muted = vol == 0 || ((vol & 0xFFFF) == 0 && ((vol >> 16) & 0xFFFF) == 0);
    Ok(json!({"muted": muted}).to_string())
}

// ===========================================================================
// 22. screen_lock — lock workstation
// ===========================================================================

fn screen_lock(ctx: &ErrorContext) -> std::result::Result<String, AetherError> {
    audit::log_security(TOOL, "screen_lock", "locking workstation");
    unsafe { LockWorkStation() }.map_err(|e| AetherError::win32(ctx.clone(), "LockWorkStation", e))?;
    Ok(json!({"success": true}).to_string())
}

// ===========================================================================
// 23. input_locale — get/set keyboard layout
// ===========================================================================

fn input_locale(ctx: &ErrorContext, params: &Value) -> std::result::Result<String, AetherError> {
    if let Some(locale) = params["locale_id"].as_str() {
        // Set layout
        let locale_wide: Vec<u16> = locale
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let _hkl = unsafe { LoadKeyboardLayoutW(PCWSTR(locale_wide.as_ptr()), KLF_ACTIVATE) }
            .map_err(|e| AetherError::win32(
                ctx.clone(),
                "LoadKeyboardLayoutW",
                format!("locale: {locale}: {e}"),
            ))?;

        audit::log_success(TOOL, "input_locale", &format!("set to {locale}"));
        return Ok(json!({"success": true, "locale_id": locale}).to_string());
    }

    // Get layout
    let hkl = unsafe { GetKeyboardLayout(0) };
    let locale_hex = format!("{:08X}", hkl.0 as u32);

    Ok(json!({"locale_id": locale_hex}).to_string())
}

// ===========================================================================
// Helpers
// ===========================================================================

/// Parse a HWND from params. Accepts `hwnd` as hex string (optionally prefixed
/// with "0x") or as a decimal string.
fn parse_hwnd(ctx: &ErrorContext, params: &Value) -> std::result::Result<HWND, AetherError> {
    let raw = params["hwnd"]
        .as_str()
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "Missing 'hwnd' parameter"))?;

    let hwnd_val = if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        usize::from_str_radix(hex, 16)
            .map_err(|_| AetherError::invalid_param(ctx.clone(), "Invalid HWND hex string"))?
    } else {
        raw.parse::<usize>()
            .map_err(|_| AetherError::invalid_param(ctx.clone(), "Invalid HWND value"))?
    };

    let hwnd = HWND(hwnd_val as *mut std::ffi::c_void);

    // Validate that the handle looks like a real window
    if unsafe { IsWindow(hwnd) }.0 == 0 {
        return Err(AetherError::not_found(ctx.clone(), format!(
            "Window handle 0x{hwnd_val:X} is not a valid window"
        ), None));
    }

    Ok(hwnd)
}

/// Map a key name string to a `VIRTUAL_KEY` code.
///
/// Supports: CTRL, ALT, SHIFT, WIN, ENTER, TAB, ESC, SPACE, DELETE,
/// BACKSPACE, F1–F12, and single letters A–Z.
fn vk_from_name(ctx: &ErrorContext, name: &str) -> std::result::Result<VIRTUAL_KEY, AetherError> {
    match name.to_uppercase().as_str() {
        "CTRL" | "CONTROL" => Ok(VK_CONTROL),
        "ALT" | "MENU" => Ok(VK_MENU),
        "SHIFT" => Ok(VK_SHIFT),
        "WIN" | "LWIN" => Ok(VK_LWIN),
        "RWIN" => Ok(VK_RWIN),
        "ENTER" | "RETURN" => Ok(VK_RETURN),
        "TAB" => Ok(VK_TAB),
        "ESC" | "ESCAPE" => Ok(VK_ESCAPE),
        "SPACE" => Ok(VK_SPACE),
        "DELETE" | "DEL" => Ok(VK_DELETE),
        "BACKSPACE" | "BACK" => Ok(VK_BACK),
        "LEFT" => Ok(VK_LEFT),
        "RIGHT" => Ok(VK_RIGHT),
        "UP" => Ok(VK_UP),
        "DOWN" => Ok(VK_DOWN),
        "HOME" => Ok(VK_HOME),
        "END" => Ok(VK_END),
        "PAGEUP" | "PGUP" => Ok(VK_PRIOR),
        "PAGEDOWN" | "PGDN" => Ok(VK_NEXT),
        "INSERT" | "INS" => Ok(VK_INSERT),
        "PRINTSCREEN" | "PRTSC" => Ok(VK_SNAPSHOT),
        "PAUSE" => Ok(VK_PAUSE),
        "CAPSLOCK" => Ok(VK_CAPITAL),
        "NUMLOCK" => Ok(VK_NUMLOCK),
        "SCROLLLOCK" => Ok(VK_SCROLL),
        "LWINDOWS" => Ok(VK_LWIN),
        "RWINDOWS" => Ok(VK_RWIN),
        "APPS" | "MENUKEY" => Ok(VK_APPS),
        "F1" => Ok(VK_F1),
        "F2" => Ok(VK_F2),
        "F3" => Ok(VK_F3),
        "F4" => Ok(VK_F4),
        "F5" => Ok(VK_F5),
        "F6" => Ok(VK_F6),
        "F7" => Ok(VK_F7),
        "F8" => Ok(VK_F8),
        "F9" => Ok(VK_F9),
        "F10" => Ok(VK_F10),
        "F11" => Ok(VK_F11),
        "F12" => Ok(VK_F12),
        single if single.len() == 1 => {
            let ch = single.chars().next().unwrap();
            if ch.is_ascii_uppercase() {
                // VK codes for A–Z match ASCII uppercase
                Ok(VIRTUAL_KEY(ch as u16))
            } else if ch.is_ascii_digit() {
                // VK codes for 0–9
                Ok(VIRTUAL_KEY(ch as u16))
            } else if ch.is_ascii_lowercase() {
                Ok(VIRTUAL_KEY(ch.to_ascii_uppercase() as u16))
            } else {
                Err(AetherError::invalid_param(ctx.clone(), format!(
                    "Unsupported key character: '{ch}'"
                )))
            }
        }
        other => Err(AetherError::invalid_param(ctx.clone(), format!(
            "Unknown key name: '{other}'"
        ))),
    }
}
