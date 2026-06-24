// Copyright (c) 2026 Daniel Markstedt <daniel@mindani.net>
//
// Licensed under the Apache License, Version 2.0 or the MIT license, at your
// option. See the project licensing terms for details.

//! C ABI for `stuffit`.
//!
//! All borrowed pointers returned by this library remain valid until their
//! owning archive is freed. Errors and their messages are thread-local.

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use stuffit::{ArchiveFormat, SitArchive, SitEntry, SitError};

const FORK_DATA: c_int = 0;
const FORK_RESOURCE: c_int = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StuffitErrorCode {
    Ok = 0,
    InvalidArgument = 1,
    Io = 2,
    Archive = 3,
    Unsupported = 4,
    Encrypted = 5,
    Panic = 6,
}

struct LastError {
    code: StuffitErrorCode,
    message: CString,
}

thread_local! {
    static LAST_ERROR: RefCell<LastError> = RefCell::new(LastError {
        code: StuffitErrorCode::Ok,
        message: cstring_lossy("no error"),
    });
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct StuffitBytes {
    pub ptr: *const u8,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct StuffitOwnedBytes {
    pub ptr: *mut u8,
    pub len: usize,
}

#[repr(C)]
pub struct StuffitEntryInfo {
    pub name: *const c_char,
    pub data_len: usize,
    pub resource_len: usize,
    pub file_type: [u8; 4],
    pub creator: [u8; 4],
    pub finder_flags: u16,
    pub is_folder: u8,
    pub data_method: u8,
    pub resource_method: u8,
}

#[repr(C)]
pub struct StuffitNewEntry {
    pub name: *const c_char,
    pub data_fork: StuffitBytes,
    pub resource_fork: StuffitBytes,
    pub file_type: [u8; 4],
    pub creator: [u8; 4],
    pub finder_flags: u16,
    pub is_folder: u8,
}

struct Entry {
    name: CString,
    data_fork: Vec<u8>,
    resource_fork: Vec<u8>,
    file_type: [u8; 4],
    creator: [u8; 4],
    finder_flags: u16,
    is_folder: bool,
    data_method: u8,
    resource_method: u8,
}

pub struct StuffitArchive {
    entries: Vec<Entry>,
}

pub struct StuffitWriter {
    entries: Vec<SitEntry>,
}

struct FfiError {
    code: StuffitErrorCode,
    message: String,
}

impl FfiError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: StuffitErrorCode::InvalidArgument,
            message: message.into(),
        }
    }
}

impl From<SitError> for FfiError {
    fn from(error: SitError) -> Self {
        let code = match error {
            SitError::Io(_) => StuffitErrorCode::Io,
            SitError::UnsupportedVersion(_) => StuffitErrorCode::Unsupported,
            SitError::EncryptedArchive | SitError::IncorrectPassword => StuffitErrorCode::Encrypted,
            _ => StuffitErrorCode::Archive,
        };
        Self {
            code,
            message: error.to_string(),
        }
    }
}

fn cstring_lossy(message: &str) -> CString {
    let bytes = message
        .as_bytes()
        .iter()
        .map(|byte| if *byte == 0 { b'?' } else { *byte })
        .collect::<Vec<_>>();
    CString::new(bytes).expect("interior NUL bytes were replaced")
}

fn set_error(code: StuffitErrorCode, message: impl AsRef<str>) {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = LastError {
            code,
            message: cstring_lossy(message.as_ref()),
        };
    });
}

fn clear_error() {
    set_error(StuffitErrorCode::Ok, "no error");
}

fn ffi_result<T>(failure: T, f: impl FnOnce() -> Result<T, FfiError>) -> T {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(value)) => {
            clear_error();
            value
        }
        Ok(Err(error)) => {
            set_error(error.code, error.message);
            failure
        }
        Err(_) => {
            set_error(StuffitErrorCode::Panic, "panic inside stuffit-ffi");
            failure
        }
    }
}

fn convert_archive(archive: SitArchive) -> Result<StuffitArchive, FfiError> {
    let mut entries = Vec::with_capacity(archive.entries.len());
    for entry in archive.entries {
        validate_name(&entry.name).map_err(|message| FfiError {
            code: StuffitErrorCode::Archive,
            message,
        })?;
        validate_read_method(
            &entry,
            entry.data_method,
            !entry.data_fork.is_empty(),
            "data",
        )?;
        validate_read_method(
            &entry,
            entry.rsrc_method,
            !entry.resource_fork.is_empty(),
            "resource",
        )?;
        let (data_fork, resource_fork) = entry.decompressed_forks().map_err(|error| {
            let mut error = FfiError::from(error);
            error.message = format!("decompress {}: {}", entry.name, error.message);
            error
        })?;
        entries.push(Entry {
            name: cstring_lossy(&entry.name),
            data_fork,
            resource_fork,
            file_type: entry.file_type,
            creator: entry.creator,
            finder_flags: entry.finder_flags,
            is_folder: entry.is_folder,
            data_method: entry.data_method,
            resource_method: entry.rsrc_method,
        });
    }
    Ok(StuffitArchive { entries })
}

fn validate_read_method(
    entry: &SitEntry,
    method: u8,
    has_data: bool,
    fork: &str,
) -> Result<(), FfiError> {
    if !entry.is_compressed || !has_data {
        return Ok(());
    }
    let supported = match entry.format {
        ArchiveFormat::Sit5 => matches!(method, 0 | 13 | 14 | 15),
        ArchiveFormat::Classic => matches!(method & 0x0f, 0 | 1 | 2 | 3 | 13),
    };
    if supported {
        Ok(())
    } else {
        Err(FfiError {
            code: StuffitErrorCode::Unsupported,
            message: format!(
                "unsupported {fork} fork compression method {method} for {:?}",
                entry.name
            ),
        })
    }
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.starts_with('/')
        || name.contains('\\')
        || name.contains('\0')
        || name
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(format!("unsafe archive entry name: {name:?}"));
    }
    Ok(())
}

fn validate_hierarchy(entries: &[SitEntry]) -> Result<(), FfiError> {
    for entry in entries {
        if let Some((parent, _)) = entry.name.rsplit_once('/') {
            let parent_is_folder = entries
                .iter()
                .any(|candidate| candidate.name == parent && candidate.is_folder);
            if !parent_is_folder {
                return Err(FfiError::invalid(format!(
                    "entry {:?} has no parent folder {:?}",
                    entry.name, parent
                )));
            }
        }
    }
    Ok(())
}

fn parse_bytes(data: &[u8]) -> Result<*mut StuffitArchive, FfiError> {
    let archive = convert_archive(SitArchive::parse(data).map_err(FfiError::from)?)?;
    Ok(Box::into_raw(Box::new(archive)))
}

unsafe fn borrowed_bytes<'a>(bytes: StuffitBytes, label: &str) -> Result<&'a [u8], FfiError> {
    if bytes.ptr.is_null() && bytes.len != 0 {
        return Err(FfiError::invalid(format!("{label} pointer is NULL")));
    }
    if bytes.len == 0 {
        Ok(&[])
    } else {
        Ok(std::slice::from_raw_parts(bytes.ptr, bytes.len))
    }
}

#[no_mangle]
pub extern "C" fn stuffit_ffi_abi_version() -> u32 {
    1
}

#[no_mangle]
/// # Safety
/// `path` must point to a readable NUL-terminated C string.
pub unsafe extern "C" fn stuffit_archive_parse_file(path: *const c_char) -> *mut StuffitArchive {
    ffi_result(ptr::null_mut(), || {
        if path.is_null() {
            return Err(FfiError::invalid("path is NULL"));
        }
        let path = unsafe { CStr::from_ptr(path) }
            .to_str()
            .map_err(|error| FfiError::invalid(format!("path is not UTF-8: {error}")))?;
        let data = std::fs::read(path).map_err(|error| FfiError {
            code: StuffitErrorCode::Io,
            message: format!("read {path}: {error}"),
        })?;
        parse_bytes(&data)
    })
}

#[no_mangle]
/// # Safety
/// `data` must be readable for `len` bytes, or may be NULL when `len` is zero.
pub unsafe extern "C" fn stuffit_archive_parse_bytes(
    data: *const u8,
    len: usize,
) -> *mut StuffitArchive {
    ffi_result(ptr::null_mut(), || {
        if data.is_null() && len != 0 {
            return Err(FfiError::invalid("data pointer is NULL"));
        }
        let data = if len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(data, len) }
        };
        parse_bytes(data)
    })
}

#[no_mangle]
/// # Safety
/// `archive` must be NULL or a live handle returned by this library, and must
/// not have been freed previously.
pub unsafe extern "C" fn stuffit_archive_free(archive: *mut StuffitArchive) {
    if !archive.is_null() {
        unsafe {
            drop(Box::from_raw(archive));
        }
    }
}

#[no_mangle]
/// # Safety
/// `archive` must point to a live archive handle.
pub unsafe extern "C" fn stuffit_archive_entry_count(archive: *const StuffitArchive) -> usize {
    ffi_result(0, || {
        if archive.is_null() {
            return Err(FfiError::invalid("archive is NULL"));
        }
        Ok(unsafe { (*archive).entries.len() })
    })
}

#[no_mangle]
/// # Safety
/// `archive` must be live and `out` must be writable for one entry-info value.
pub unsafe extern "C" fn stuffit_archive_entry_info(
    archive: *const StuffitArchive,
    index: usize,
    out: *mut StuffitEntryInfo,
) -> c_int {
    ffi_result(-1, || {
        if archive.is_null() || out.is_null() {
            return Err(FfiError::invalid("archive or output pointer is NULL"));
        }
        let entry = unsafe { &*archive }
            .entries
            .get(index)
            .ok_or_else(|| FfiError::invalid(format!("entry index {index} out of range")))?;
        unsafe {
            *out = StuffitEntryInfo {
                name: entry.name.as_ptr(),
                data_len: entry.data_fork.len(),
                resource_len: entry.resource_fork.len(),
                file_type: entry.file_type,
                creator: entry.creator,
                finder_flags: entry.finder_flags,
                is_folder: u8::from(entry.is_folder),
                data_method: entry.data_method,
                resource_method: entry.resource_method,
            };
        }
        Ok(0)
    })
}

#[no_mangle]
/// # Safety
/// `archive` must be live and `out` must be writable for one byte-buffer value.
pub unsafe extern "C" fn stuffit_archive_entry_fork(
    archive: *const StuffitArchive,
    index: usize,
    fork: c_int,
    out: *mut StuffitBytes,
) -> c_int {
    ffi_result(-1, || {
        if archive.is_null() || out.is_null() {
            return Err(FfiError::invalid("archive or output pointer is NULL"));
        }
        let entry = unsafe { &*archive }
            .entries
            .get(index)
            .ok_or_else(|| FfiError::invalid(format!("entry index {index} out of range")))?;
        let bytes = match fork {
            FORK_DATA => &entry.data_fork,
            FORK_RESOURCE => &entry.resource_fork,
            _ => return Err(FfiError::invalid(format!("unknown fork {fork}"))),
        };
        unsafe {
            *out = StuffitBytes {
                ptr: bytes.as_ptr(),
                len: bytes.len(),
            };
        }
        Ok(0)
    })
}

#[no_mangle]
pub extern "C" fn stuffit_writer_new() -> *mut StuffitWriter {
    ffi_result(ptr::null_mut(), || {
        Ok(Box::into_raw(Box::new(StuffitWriter {
            entries: Vec::new(),
        })))
    })
}

#[no_mangle]
/// # Safety
/// `writer` must be NULL or a live handle returned by this library, and must
/// not have been freed previously.
pub unsafe extern "C" fn stuffit_writer_free(writer: *mut StuffitWriter) {
    if !writer.is_null() {
        unsafe {
            drop(Box::from_raw(writer));
        }
    }
}

#[no_mangle]
/// # Safety
/// `writer` must be live. `entry`, its name, and its fork buffers must remain
/// readable for the duration of this call.
pub unsafe extern "C" fn stuffit_writer_add_entry(
    writer: *mut StuffitWriter,
    entry: *const StuffitNewEntry,
) -> c_int {
    ffi_result(-1, || {
        if writer.is_null() || entry.is_null() {
            return Err(FfiError::invalid("writer or entry pointer is NULL"));
        }
        let entry = unsafe { &*entry };
        if entry.name.is_null() {
            return Err(FfiError::invalid("entry name is NULL"));
        }
        let name = unsafe { CStr::from_ptr(entry.name) }
            .to_str()
            .map_err(|error| FfiError::invalid(format!("entry name is not UTF-8: {error}")))?
            .to_owned();
        validate_name(&name).map_err(FfiError::invalid)?;
        let data_fork = unsafe { borrowed_bytes(entry.data_fork, "data fork")? }.to_vec();
        let resource_fork =
            unsafe { borrowed_bytes(entry.resource_fork, "resource fork")? }.to_vec();
        unsafe { &mut *writer }.entries.push(SitEntry {
            name,
            data_fork,
            resource_fork,
            file_type: entry.file_type,
            creator: entry.creator,
            is_folder: entry.is_folder != 0,
            finder_flags: entry.finder_flags,
            ..Default::default()
        });
        Ok(0)
    })
}

#[no_mangle]
/// # Safety
/// `writer` must be live and `out` must be writable for one owned-buffer value.
pub unsafe extern "C" fn stuffit_writer_finish(
    writer: *const StuffitWriter,
    method: u8,
    out: *mut StuffitOwnedBytes,
) -> c_int {
    ffi_result(-1, || {
        if writer.is_null() || out.is_null() {
            return Err(FfiError::invalid("writer or output pointer is NULL"));
        }
        let writer = unsafe { &*writer };
        validate_hierarchy(&writer.entries)?;
        if !matches!(method, 0 | 13 | 14 | 15) {
            return Err(FfiError {
                code: StuffitErrorCode::Unsupported,
                message: format!("unsupported write compression method {method}"),
            });
        }
        let archive = SitArchive {
            entries: writer.entries.clone(),
        };
        let bytes = archive
            .serialize_with_method(method)
            .map_err(FfiError::from)?;
        let mut bytes = bytes.into_boxed_slice();
        let result = StuffitOwnedBytes {
            ptr: bytes.as_mut_ptr(),
            len: bytes.len(),
        };
        std::mem::forget(bytes);
        unsafe {
            *out = result;
        }
        Ok(0)
    })
}

#[no_mangle]
/// # Safety
/// `bytes` must be an owned buffer returned by this library and must not have
/// been freed previously.
pub unsafe extern "C" fn stuffit_owned_bytes_free(bytes: StuffitOwnedBytes) {
    if !bytes.ptr.is_null() {
        unsafe {
            let slice = ptr::slice_from_raw_parts_mut(bytes.ptr, bytes.len);
            drop(Box::from_raw(slice));
        }
    }
}

#[no_mangle]
pub extern "C" fn stuffit_last_error_code() -> StuffitErrorCode {
    LAST_ERROR.with(|slot| slot.borrow().code)
}

#[no_mangle]
pub extern "C" fn stuffit_last_error() -> *const c_char {
    LAST_ERROR.with(|slot| slot.borrow().message.as_ptr())
}
