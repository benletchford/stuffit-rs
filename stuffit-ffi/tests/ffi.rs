use std::ffi::{CStr, CString};
use std::mem::MaybeUninit;
use std::ptr;

use stuffit_ffi::*;

#[test]
fn creates_and_parses_dual_fork_entry() {
    unsafe {
        let writer = stuffit_writer_new();
        assert!(!writer.is_null());

        let folder_name = CString::new("Apps").unwrap();
        let folder = StuffitNewEntry {
            name: folder_name.as_ptr(),
            data_fork: StuffitBytes {
                ptr: ptr::null(),
                len: 0,
            },
            resource_fork: StuffitBytes {
                ptr: ptr::null(),
                len: 0,
            },
            file_type: [0; 4],
            creator: [0; 4],
            creation_date: 0,
            modification_date: 0,
            finder_flags: 0,
            is_folder: 1,
        };
        assert_eq!(stuffit_writer_add_entry(writer, &folder), 0);

        let name = CString::new("Apps/Demo").unwrap();
        let data = b"data fork";
        let resource = b"resource fork";
        let entry = StuffitNewEntry {
            name: name.as_ptr(),
            data_fork: StuffitBytes {
                ptr: data.as_ptr(),
                len: data.len(),
            },
            resource_fork: StuffitBytes {
                ptr: resource.as_ptr(),
                len: resource.len(),
            },
            file_type: *b"APPL",
            creator: *b"TEST",
            creation_date: 0xd1111111,
            modification_date: 0xd2222222,
            finder_flags: 0x4000,
            is_folder: 0,
        };
        assert_eq!(stuffit_writer_add_entry(writer, &entry), 0);

        let mut encoded = MaybeUninit::<StuffitOwnedBytes>::uninit();
        assert_eq!(stuffit_writer_finish(writer, 13, encoded.as_mut_ptr()), 0);
        let encoded = encoded.assume_init();
        stuffit_writer_free(writer);

        let archive = stuffit_archive_parse_bytes(encoded.ptr, encoded.len);
        assert!(!archive.is_null());
        assert_eq!(stuffit_archive_entry_count(archive), 2);

        let mut info = MaybeUninit::<StuffitEntryInfo>::uninit();
        assert_eq!(stuffit_archive_entry_info(archive, 1, info.as_mut_ptr()), 0);
        let info = info.assume_init();
        assert_eq!(CStr::from_ptr(info.name).to_bytes(), b"Apps/Demo");
        assert_eq!(info.file_type, *b"APPL");
        assert_eq!(info.creator, *b"TEST");
        assert_eq!(info.creation_date, 0xd1111111);
        assert_eq!(info.modification_date, 0xd2222222);
        assert_eq!(info.finder_flags, 0x4000);

        let mut fork = MaybeUninit::<StuffitBytes>::uninit();
        assert_eq!(
            stuffit_archive_entry_fork(archive, 1, 1, fork.as_mut_ptr()),
            0
        );
        let fork = fork.assume_init();
        assert_eq!(std::slice::from_raw_parts(fork.ptr, fork.len), resource);

        stuffit_archive_free(archive);
        stuffit_owned_bytes_free(encoded);
    }
}

#[test]
fn reports_invalid_arguments_without_unwinding() {
    unsafe {
        assert!(stuffit_archive_parse_bytes(ptr::null(), 4).is_null());
        assert_eq!(stuffit_last_error_code(), StuffitErrorCode::InvalidArgument);
        assert!(!CStr::from_ptr(stuffit_last_error()).to_bytes().is_empty());

        let writer = stuffit_writer_new();
        let name = CString::new("../escape").unwrap();
        let entry = StuffitNewEntry {
            name: name.as_ptr(),
            data_fork: StuffitBytes {
                ptr: ptr::null(),
                len: 0,
            },
            resource_fork: StuffitBytes {
                ptr: ptr::null(),
                len: 0,
            },
            file_type: [0; 4],
            creator: [0; 4],
            creation_date: 0,
            modification_date: 0,
            finder_flags: 0,
            is_folder: 0,
        };
        assert_eq!(stuffit_writer_add_entry(writer, &entry), -1);
        assert_eq!(stuffit_last_error_code(), StuffitErrorCode::InvalidArgument);
        stuffit_writer_free(writer);
    }
}
