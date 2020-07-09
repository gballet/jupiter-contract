mod eei {
    extern "C" {
        pub fn revert();
        pub fn finish(data: *const u8, len: usize);
        pub fn calldata(buf: *const u8, offset: usize, len: usize);
        pub fn calldata_size() -> usize;

        pub fn get_storage_root(ptr: *mut u8, len: usize);
        pub fn set_storage_root(ptr: *const u8, len: usize);
    }
}

pub fn revert() {
    unsafe {
        eei::revert();
    }
}

pub fn finish(res: Vec<u8>) {
    unsafe {
        eei::finish(res.as_ptr(), res.len());
    }
}

pub fn calldata(buf: &mut Vec<u8>, offset: usize) {
    unsafe {
        eei::calldata(buf.as_mut_ptr(), offset, buf.len());
    }
}

pub fn calldata_size() -> usize {
    unsafe { eei::calldata_size() }
}

pub fn get_storage_root(buf: &mut Vec<u8>) {
    unsafe {
        eei::get_storage_root(buf.as_mut_ptr(), buf.len());
    }
}

pub fn set_storage_root(buf: Vec<u8>) {
    unsafe {
        eei::set_storage_root(buf.as_ptr(), buf.len());
    }
}
