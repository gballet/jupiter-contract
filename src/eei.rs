#[cfg(not(test))]
extern "C" {
    pub fn revert();
    pub fn finish(data: *const u8, len: usize);
    pub fn calldata(buf: *const u8, offset: usize, len: usize);
    pub fn calldata_size() -> usize;

    pub fn get_storage_root(ptr: *mut u8, len: usize);
    pub fn set_storage_root(ptr: *const u8, len: usize);
}
