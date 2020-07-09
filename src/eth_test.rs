    static mut CD: Vec<u8> = Vec::new();
    static mut ROOT: Vec<u8> = Vec::new();

    pub fn reset() {
        unsafe {
            CD.clear();
            ROOT.clear();
        }
    }

    pub fn calldata(buf: &mut Vec<u8>, offset: usize) {
        let end = offset + buf.len();
        unsafe {
            buf.copy_from_slice(&CD[offset..end]);
        }
    }

    pub fn calldata_size() -> usize {
        return unsafe { CD.len() };
    }

    pub fn get_storage_root(buf: &mut Vec<u8>) {
        unsafe {
            buf.copy_from_slice(&ROOT[..]);
        }
    }

    pub fn set_storage_root(buf: Vec<u8>) {
        if buf.len() != 32 {
            panic!("Invalid root length");
        }
        unsafe {
            ROOT.resize(32, 0u8);
            for (i, b) in buf.iter().enumerate() {
                ROOT[i] = *b;
            }
        }
    }
    pub fn set_calldata(buf: Vec<u8>) {
        for b in buf.iter() {
            unsafe {
                CD.push(*b);
            }
        }
    }
