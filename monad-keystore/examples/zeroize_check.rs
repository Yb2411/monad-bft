use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;

use monad_keystore::keystore::{KeystoreSecret, KeystoreVersion};

struct LeakingAlloc {
    freed: Mutex<Vec<(*mut u8, Layout)>>,
}

unsafe impl Send for LeakingAlloc {}
unsafe impl Sync for LeakingAlloc {}

unsafe impl GlobalAlloc for LeakingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.freed.lock().unwrap().push((ptr, layout));
    }
}

impl LeakingAlloc {
    const fn new() -> Self {
        Self {
            freed: Mutex::new(Vec::new()),
        }
    }

    fn drain_freed(&self) {
        let mut freed = self.freed.lock().unwrap();
        for (ptr, layout) in freed.drain(..) {
            unsafe { System.dealloc(ptr, layout) };
        }
    }
}

#[global_allocator]
static ALLOC: LeakingAlloc = LeakingAlloc::new();

fn main() {
    let secret = vec![0x42u8; 32];
    let ptr = secret.as_ptr();

    unsafe {
        let slice = std::slice::from_raw_parts(ptr, 32);
        println!("before to_secp: {:?}", slice);
        assert!(slice.iter().all(|&b| b == 0x42));
    }

    let keystore_secret = KeystoreSecret::new(secret);
    let _keypair = keystore_secret
        .to_secp(KeystoreVersion::DirectIkm)
        .unwrap();

    unsafe {
        let slice = std::slice::from_raw_parts(ptr, 32);
        println!("after  to_secp: {:?}", slice);
        assert!(
            slice.iter().all(|&b| b == 0),
            "IKM was not zeroized: {:?}",
            slice
        );
    }

    println!("PASS: IKM zeroized after to_secp consumed KeystoreSecret");

    ALLOC.drain_freed();
}
