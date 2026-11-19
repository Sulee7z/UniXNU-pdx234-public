#!/usr/bin/env python3
"""Execute the actual pinned runtime Directory::open and filesystem helpers."""
from pathlib import Path
import argparse
import subprocess
import tempfile
import hashlib


def item(text, marker):
    start = text.index(marker)
    brace = text.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rustc', default='/mnt/e/UniXNU-sheng27-sony-20261113/rust-userspace-002/rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustc')
    args = parser.parse_args()
    path = Path('/mnt/e/UniXNU-sheng27-sony-20261113/metal-runtime-001/.cache/gpu-reference/metal2vulkan/crates/metal2vulkan-runtime/src/shader_cache/store.rs')
    text = path.read_text()
    source = '''use std::{fs, io::{self, Write}, path::{Path,PathBuf}, sync::atomic::{AtomicU64,Ordering}, time::SystemTime};
type Hash256 = [u8;32];
const LAYOUT: &str = "v1";
fn hex(bytes: &[u8]) -> String {bytes.iter().map(|x|format!("{x:02x}")).collect()}
'''
    for marker in ('pub(crate) struct Directory', 'pub(crate) struct Failed', 'fn unique()',
                   'pub(super) fn create_private_dir_all', 'fn new_private_file'):
        source += item(text, marker).replace('pub(super) ', '') + '\n'
    source += 'impl Directory {\n'
    for marker in ('pub(crate) fn open(root:', 'fn layout_dir(', 'fn build_dir('):
        source += item(text, marker) + '\n'
    source += '''}
fn main() {
 let root=PathBuf::from(std::env::args().nth(1).unwrap());
 std::env::remove_var("METAL2VULKAN_SHADER_CACHE_OPTIONAL");
 assert!(Directory::open(root.join("good"),[0;32],1024).is_ok());
 let blocked=root.join("blocked");fs::create_dir(&blocked).unwrap();
 fs::write(blocked.join("v1"),b"not a directory").unwrap();
 assert!(Directory::open(blocked.clone(),[0;32],1024).is_err());
 std::env::set_var("METAL2VULKAN_SHADER_CACHE_OPTIONAL","1");
 assert!(Directory::open(blocked.clone(),[0;32],1024).is_ok());
 assert_eq!(fs::read(blocked.join("v1")).unwrap(),b"not a directory");
 std::env::remove_var("METAL2VULKAN_SHADER_CACHE_OPTIONAL");
 assert!(Directory::open(blocked,[0;32],1024).is_err());
 let file=root.join("file");fs::write(&file,b"keep").unwrap();
 assert!(Directory::open(file.join("child"),[0;32],1024).is_err());
 std::env::set_var("METAL2VULKAN_SHADER_CACHE_OPTIONAL","1");
 assert!(Directory::open(file.join("child"),[0;32],1024).is_ok());
 assert_eq!(fs::read(&file).unwrap(),b"keep");
 println!("PASS actual runtime cache: writable, blocked build subdir, blocked root, optional mode, restoration");
}
'''
    with tempfile.TemporaryDirectory(prefix='d27-runtime-cache-') as tmp:
        temp = Path(tmp)
        (temp / 'check.rs').write_text(source)
        subprocess.run([args.rustc, '--edition', '2021', '-A', 'dead_code', str(temp / 'check.rs'), '-o', str(temp / 'check')], check=True)
        subprocess.run([str(temp / 'check'), str(temp)], check=True)
    print('runtime store SHA256', hashlib.sha256(path.read_bytes()).hexdigest())


if __name__ == '__main__':
    main()
