extern crate libc;
use std::intrinsics;
use std::ptr;
use std::str;
use std::ffi;
use std::fmt;

// Using an actual slice is causing issues with auto deref, instead implement a custom iterator and
// drop trait
pub struct Instructions {
    ptr: *const Insn,
    len: isize,
}

impl Instructions {
    // This method really shouldn't be public, but it was unclear how to make it visible in lib.rs
    // but not globally visible.
    pub fn from_raw_parts(ptr: *const Insn, len: isize) -> Instructions {
        Instructions {
            ptr: ptr,
            len: len,
        }
    }

    pub fn len(&self) -> isize {
        self.len
    }

    pub fn iter(&self) -> InstructionIterator {
        InstructionIterator { insns: &self, cur: 0 }
    }
}

impl Drop for Instructions {
    fn drop(&mut self) {
        unsafe { cs_free(self.ptr, self.len as libc::size_t); }
    }
}

pub struct InstructionIterator<'a> {
    insns: &'a Instructions,
    cur: isize,
}

impl<'a> Iterator for InstructionIterator<'a> {
    type Item = Insn;

    fn next(&mut self) -> Option<Insn> {
        if self.cur == self.insns.len {
            None
        } else {
            let obj = unsafe { intrinsics::offset(self.insns.ptr, self.cur) };
            self.cur += 1;
            Some(unsafe { ptr::read(obj) })
        }
    }
}
