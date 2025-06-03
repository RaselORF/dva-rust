use libc::strcpy;
use std::{
    alloc::{alloc, Layout},
    ffi::{CStr, CString},
    fmt::Display,
    mem::{forget, ManuallyDrop},
    os::raw::c_char,
    path::Path,
    ptr,
    sync::Mutex,
};

// CPJ-1
pub fn avoid_const_path_join() {
    let path = Path::new("..").join("a").join("b").join("c");
    println!("{:?}", path);
}

// FDF-1
struct MyString(&'static str);

impl Drop for MyString {
    fn drop(&mut self) {
        println!(">>> Dropping Data: {}", self.0);
    }
}

pub fn check_double_free() {
    let b = Box::new(MyString("A"));
    let p: *const Box<MyString> = &b;
    unsafe {
        let b_dup = p.read();
        println!("{}", b_dup.0);
    }
}

// FDL-1
pub fn check_double_lock() {
    let my_mutex = Mutex::new(10);
    let val = my_mutex.lock().unwrap();
    println!("{:?}", *val);

    *my_mutex.lock().unwrap() += 1;
}

// FLM-1
struct ConstStringData<'a> {
    x: *const String,
    y: &'a str,
}

fn bar<'a, 'b>(arg: &'a String) -> ConstStringData<'b> {
    ConstStringData {
        x: arg as *const String,
        y: "sss",
    }
}

pub fn check_flm_1() {
    let v = "Hello".to_string();
    let bar_obj = bar(&v);
    drop(v);
    unsafe {
        // This is where the use after free happens
        println!("{}", *bar_obj.x)
    }
}

// FLM-2
struct MutStringData<'a> {
    x: *mut String,
    y: &'a str,
}

fn baz<'a>(s: &'a mut String, d: &'a mut MutStringData) {
    d.x = s;
}

pub fn check_flm_2() {
    let mut data = MutStringData {
        x: &mut "Hello".to_string(),
        y: "Demo",
    };
    {
        let mut v = "World".to_string();
        baz(&mut v, &mut data);
    }
    // v is out of scope and it is dropped.
    // but it is borrowed inside data
    // which causes use-after-free bug
    unsafe {
        println!("{}", *data.x);
    }
}

// FLSC-1
pub fn avoid_compare_to_nan(x: f32) -> bool {
    return x == f32::NAN;
}

// FML-1
struct FmlData {
    v: u32,
}

impl Drop for FmlData {
    fn drop(&mut self) {
        println!("Dropping Data {}", self.v);
    }
}

pub unsafe fn check_fml_1() {
    let ptr = alloc(Layout::new::<FmlData>()) as *mut FmlData;
    ptr.write(FmlData { v: 5 });
}

// FML-2
fn get_ptr_to_fml_data() -> *mut FmlData {
    let b = Box::new(FmlData { v: 5 });
    Box::into_raw(b)
}

pub fn check_fml_2() {
    let ptr = get_ptr_to_fml_data();
}

// FML-3
struct Fml3Data(u32);
impl Drop for Fml3Data {
    fn drop(&mut self) {
        println!("Dropping Data {}", self.0);
    }
}
struct Container(Box<Fml3Data>);

pub fn check_fml_3(f: bool) {
    let c = Container(Box::new(Fml3Data(57)));
    let m = ManuallyDrop::new(c);
    if f {
        let x = ManuallyDrop::into_inner(m);
        println!("{}", x.0 .0);
    }
    println!("End");
}

// FML-4
pub fn check_fml_4() {
    let c = Container(Box::new(Fml3Data(57)));
    forget(c);
}

pub mod a {
    // FT-22
    pub fn check_int_overflow<T>(n: usize) -> Vec<T>
    where
        T: Copy,
    {
        let mut buf = Vec::with_capacity(100000 * n);
        buf
    }

    // FT-23
    pub fn check_resource_exhaustion(n: usize) {
        let mut vec = vec![1];
        vec.reserve(n);
        assert!(vec.capacity() >= 11);
    }
}

// FT-24
pub fn check_null_to_c_func() {
    unsafe {
        let src = CString::new("hello").unwrap();
        let dest: *mut libc::c_char = ptr::null_mut();
        strcpy(dest, src.as_ptr());
    }
}

// FT-25
unsafe extern "C" {
    fn maybe_null(flag: i32) -> *const c_char;
}

pub fn check_null_return_from_c_func() {
    unsafe {
        let ptr = maybe_null(0);
        let c_str = CStr::from_ptr(ptr);
        let str_slice = c_str.to_str().unwrap();

        println!("Received: {}", str_slice);
    }
}

// FT-26
#[unsafe(no_mangle)]
pub extern "C" fn check_nullable_arg(msg: *const c_char) {
    let c_str = unsafe { CStr::from_ptr(msg) }; // no null check here
    let str_slice = c_str.to_str().unwrap();
    println!("Rust received: {}", str_slice);
}

// SGT-1
pub struct W {
    pub data: String,
}

fn do_format<W>(x: W) -> String
where
    W: Display,
{
    format!(">> {}", x)
}

pub fn check_shadowing() {
    let s = do_format("ABC");
    println!("{s}");
}

// UAF-1
fn print_string(s: &String) {
    println!("{s}")
}

fn get_const_string() -> *const String {
    &"Hello".to_string()
}

pub fn check_uaf_1() -> *const String {
    let d = get_const_string();
    unsafe {
        print_string(&*d);
    }
    d
}

// UAF-2
struct MyBox {
    x: String,
}

struct Uaf2Data {
    x: *const String,
}

fn use_string(s: String) {
    println!("{s}")
}

pub fn check_uaf_2() {
    let data = {
        let mb = MyBox {
            x: "Hello".to_string(),
        };
        Uaf2Data { x: &mb.x }
    };
    unsafe {
        use_string(data.x.read()); // use-after-free
    }
}

// UAF-3
struct Uaf3Data {
    x: *mut String,
}

pub fn check_uaf_3() {
    let data = {
        let mut mb = MyBox {
            x: "Hello".to_string(),
        };
        Uaf3Data { x: &mut mb.x }
    };
    unsafe {
        use_string(ptr::read(data.x)); // use-after-free
    }
}

// URP-1
pub fn avoid_abs_path_in_join() {
    let path = Path::new("/usr").join("/local/bin");
    println!("{:?}", path);
}

// URPV-1
pub fn use_runtime_path_value() -> String {
    let path = option_env!("CARGO");
    return path.map_or("".to_string(), |s| s.to_string());
}
