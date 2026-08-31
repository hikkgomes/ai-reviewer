pub fn broken(value: u32) -> u32 {
    unsafe { std::mem::transmute::<u32, u32>(value)
