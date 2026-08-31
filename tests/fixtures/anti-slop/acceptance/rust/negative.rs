pub fn different_transmute(value: u32) -> i32 {
    unsafe { std::mem::transmute::<u32, i32>(value) }
}

pub fn no_dynamic_round_trip(value: u32) -> u32 {
    value
}
