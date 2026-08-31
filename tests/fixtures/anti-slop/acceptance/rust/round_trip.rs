use std::any::Any;

pub fn same_type_transmute(value: u32) -> u32 {
    unsafe { std::mem::transmute::<u32, u32>(value) }
}

pub fn immediate_any_round_trip(value: u32) -> u32 {
    *(Box::new(value) as Box<dyn Any>).downcast::<u32>().unwrap()
}

pub fn direct_value(value: u32) -> u32 {
    value
}
