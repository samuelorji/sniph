pub fn format_number_to_bytes(number: u128) -> String {
    const KB: u128 = 1024;
    const MB: u128 = 1024 * KB;
    const GB: u128 = 1024 * MB;
    const TB: u128 = 1024 * GB;
    const PB: u128 = 1024 * TB;
    const EB: u128 = 1024 * PB;

    match number {
        b if b < KB => format!("{} B", b),
        b if b < MB => format!("{:.2} KB", b as f64 / KB as f64),
        b if b < GB => format!("{:.2} MB", b as f64 / MB as f64),
        b if b < TB => format!("{:.2} GB", b as f64 / GB as f64),
        b if b < PB => format!("{:.2} TB", b as f64 / TB as f64),
        b if b < EB => format!("{:.2} PB", b as f64 / PB as f64),
        b => format!("{:.2} EB", b as f64 / EB as f64),
    }
}
