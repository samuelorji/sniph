pub fn format_number_to_units(number: u128) -> String {
    const KB: u128 = 1024;
    const MB: u128 = 1024 * KB;
    const GB: u128 = 1024 * MB;
    const TB: u128 = 1024 * GB;
    const PB: u128 = 1024 * TB;
    const EB: u128 = 1024 * PB;

    match number {
        b if b < KB => format!("{} ", b),
        b if b < MB => format!("{:.2} K", b as f64 / KB as f64),
        b if b < GB => format!("{:.2} M", b as f64 / MB as f64),
        b if b < TB => format!("{:.2} G", b as f64 / GB as f64),
        b if b < PB => format!("{:.2} T", b as f64 / TB as f64),
        b if b < EB => format!("{:.2} P", b as f64 / PB as f64),
        b => format!("{:.2} E", b as f64 / EB as f64),
    }
}
