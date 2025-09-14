pub struct SniffStats {
    packets_captured : usize,
    packets_skipped : usize,
}

impl SniffStats {
    pub fn new() -> SniffStats {
        SniffStats{
            packets_captured : 0,
            packets_skipped : 0,
        }
    }
    
    pub fn increment_captured_packets(&mut self) {
        self.packets_captured += 1;
    }
    
    pub fn increment_skipped_packets(&mut self) {
        self.packets_skipped += 1;
    }
    
    pub fn get_packets_captured(&self) -> usize {
        self.packets_captured
    }
    
    pub fn get_packets_skipped(&self) -> usize {
        self.packets_skipped
    }
}