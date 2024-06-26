pub trait HashFn<const B: usize, const L: usize> {
    const BLOCK_SIZE: usize = B;
    const OUTPUT_SIZE: usize = L;

    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> [u8; L];
}