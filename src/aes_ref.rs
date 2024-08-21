pub const AES128_SBOX: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

pub const RCON: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
];

pub const BYTESIZE: usize = 8;
pub const BLOCKSIZE_IN_BYTE: usize = 16;
pub const BLOCKSIZE_IN_BIT: usize = 128;
pub const NUM_COLUMNS: usize = 4;
pub const NUM_ROWS: usize = 4;
pub const NUM_ROUNDS: usize = 10;

pub type StateByteArray = [u8; BLOCKSIZE_IN_BYTE];
pub type StateByteMat = [[u8; NUM_COLUMNS]; NUM_ROWS];
pub type StateBitArray = [u8; BLOCKSIZE_IN_BIT];

pub struct Aes128Ref {
    key: StateByteArray,
    rk_mat: [StateByteMat; NUM_ROUNDS+1],
}

impl Aes128Ref {
    pub fn new(master_key: &StateByteArray) -> Aes128Ref {
        let mut key = [0u8; BLOCKSIZE_IN_BYTE];
        for i in 0..BLOCKSIZE_IN_BYTE {
            key[i] = master_key[i];
        }
        let rk_mat = [[[0u8; NUM_COLUMNS]; NUM_ROWS]; NUM_ROUNDS+1];

        let mut aes = Aes128Ref {
            key: key,
            rk_mat: rk_mat,
        };
        aes.expand_key();

        aes
    }

    fn expand_key(&mut self) {
        for col in 0..NUM_COLUMNS {
            for row in 0..NUM_ROWS {
                self.rk_mat[0][col][row] = self.key[4*col + row];
            }
        }

        for r in 1..=NUM_ROUNDS {
            let cur_key = self.rk_mat[r-1];
            self.rk_mat[r] = cur_key;

            let sub_rot_key = [
                AES128_SBOX[cur_key[3][1] as usize],
                AES128_SBOX[cur_key[3][2] as usize],
                AES128_SBOX[cur_key[3][3] as usize],
                AES128_SBOX[cur_key[3][0] as usize],
            ];

            for row in 0..NUM_ROWS {
                self.rk_mat[r][0][row] ^= sub_rot_key[row];
            }
            self.rk_mat[r][0][0] ^= RCON[r];

            for col in 1..NUM_COLUMNS {
                for row in 0..NUM_ROWS {
                    self.rk_mat[r][col][row] ^= self.rk_mat[r][col-1][row];
                }
            }
        }
    }

    pub fn get_round_keys(&self) -> [StateByteArray; NUM_ROUNDS+1] {
        let mut round_keys = [[0u8; BLOCKSIZE_IN_BYTE]; NUM_ROUNDS+1];
        for r in 0..=NUM_ROUNDS {
            for col in 0..NUM_COLUMNS {
                for row in 0..NUM_ROWS {
                    round_keys[r][4*col + row] = self.rk_mat[r][col][row]
                }
            }
        }

        round_keys
    }

    pub fn encrypt_block(&self, message: StateByteArray) -> StateByteArray {
        let mut state = byte_array_to_mat(message);
        self.add_round_key(&mut state, 0);

        for r in 1..NUM_ROUNDS {
            self.sub_bytes(&mut state);
            self.shift_rows(&mut state);
            self.mix_columns(&mut state);
            self.add_round_key(&mut state, r);
        }

        self.sub_bytes(&mut state);
        self.shift_rows(&mut state);
        self.add_round_key(&mut state, NUM_ROUNDS);

        byte_mat_to_array(state)
    }

    pub fn add_round_key(&self, state: &mut StateByteMat, round: usize) {
        for col in 0..NUM_COLUMNS {
            for row in 0..NUM_ROWS {
                state[col][row] ^= self.rk_mat[round][col][row];
            }
        }
    }

    pub fn sub_bytes(&self, state: &mut StateByteMat) {
        for col in 0..NUM_COLUMNS {
            for row in 0..NUM_ROWS {
                state[col][row] = AES128_SBOX[state[col][row] as usize];
            }
        }
    }

    pub fn shift_rows(&self, state: &mut StateByteMat) {
        let buf = state.clone();
        for row in 0..NUM_ROWS {
            for col in 0..NUM_COLUMNS {
                state[col][row] = buf[(row + col) % NUM_COLUMNS][row];
            }
        }
    }

    pub fn mix_columns(&self, state: &mut StateByteMat) {
        let buf = state.clone();
        for col in 0..NUM_COLUMNS {
            for row in 0..NUM_ROWS {
                state[col][row] = mult_by_two(buf[col][row] ^ buf[col][(row + 1) % NUM_ROWS]);
                state[col][row] ^= buf[col][(row + 1) % NUM_ROWS];
                state[col][row] ^= buf[col][(row + 2) % NUM_ROWS];
                state[col][row] ^= buf[col][(row + 3) % NUM_ROWS];
            }
        }
    }
}

pub fn byte_array_to_mat(input: StateByteArray) -> StateByteMat {
    let mut output = [[0u8; NUM_COLUMNS]; NUM_ROWS];
    for col in 0..NUM_COLUMNS {
        for row in 0..NUM_ROWS {
            output[col][row] = input[4*col + row];
        }
    }

    output
}

pub fn byte_mat_to_array(input: StateByteMat) -> StateByteArray {
    let mut output = [0u8; BLOCKSIZE_IN_BYTE];
    for col in 0..NUM_COLUMNS {
        for row in 0..NUM_ROWS {
            output[4*col + row] = input[col][row];
        }
    }

    output
}

pub fn byte_array_to_bit_array(input: StateByteArray) -> StateBitArray {
    let mut output = [0u8; BLOCKSIZE_IN_BIT];
    for (byte_idx, byte) in input.iter().enumerate() {
        for bit_idx in 0..BYTESIZE {
            let index = BYTESIZE * byte_idx + bit_idx;
            output[index] = (byte & (1 << bit_idx)) >> bit_idx;
        }
    }

    output
}

pub fn byte_mat_to_bit_array(input: StateByteMat) -> StateBitArray {
    byte_array_to_bit_array(byte_mat_to_array(input))
}

fn mult_by_two(a: u8) -> u8 {
    if a & 0x80 != 0 {
        ((a << 1) & 0xFF) ^ 0x1B
    } else {
        a << 1
    }
}
