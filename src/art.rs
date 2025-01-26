use sha2::{Digest, Sha256};

const GRID_SIZE: usize = 16;

/// Generate a 32×32 ASCII art grid by “walking” around based on the hash
pub fn generate_ascii_art(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);

    // Initialize a grid filled with dots (or space)
    let mut grid = vec![vec!['.'; GRID_SIZE]; GRID_SIZE];

    // Start near the center
    let mut x = GRID_SIZE as isize / 2;
    let mut y = GRID_SIZE as isize / 2;

    // For each byte in the hash, interpret bits to move and place a symbol
    for &byte in hash.iter() {
        // We'll split each byte into 4 segments of 2 bits,
        // each controlling direction or a symbol choice.
        // Example: for a byte = 0bXYZW_ABCD_EFGH_IJKL
        //   - XYZW: used to choose direction 4 times
        //   - ABCD, EFGH, IJKL: each might correspond to a symbol or another small rule

        // Move 4 times per byte (so 128 steps in total)
        for i in 0..4 {
            // Extract 2 bits for direction (0..3)
            let direction = (byte >> (2 * i)) & 0b11;
            match direction {
                0 => y = (y - 1).clamp(0, GRID_SIZE as isize - 1),
                1 => x = (x + 1).clamp(0, GRID_SIZE as isize - 1),
                2 => y = (y + 1).clamp(0, GRID_SIZE as isize - 1),
                3 => x = (x - 1).clamp(0, GRID_SIZE as isize - 1),
                _ => unreachable!(),
            }

            // Place a symbol in the grid
            // For variety, choose different symbols based on direction or iteration
            let symbol = match direction {
                0 => '*',
                1 => '#',
                2 => '+',
                3 => 'x',
                _ => '?',
            };
            grid[y as usize][x as usize] = symbol;
        }
    }

    // Convert the 2D vector to a single string for printing
    grid.into_iter()
        .map(|row| row.into_iter().collect::<String>())
        .collect::<Vec<String>>()
        .join("\n")
}
