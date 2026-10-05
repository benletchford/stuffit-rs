use crate::SitError;

fn invalid(reason: &str) -> SitError {
    SitError::Decompression(format!("invalid classic method 14 stream: {reason}"))
}

struct Bits<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Bits<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read(&mut self, count: usize) -> Result<u32, SitError> {
        if count > 32 || self.position + count > self.bytes.len() * 8 {
            return Err(invalid("unexpected end of bitstream"));
        }
        let mut value = 0u32;
        for shift in 0..count {
            let byte = self.bytes[self.position / 8];
            value |= (((byte >> (self.position % 8)) & 1) as u32) << shift;
            self.position += 1;
        }
        Ok(value)
    }

    fn align(&mut self) {
        self.position = (self.position + 7) & !7;
    }
}

#[derive(Default)]
struct Node {
    children: [Option<usize>; 2],
    symbol: Option<usize>,
}

struct Tree {
    nodes: Vec<Node>,
}

impl Tree {
    fn from_lengths(lengths: &[u8]) -> Result<Self, SitError> {
        let mut symbols: Vec<_> = lengths.iter().copied().zip(0..lengths.len()).collect();
        sort_lengths(&mut symbols);
        let first = symbols.iter().position(|(length, _)| *length != 0);
        if first.is_none() {
            return Err(invalid("empty Huffman tree"));
        }

        let mut tree = Self {
            nodes: vec![Node::default()],
        };
        let mut code = 0u64;
        let mut previous_length = 0u8;
        for (length, symbol) in symbols.into_iter().skip(first.unwrap()) {
            if length > 63 {
                return Err(invalid("Huffman code is too long"));
            }
            code <<= length - previous_length;
            if code >= (1u64 << length) {
                return Err(invalid("oversubscribed Huffman tree"));
            }
            let mut node = 0;
            for shift in (0..length).rev() {
                if tree.nodes[node].symbol.is_some() {
                    return Err(invalid("overlapping Huffman codes"));
                }
                let bit = ((code >> shift) & 1) as usize;
                node = match tree.nodes[node].children[bit] {
                    Some(index) => index,
                    None => {
                        let index = tree.nodes.len();
                        tree.nodes.push(Node::default());
                        tree.nodes[node].children[bit] = Some(index);
                        index
                    }
                };
            }
            if tree.nodes[node].symbol.is_some()
                || tree.nodes[node].children.iter().any(Option::is_some)
            {
                return Err(invalid("overlapping Huffman codes"));
            }
            tree.nodes[node].symbol = Some(symbol);
            code += 1;
            previous_length = length;
        }
        Ok(tree)
    }

    fn read(&self, bits: &mut Bits<'_>) -> Result<usize, SitError> {
        let mut node = 0;
        loop {
            if let Some(symbol) = self.nodes[node].symbol {
                return Ok(symbol);
            }
            let bit = bits.read(1)? as usize;
            node =
                self.nodes[node].children[bit].ok_or_else(|| invalid("undefined Huffman code"))?;
        }
    }
}

fn sort_lengths(pairs: &mut [(u8, usize)]) {
    if pairs.len() < 2 {
        return;
    }
    let pivot = pairs[0].0;
    let mut left = 0usize;
    let mut right = pairs.len();
    loop {
        left += 1;
        while left < pairs.len() && pivot > pairs[left].0 {
            left += 1;
        }
        right -= 1;
        while right > 0 && pivot < pairs[right].0 {
            right -= 1;
        }
        if right <= left {
            break;
        }
        pairs.swap(left, right);
    }
    if right > 0 {
        pairs.swap(0, right);
        sort_lengths(&mut pairs[..right]);
        sort_lengths(&mut pairs[right + 1..]);
    } else {
        sort_lengths(&mut pairs[1..]);
    }
}

fn read_tree(bits: &mut Bits<'_>, alphabet: usize, depth: usize) -> Result<Tree, SitError> {
    if depth > 4 {
        return Err(invalid("nested Huffman tree is too deep"));
    }
    let has_zero = bits.read(1)? != 0;
    let width = bits.read(2)? as usize + 2;
    let offset = bits.read(3)? as usize + 1;
    let range = 1usize << width;
    let zero = has_zero.then_some(range - 2);
    let nested = bits.read(2)? & 1 != 0;
    let code_tree = if nested {
        Some(read_tree(bits, range, depth + 1)?)
    } else {
        None
    };

    let mut lengths = Vec::with_capacity(alphabet);
    while lengths.len() < alphabet {
        let value = if let Some(tree) = &code_tree {
            tree.read(bits)?
        } else {
            bits.read(width)? as usize
        };
        if Some(value) == zero {
            lengths.push(0);
        } else if value == range - 1 {
            let repeats = if let Some(tree) = &code_tree {
                tree.read(bits)? + 3
            } else {
                bits.read(width)? as usize + 3
            };
            let previous = *lengths
                .last()
                .ok_or_else(|| invalid("repeat before first code length"))?;
            if repeats > alphabet - lengths.len() {
                return Err(invalid("code length repeat exceeds alphabet"));
            }
            lengths.resize(lengths.len() + repeats, previous);
        } else {
            let length = value + offset;
            if length > 63 {
                return Err(invalid("Huffman code is too long"));
            }
            lengths.push(length as u8);
        }
    }
    let tree = Tree::from_lengths(&lengths)?;
    bits.align();
    Ok(tree)
}

fn slot_value(
    bits: &mut Bits<'_>,
    slot: usize,
    first_free: usize,
    base: usize,
) -> Result<usize, SitError> {
    let extra = slot.saturating_sub(first_free) / 4;
    let mut value = base;
    for index in 0..slot {
        value += 1usize << (index.saturating_sub(first_free) / 4);
    }
    Ok(value + bits.read(extra)? as usize)
}

pub(super) fn decompress(data: &[u8], expected_len: usize) -> Result<Vec<u8>, SitError> {
    let mut bits = Bits::new(data);
    let block_count = bits.read(16)? as usize;
    let mut output = Vec::with_capacity(expected_len);
    for _ in 0..block_count {
        let _compressed_len = bits.read(32)?;
        let block_len = bits.read(32)? as usize;
        let target = output
            .len()
            .checked_add(block_len)
            .ok_or_else(|| invalid("output length overflow"))?;
        if target > expected_len {
            return Err(invalid("block exceeds declared output length"));
        }
        let symbols = read_tree(&mut bits, 308, 0)?;
        let distances = read_tree(&mut bits, 75, 0)?;
        while output.len() < target {
            let symbol = symbols.read(&mut bits)?;
            if symbol < 256 {
                output.push(symbol as u8);
            } else {
                let length = slot_value(&mut bits, symbol - 256, 4, 4)?;
                let distance_slot = distances.read(&mut bits)?;
                let distance = slot_value(&mut bits, distance_slot, 3, 1)?;
                if distance == 0 || distance > output.len() || output.len() + length > target {
                    return Err(invalid("match exceeds output history or block"));
                }
                for _ in 0..length {
                    output.push(output[output.len() - distance]);
                }
            }
        }
        bits.align();
    }
    if output.len() != expected_len {
        return Err(invalid("decoded length differs from archive header"));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::decompress;

    struct Writer {
        bytes: Vec<u8>,
        position: usize,
    }

    impl Writer {
        fn new() -> Self {
            Self {
                bytes: Vec::new(),
                position: 0,
            }
        }

        fn write(&mut self, value: u32, width: usize) {
            for bit in 0..width {
                if self.position / 8 == self.bytes.len() {
                    self.bytes.push(0);
                }
                self.bytes[self.position / 8] |=
                    (((value >> bit) & 1) as u8) << (self.position % 8);
                self.position += 1;
            }
        }

        fn align(&mut self) {
            while self.position % 8 != 0 {
                self.write(0, 1);
            }
        }

        fn tree_with_symbols(&mut self, alphabet: usize, symbols: &[usize]) {
            self.write(1, 1); // zero-length sentinel is 2
            self.write(0, 2); // two-bit code length fields
            self.write(0, 3); // nonzero lengths start at one
            self.write(0, 2); // raw code lengths
            for index in 0..alphabet {
                self.write(if symbols.contains(&index) { 0 } else { 2 }, 2);
            }
            self.align();
        }
    }

    #[test]
    fn decodes_literal_block() {
        let mut stream = Writer::new();
        stream.write(1, 16); // one block
        stream.write(0, 32); // compressed block size hint
        stream.write(1, 32); // one output byte
        stream.tree_with_symbols(308, &[b'A' as usize]);
        stream.tree_with_symbols(75, &[0]);
        stream.write(0, 1); // literal A
        stream.align();
        assert_eq!(decompress(&stream.bytes, 1).unwrap(), b"A");
        assert!(decompress(&stream.bytes[..stream.bytes.len() - 1], 1).is_err());
    }

    #[test]
    fn decodes_overlapping_match_and_limits_output() {
        let mut stream = Writer::new();
        stream.write(1, 16);
        stream.write(0, 32);
        stream.write(5, 32);
        stream.tree_with_symbols(308, &[b'A' as usize, 256]);
        stream.tree_with_symbols(75, &[0]);
        stream.write(0, 1); // literal A
        stream.write(1, 1); // length slot zero: four bytes
        stream.write(0, 1); // distance slot zero: previous byte
        stream.align();
        assert_eq!(decompress(&stream.bytes, 5).unwrap(), b"AAAAA");
        assert!(decompress(&stream.bytes, 4).is_err());
    }
}
