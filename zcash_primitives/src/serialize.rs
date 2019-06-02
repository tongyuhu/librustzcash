use std::io::{self, Read, Write};

const MAX_SIZE: usize = 0x02000000;

struct CompactSize;

impl CompactSize {
    fn read<R: Read>(mut reader: R) -> io::Result<usize> {
        let mut flag = [0; 1];
        reader.read_exact(&mut flag)?;
        let flag = flag[0];
        match if flag < 253 {
            Ok(flag as usize)
        } else if flag == 253 {
            let mut buf = [0; 2];
            reader.read_exact(&mut buf)?;
            match u16::from_le_bytes(buf) {
                n if n < 253 => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "non-canonical CompactSize",
                )),
                n => Ok(n as usize),
            }
        } else if flag == 254 {
            let mut buf = [0; 4];
            reader.read_exact(&mut buf)?;
            match u32::from_le_bytes(buf) {
                n if n < 0x10000 => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "non-canonical CompactSize",
                )),
                n => Ok(n as usize),
            }
        } else {
            let mut buf = [0; 8];
            reader.read_exact(&mut buf)?;
            match u64::from_le_bytes(buf) {
                n if n < 0x100000000 => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "non-canonical CompactSize",
                )),
                n => Ok(n as usize),
            }
        }? {
            s if s > MAX_SIZE => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "CompactSize too large",
            )),
            s => Ok(s),
        }
    }

    fn write<W: Write>(mut writer: W, size: usize) -> io::Result<()> {
        match size {
            s if s < 253 => writer.write_all(&[s as u8]),
            s if s <= 0xFFFF => {
                writer.write_all(&[253])?;
                writer.write_all(&(s as u16).to_le_bytes())
            }
            s if s <= 0xFFFFFFFF => {
                writer.write_all(&[254])?;
                writer.write_all(&(s as u32).to_le_bytes())
            }
            s => {
                writer.write_all(&[255])?;
                writer.write_all(&(s as u64).to_le_bytes())
            }
        }
    }
}

pub struct Vector;

impl Vector {
    pub fn read<R: Read, E, F>(mut reader: R, func: F) -> io::Result<Vec<E>>
    where
        F: Fn(&mut R) -> io::Result<E>,
    {
        let count = CompactSize::read(&mut reader)?;
        (0..count).into_iter().map(|_| func(&mut reader)).collect()
    }

    pub fn write<W: Write, E, F>(mut writer: W, vec: &[E], func: F) -> io::Result<()>
    where
        F: Fn(&mut W, &E) -> io::Result<()>,
    {
        CompactSize::write(&mut writer, vec.len())?;
        vec.iter().map(|e| func(&mut writer, e)).collect()
    }
}

pub struct Optional;

impl Optional {
    pub fn read<R: Read, T, F>(mut reader: R, func: F) -> io::Result<Option<T>>
    where
        F: Fn(&mut R) -> io::Result<T>,
    {
        let mut buf = [0; 1];
        reader.read_exact(&mut buf)?;
        match buf[0] {
            0 => Ok(None),
            1 => Ok(Some(func(&mut reader)?)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "non-canonical Option<T>",
            )),
        }
    }

    pub fn write<W: Write, T, F>(mut writer: W, val: &Option<T>, func: F) -> io::Result<()>
    where
        F: Fn(&mut W, &T) -> io::Result<()>,
    {
        match val {
            None => writer.write_all(&[0]),
            Some(e) => {
                writer.write_all(&[1])?;
                func(&mut writer, e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_size() {
        macro_rules! eval {
            ($value:expr, $expected:expr) => {
                let mut data = vec![];
                CompactSize::write(&mut data, $value).unwrap();
                assert_eq!(&data[..], &$expected[..]);
                match CompactSize::read(&data[..]) {
                    Ok(n) => assert_eq!(n, $value),
                    Err(e) => panic!("Unexpected error: {:?}", e),
                }
            };
        }

        eval!(0, [0]);
        eval!(1, [1]);
        eval!(252, [252]);
        eval!(253, [253, 253, 0]);
        eval!(254, [253, 254, 0]);
        eval!(255, [253, 255, 0]);
        eval!(256, [253, 0, 1]);
        eval!(256, [253, 0, 1]);
        eval!(65535, [253, 255, 255]);
        eval!(65536, [254, 0, 0, 1, 0]);
        eval!(65537, [254, 1, 0, 1, 0]);

        eval!(33554432, [254, 0, 0, 0, 2]);

        {
            let value = 33554433;
            let encoded = &[254, 1, 0, 0, 2][..];
            let mut data = vec![];
            CompactSize::write(&mut data, value).unwrap();
            assert_eq!(&data[..], encoded);
            assert!(CompactSize::read(encoded).is_err());
        }
    }

    #[test]
    fn vector() {
        macro_rules! eval {
            ($value:expr, $expected:expr) => {
                let mut data = vec![];
                Vector::write(&mut data, &$value, |w, e| w.write_all(&[*e])).unwrap();
                assert_eq!(&data[..], &$expected[..]);
                match Vector::read(&data[..], |r| {
                    let mut buf = [0; 1];
                    r.read_exact(&mut buf)?;
                    Ok(buf[0])
                }) {
                    Ok(v) => assert_eq!(v, $value),
                    Err(e) => panic!("Unexpected error: {:?}", e),
                }
            };
        }

        eval!(vec![], [0]);
        eval!(vec![0], [1, 0]);
        eval!(vec![1], [1, 1]);
        eval!(vec![5; 8], [8, 5, 5, 5, 5, 5, 5, 5, 5]);

        {
            // expected = [253, 4, 1, 7, 7, 7, ...]
            let mut expected = vec![7; 263];
            expected[0] = 253;
            expected[1] = 4;
            expected[2] = 1;

            eval!(vec![7; 260], expected);
        }
    }

    #[test]
    fn optional() {
        macro_rules! eval {
            ($value:expr, $expected:expr, $write:expr, $read:expr) => {
                let mut data = vec![];
                Optional::write(&mut data, &$value, $write).unwrap();
                assert_eq!(&data[..], &$expected[..]);
                match Optional::read(&data[..], $read) {
                    Ok(v) => assert_eq!(v, $value),
                    Err(e) => panic!("Unexpected error: {:?}", e),
                }
            };
        }

        macro_rules! eval_u8 {
            ($value:expr, $expected:expr) => {
                eval!($value, $expected, |w, e| w.write_all(&[*e]), |r| {
                    let mut buf = [0; 1];
                    r.read_exact(&mut buf)?;
                    Ok(buf[0])
                })
            };
        }

        macro_rules! eval_vec {
            ($value:expr, $expected:expr) => {
                eval!(
                    $value,
                    $expected,
                    |w, v| Vector::write(w, v, |w, e| w.write_all(&[*e])),
                    |r| Vector::read(r, |r| {
                        let mut buf = [0; 1];
                        r.read_exact(&mut buf)?;
                        Ok(buf[0])
                    })
                )
            };
        }

        eval_u8!(None, [0]);
        eval_u8!(Some(0), [1, 0]);
        eval_u8!(Some(1), [1, 1]);
        eval_u8!(Some(5), [1, 5]);

        eval_vec!(Some(vec![]), [1, 0]);
        eval_vec!(Some(vec![0]), [1, 1, 0]);
        eval_vec!(Some(vec![1]), [1, 1, 1]);
        eval_vec!(Some(vec![5; 8]), [1, 8, 5, 5, 5, 5, 5, 5, 5, 5]);
    }
}
