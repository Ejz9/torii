/// Zero-copy TLS ClientHello SNI extractor based on RFC 6066 and RFC 9846.
/// Inspired by Rustls
/// Reader: https://github.com/rustls/rustls/blob/main/rustls/src/msgs/codec.rs
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.buf.split_at_checked(len)?;
        self.buf = tail;
        Some(head)
    }

    pub fn read_u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    pub fn read_u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn read_u24(&mut self) -> Option<usize> {
        let b = self.take(3)?;
        Some(((b[0] as usize) << 16) | ((b[1] as usize) << 8) | (b[2] as usize))
    }

    pub fn sub(&mut self, len: usize) -> Option<Self> {
        self.take(len).map(Self::new)
    }

    pub fn sub_u8_len(&mut self) -> Option<Self> {
        let len = self.read_u8()? as usize;
        self.sub(len)
    }

    pub fn sub_u16_len(&mut self) -> Option<Self> {
        let len = self.read_u16()? as usize;
        self.sub(len)
    }

    pub fn sub_u24_len(&mut self) -> Option<Self> {
        let len = self.read_u24()? as usize;
        self.sub(len)
    }

    pub fn skip(&mut self, len: usize) -> Option<()> {
        self.take(len).map(|_| ())
    }

    pub fn skip_u8_len(&mut self) -> Option<()> {
        let len = self.read_u8()? as usize;
        self.skip(len)
    }

    pub fn skip_u16_len(&mut self) -> Option<()> {
        let len = self.read_u16()? as usize;
        self.skip(len)
    }

    pub fn skip_u24_len(&mut self) -> Option<()> {
        let len = self.read_u24()? as usize;
        self.skip(len)
    }
}

pub fn extract_sni<'a>(peeked_bytes: &'a [u8]) -> Option<&'a str> {
    let mut reader = Reader::new(peeked_bytes);

    if reader.read_u8()? != 0x16 {
        return None;
    }
    reader.skip(2)?;
    let mut record = reader.sub_u16_len()?;

    if record.read_u8()? != 0x01 {
        return None;
    }
    let mut client_hello = record.sub_u24_len()?;

    client_hello.skip(2)?;
    client_hello.skip(32)?;
    client_hello.skip_u8_len()?;
    client_hello.skip_u16_len()?;
    client_hello.skip_u8_len()?;

    let mut extensions = client_hello.sub_u16_len()?;

    while let Some(ext_type) = extensions.read_u16() {
        let mut ext = extensions.sub_u16_len()?;

        if ext_type == 0x0000 {
            let mut server_names = ext.sub_u16_len()?;

            while let Some(name_type) = server_names.read_u8() {
                let name_len = server_names.read_u16()? as usize;
                let name = server_names.take(name_len)?;
                if name_type == 0x00 {
                    return core::str::from_utf8(name).ok();
                }
            }
        }
    }
    None
}
