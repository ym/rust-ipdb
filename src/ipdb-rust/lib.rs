use std::fmt::{self, Display, Formatter};
use std::io;
use std::str;

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use serde::{de, Deserialize};
use serde_json;

use city::CityInfo;

#[cfg(feature = "mmap")]
pub use memmap2::Mmap;
#[cfg(feature = "mmap")]
use memmap2::MmapOptions;
#[cfg(feature = "mmap")]
use std::fs::File;

const IPV4: u16 = 0x01;
const IPV6: u16 = 0x02;

#[derive(Debug, PartialEq, Eq)]
pub enum IPDBError {
    FileSizeError(String),
    MetaDataError(String),
    IOError(String),

    DatabaseError(String),
    OutOfBoundError(usize, usize),
    IPFormatError(String),

    NotSupportedError(String),

    DataNotFoundError(String),
}

impl From<io::Error> for IPDBError {
    fn from(err: io::Error) -> IPDBError {
        // clean up and clean up MaxMindDBError generally
        IPDBError::IOError(err.to_string())
    }
}

impl Display for IPDBError {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            IPDBError::FileSizeError(msg) => write!(fmt, "FileSizeError: {}", msg)?,
            IPDBError::MetaDataError(msg) => write!(fmt, "MetaDataError: {}", msg)?,
            IPDBError::IOError(msg) => write!(fmt, "IOError: {}", msg)?,

            IPDBError::DatabaseError(msg) => write!(fmt, "DatabaseError: {}", msg)?,
            IPDBError::OutOfBoundError(a, b) => write!(fmt, "OutOfBoundError: {} > {}", a, b)?,

            IPDBError::IPFormatError(msg) => write!(fmt, "IPFormatError: {}", msg)?,
            IPDBError::NotSupportedError(msg) => write!(fmt, "NotSupportedError: {}", msg)?,
            IPDBError::DataNotFoundError(msg) => write!(fmt, "DataNotFoundError: {}", msg)?,
        }
        Ok(())
    }
}

// Use default implementation for `std::error::Error`
impl std::error::Error for IPDBError {}

impl de::Error for IPDBError {
    fn custom<T: Display>(msg: T) -> Self {
        IPDBError::DatabaseError(format!("{}", msg))
    }
}

#[derive(Deserialize, Debug)]
pub struct Metadata {
    pub build: i64,
    pub ip_version: u16,
    pub node_count: usize,
    pub total_size: usize,

    pub fields: Vec<String>,
    pub languages: HashMap<String, usize>,
}

#[derive(Debug)]
pub struct Reader<S: AsRef<[u8]>> {
    buf: S,

    pub meta: Metadata,

    pointer_base: usize,
    ipv4_offset: usize,
}

#[cfg(feature = "mmap")]
impl<'de> Reader<Mmap> {
    /// Open an IPDB database file by memory mapping it.
    ///
    /// # Example
    ///
    /// ```
    /// let reader = ipdb::Reader::open_mmap("ipdb.ipdb").unwrap();
    /// ```
    pub fn open_mmap<P: AsRef<Path>>(database: P) -> Result<Reader<Mmap>, IPDBError> {
        let file_read = File::open(database)?;
        let mmap = unsafe { MmapOptions::new().map(&file_read) }?;
        Reader::from_source(mmap)
    }
}

impl Reader<Vec<u8>> {
    /// Open an IPDB database file by loading it into memory.
    ///
    /// # Example
    ///
    /// ```
    /// let reader = ipdb::Reader::open_readfile("ipdb.ipdb").unwrap();
    /// ```
    pub fn open_readfile<P: AsRef<Path>>(database: P) -> Result<Reader<Vec<u8>>, IPDBError> {
        use std::fs;

        let buf: Vec<u8> = fs::read(&database)?;
        Reader::from_source(buf)
    }
}

impl<'de, S: AsRef<[u8]>> Reader<S> {
    pub fn from_source(buf: S) -> Result<Reader<S>, IPDBError> {
        let file_size = buf.as_ref().len();
        let meta_bytes: [u8; 4] = buf.as_ref()[0..4].try_into().map_err(|_| {
            IPDBError::MetaDataError(format!(
                "The file size is too small to be a valid database: {}",
                file_size
            ))
        })?;
        let meta_length = u32::from_be_bytes(meta_bytes) as usize;

        // validate file size
        if file_size < 4 + meta_length {
            return Err(IPDBError::FileSizeError(format!(
                "File size is too small. Expected at least {} bytes, got {}",
                4 + meta_length,
                file_size
            )));
        }

        let meta: Metadata = serde_json::from_slice(&buf.as_ref()[4..4 + meta_length]).unwrap();

        // validate metadata
        if meta.languages.len() == 0 {
            return Err(IPDBError::MetaDataError(
                "No languages specified in metadata.".to_owned(),
            ));
        } else if meta.fields.len() == 0 {
            return Err(IPDBError::MetaDataError(
                "No fields specified in metadata.".to_owned(),
            ));
        }

        // validate if filesize matches metadata
        if file_size != (4 + meta_length + meta.total_size) {
            return Err(IPDBError::FileSizeError(format!(
                "File size does not match metadata. Expected {} bytes, got {}",
                meta.total_size, file_size
            )));
        }

        let mut r = Reader {
            buf,
            meta,
            pointer_base: 4 + meta_length,
            ipv4_offset: 0,
        };
        r.ipv4_offset = r.find_ipv4_start()?;

        Ok(r)
    }

    fn find_ipv4_start(&self) -> Result<usize, IPDBError> {
        let mut node: usize = 0_usize;
        for i in 0_u8..96 {
            if node >= self.meta.node_count {
                break;
            }

            if i >= 80 {
                node = self.read_node(node, 1)?;
            } else {
                node = self.read_node(node, 0)?;
            }
        }

        Ok(node)
    }

    #[inline]
    fn is_ipv4_supported(&self) -> bool {
        (self.meta.ip_version & IPV4) == IPV4
    }

    #[inline]
    fn is_ipv6_supported(&self) -> bool {
        (self.meta.ip_version & IPV6) == IPV6
    }

    fn read_node(&self, node: usize, index: usize) -> Result<usize, IPDBError> {
        let offset = self.pointer_base + node * 8 + index * 4;
        let bytes = &self.buf.as_ref()[offset..offset + 4];
        match u32::from_be_bytes(bytes.try_into().unwrap()) as usize {
            0 => Err(IPDBError::DataNotFoundError("Data not found".to_owned())),
            x => Ok(x),
        }
    }

    fn search_node(&self, ip: Vec<u8>) -> Result<(usize, usize), IPDBError> {
        let bit_count = ip.len() * 8;
        let mut node: usize = 0_usize;

        let mut prefix_len = bit_count;

        if bit_count == 32 {
            node = self.ipv4_offset;
        }

        for i in 0_usize..bit_count {
            if node > self.meta.node_count {
                prefix_len = i;
                break;
            }

            let index = (0xFF & (ip[i >> 3])) >> (7 - (i % 8)) & 1;
            match self.read_node(node, index as usize) {
                Ok(x) => node = x,
                Err(e) => return Err(e),
            }
        }

        if node <= self.meta.node_count {
            return Err(IPDBError::DataNotFoundError("Data not found".to_owned()));
        }

        Ok((node, prefix_len))
    }

    fn resolve_data_pointer(&self, node: usize) -> Result<(usize, usize), IPDBError> {
        let start = self.pointer_base + node - self.meta.node_count + self.meta.node_count * 8;
        if start >= self.meta.total_size {
            return Err(IPDBError::OutOfBoundError(start, self.meta.total_size));
        }

        let size = u32::from_be_bytes([
            0u8,
            0u8,
            self.buf.as_ref()[start],
            self.buf.as_ref()[start + 1],
        ]) as usize;
        let offset = start + 2 + size;

        if offset > self.meta.total_size {
            return Err(IPDBError::OutOfBoundError(offset, self.meta.total_size));
        }

        Ok((start + 2, offset))
    }

    fn parse_data(
        &self,
        start: usize,
        offset: usize,
        skip_columns: usize,
    ) -> Result<CityInfo, IPDBError> {
        use std::str::from_utf8_unchecked;
        let bytes = &self.buf.as_ref()[start..offset];
        let data = unsafe { from_utf8_unchecked(bytes) };

        let sp: Vec<&str> = data.split('\t').skip(skip_columns).collect();

        Ok(sp.into())
    }

    pub fn lookup(&self, address: IpAddr, language: String) -> Result<city::CityInfo, IPDBError> {
        let (info, _prefixlen) = self.lookup_prefix(address, language)?;
        Ok(info)
    }
    /// Lookup the socket address in the opened IPDB database
    ///
    /// Example:
    ///
    /// ```
    /// use ipdb;
    /// use std::net::IpAddr;
    /// use std::str::FromStr;
    ///
    /// let reader = ipdb::Reader::open_readfile("ipdb.ipdb").unwrap();
    ///
    /// let ip: IpAddr = "1.1.1.1".parse().unwrap();
    /// let data = reader.lookup_prefix(ip, "EN".to_owned()).unwrap();
    /// println!("{:#?}", data);
    /// ```
    pub fn lookup_prefix(
        &self,
        address: IpAddr,
        language: String,
    ) -> Result<(city::CityInfo, usize), IPDBError> {
        // check if language is supported
        let skip = match self.meta.languages.get(&language) {
            Some(x) => x,
            None => {
                return Err(IPDBError::NotSupportedError(
                    "Language not supported".to_owned(),
                ))
            }
        };

        // check if ip version is supported
        let ip_bytes = ip_to_bytes(address);
        match address {
            IpAddr::V4(_) => {
                if !self.is_ipv4_supported() {
                    return Err(IPDBError::NotSupportedError(
                        "IPv4 is not supported by this database.".to_owned(),
                    ));
                }
            }
            IpAddr::V6(_) => {
                if !self.is_ipv6_supported() {
                    return Err(IPDBError::NotSupportedError(
                        "IPv6 is not supported by this database.".to_owned(),
                    ));
                }
            }
        }

        let (pointer, prefix_len) = self.search_node(ip_bytes)?;

        let (start, offset) = self.resolve_data_pointer(pointer)?;
        let data = self.parse_data(start, offset, *skip)?;

        Ok((data, prefix_len))
    }
}

pub mod city;

#[inline]
fn ip_to_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}
