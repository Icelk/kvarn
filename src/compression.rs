#[allow(unused_imports)]
use crate::prelude::{fs::*, *};

pub enum Compressors {
    Raw(Vec<u8>),
    #[cfg(feature = "br")]
    Brotli(brotli::CompressorWriter<Vec<u8>>),
    #[cfg(feature = "gzip")]
    Gzip(flate2::write::GzEncoder<Vec<u8>>),
}
impl Compressors {
    #[inline]
    pub fn new(vec: Vec<u8>, compressor: &CompressionAlgorithm) -> Self {
        match compressor {
            #[cfg(feature = "br")]
            CompressionAlgorithm::Brotli => Self::brotli(vec),
            #[cfg(feature = "gzip")]
            CompressionAlgorithm::Gzip => Self::gzip(vec),
            CompressionAlgorithm::Identity => Self::raw(vec),
        }
    }
    #[inline]
    pub fn raw(vec: Vec<u8>) -> Self {
        Self::Raw(vec)
    }
    #[inline]
    #[cfg(feature = "br")]
    pub fn brotli(vec: Vec<u8>) -> Self {
        Self::Brotli(brotli::CompressorWriter::new(vec, 4096, 8, 21))
    }
    #[inline]
    #[cfg(feature = "gzip")]
    pub fn gzip(vec: Vec<u8>) -> Self {
        Self::Gzip(flate2::write::GzEncoder::new(
            vec,
            flate2::Compression::fast(),
        ))
    }

    /// Very small footprint.
    ///
    /// On identity compressing, only takes allocation and copying time; only few micro seconds.
    pub fn compress(bytes: &[u8], compressor: &CompressionAlgorithm) -> Vec<u8> {
        match compressor {
            CompressionAlgorithm::Identity => bytes.to_vec(),
            #[cfg(feature = "br")]
            CompressionAlgorithm::Brotli => {
                let buffer = Vec::with_capacity(bytes.len() / 3 + 128);
                let mut c = brotli::CompressorWriter::new(buffer, 4096, 8, 21);
                c.write(bytes).expect("Failed to compress using Brotli!");
                c.flush().expect("Failed to compress using Brotli!");
                let mut buffer = c.into_inner();
                buffer.shrink_to_fit();
                buffer
            }
            #[cfg(feature = "gzip")]
            CompressionAlgorithm::Gzip => {
                let buffer = Vec::with_capacity(bytes.len() / 3 + 128);
                let mut c = flate2::write::GzEncoder::new(buffer, flate2::Compression::fast());
                c.write(bytes).expect("Failed to compress using gzip!");
                let mut buffer = c.finish().expect("Failed to compress using gzip!");
                buffer.shrink_to_fit();
                buffer
            }
        }
    }

    #[inline]
    pub fn write(&mut self, bytes: &[u8]) {
        match self {
            Self::Raw(buffer) => {
                buffer.extend(bytes);
            }
            #[cfg(feature = "br")]
            Self::Brotli(compressor) => {
                if let Err(_err) = compressor.write_all(bytes) {
                    #[cfg(feature = "error-log")]
                    eprintln!("Error compressing: {}", err);
                };
            }
            #[cfg(feature = "gzip")]
            Self::Gzip(compressor) => {
                if let Err(_err) = compressor.write_all(bytes) {
                    #[cfg(feature = "error-log")]
                    eprintln!("Error compressing: {}", err);
                };
            }
        }
    }
    #[inline]
    pub fn finish(self) -> Vec<u8> {
        match self {
            Self::Raw(buffer) => buffer,
            #[cfg(feature = "br")]
            Self::Brotli(compressor) => compressor.into_inner(),
            #[cfg(feature = "gzip")]
            Self::Gzip(compressor) => compressor.finish().unwrap(),
        }
    }
}
impl Debug for Compressors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Raw(_) => "Raw(bytes)",
                #[cfg(feature = "br")]
                Self::Brotli(_) => "Brotli(brotli::CompressorWriter { bytes, internal state })",
                #[cfg(feature = "gzip")]
                Self::Gzip(_) => "Gzip(flate2::write::GzEncoder { bytes, internal state })",
            }
        )
    }
}

/// Types of encoding to use.
///
/// Does not include DEFLATE because of bad support
#[derive(Debug)]
pub enum CompressionAlgorithm {
    #[cfg(feature = "br")]
    Brotli,
    #[cfg(feature = "gzip")]
    Gzip,
    // Deflate,
    Identity,
}
impl CompressionAlgorithm {
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            CompressionAlgorithm::Identity => b"identity",
            #[cfg(feature = "br")]
            CompressionAlgorithm::Brotli => b"br",
            #[cfg(feature = "gzip")]
            CompressionAlgorithm::Gzip => b"gzip",
        }
    }
}
pub fn compression_from_header(header: &str) -> (CompressionAlgorithm, bool) {
    let header = header.to_ascii_lowercase();
    let mut options = parse::format_list_header(&header);

    options.sort_by(|a, b| b.quality.partial_cmp(&a.quality).unwrap());

    let identity = options.iter().position(|option| option == "identity");
    let identity_forbidden = if let Some(identity) = identity {
        options.get(identity).unwrap().quality == 0.0
    } else {
        false
    };

    // If Gzip enabled, prioritize it if quality == 1
    #[cfg(feature = "gzip")]
    if options.is_empty()
        || options.iter().any(|option| {
            option
                == &parse::ValueQualitySet {
                    value: "gzip",
                    quality: 1.0,
                }
        })
    {
        return (CompressionAlgorithm::Gzip, identity_forbidden);
    }
    match options[0].value {
        #[cfg(feature = "gzip")]
        "gzip" => (CompressionAlgorithm::Gzip, identity_forbidden),
        #[cfg(feature = "br")]
        "br" => (CompressionAlgorithm::Brotli, identity_forbidden),
        _ => (CompressionAlgorithm::Identity, identity_forbidden),
    }
}
