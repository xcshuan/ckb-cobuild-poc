use ckb_std::error::SysError;
use molecule::error::VerificationError;
pub use molecule::lazy_reader::Error as LazyReaderError;

#[derive(Debug)]
pub enum Error {
    Sys(SysError),
    LazyReader(LazyReaderError),
    MoleculeEncoding,
    WrongSighashAll,
    WrongWitnessLayout,
    WrongOtxStart,
    WrongScriptType,
    WrongOtx,
    NoSealFound,
    AuthError,
    ScriptHashAbsent,
    WrongCount,
    InvalidOtxFlag,
}

impl From<SysError> for Error {
    fn from(e: SysError) -> Self {
        Error::Sys(e)
    }
}

impl From<VerificationError> for Error {
    fn from(_: VerificationError) -> Self {
        Error::MoleculeEncoding
    }
}

impl From<LazyReaderError> for Error {
    fn from(e: LazyReaderError) -> Self {
        Error::LazyReader(e)
    }
}
