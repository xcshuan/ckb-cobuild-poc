use ckb_std::error::SysError;
use molecule::error::VerificationError;

#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub enum Error {
    Sys(SysError),
    MoleculeEncoding,
    WrongSighashAll,
    WrongWitnessLayout,
    WrongOtxStart,
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