use core::fmt;

use serde::{Deserialize, Serialize};

/// Used as a wrapper for messages to be sent between child and parent processes
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Message {
    IntermediateReady(i32),
    InitReady,
    WriteMapping,
    MappingWritten,
    SeccompNotify,
    SeccompNotifyDone,
    MountFdPlease(MountMsg),
    MountFdReply,
    ExecFailed(String),
    OtherError(String),
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Message::IntermediateReady(pid) => write!(f, "IntermediateReady({})", pid),
            Message::InitReady => write!(f, "InitReady"),
            Message::WriteMapping => write!(f, "WriteMapping"),
            Message::MappingWritten => write!(f, "MappingWritten"),
            Message::SeccompNotify => write!(f, "SeccompNotify"),
            Message::SeccompNotifyDone => write!(f, "SeccompNotifyDone"),
            Message::MountFdPlease(_) => write!(f, "MountFdPlease"),
            Message::MountFdReply => write!(f, "MountFdReply"),
            Message::ExecFailed(s) => write!(f, "ExecFailed({})", s),
            Message::OtherError(s) => write!(f, "OtherError({})", s),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MountMsg {
    pub source: String,
    pub destination: String,
    pub flags: u64,
    pub cleared_flags: u64,
    pub is_bind: bool,
    pub idmap: Option<MountIdMap>,
}
