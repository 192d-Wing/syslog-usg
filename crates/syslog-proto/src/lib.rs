#![doc = "Core syslog protocol types implementing the RFC 5424 message model.\n\nThis crate provides the canonical in-memory representation of syslog messages,\nincluding facility, severity, priority, structured data, and all header fields\nas defined by RFC 5424 (The Syslog Protocol) and RFC 5427 (Textual Conventions\nfor Syslog Management)."]

mod app_name;
mod facility;
mod hostname;
mod message;
mod message_id;
mod pri;
mod proc_id;
mod sd_id;
mod severity;
mod structured_data;
mod timestamp;

pub use app_name::AppName;
pub use facility::{Facility, InvalidFacility, UnknownFacilityName};
pub use hostname::Hostname;
pub use message::SyslogMessage;
pub use message_id::MessageId;
pub use pri::{InvalidPri, Pri};
pub use proc_id::ProcId;
pub use sd_id::SdId;
pub use severity::{InvalidSeverity, Severity, UnknownSeverityName};
pub use structured_data::{SdElement, SdParam, StructuredData};
pub use timestamp::SyslogTimestamp;
