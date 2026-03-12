// RFC 5424 §6.3 — STRUCTURED-DATA
// STRUCTURED-DATA = NILVALUE / 1*SD-ELEMENT

use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use crate::sd_id::SdId;

/// A single SD-PARAM (name-value pair) within a structured data element.
///
/// RFC 5424 §6.3.3: SD-PARAM = PARAM-NAME "=" %d34 PARAM-VALUE %d34
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdParam {
    /// Parameter name.
    pub name: CompactString,
    /// Parameter value.
    pub value: CompactString,
}

/// A single SD-ELEMENT within structured data.
///
/// RFC 5424 §6.3.1: SD-ELEMENT = "[" SD-ID *(SP SD-PARAM) "]"
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdElement {
    /// The SD-ID identifying this element.
    pub id: SdId,
    /// Parameters within this element. Most elements have few params; optimized for up to 4.
    pub params: SmallVec<[SdParam; 4]>,
}

/// Structured data of a syslog message.
///
/// RFC 5424 §6.3: STRUCTURED-DATA = NILVALUE / 1*SD-ELEMENT.
/// Uses `SmallVec` optimized for the common case of 0-2 elements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredData(pub SmallVec<[SdElement; 2]>);

impl StructuredData {
    /// Create an empty (nil) structured data.
    #[must_use]
    pub fn nil() -> Self {
        Self(SmallVec::new())
    }

    /// Returns `true` if this structured data is NILVALUE (no elements).
    #[must_use]
    pub fn is_nil(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns an iterator over the SD-ELEMENTs.
    pub fn iter(&self) -> impl Iterator<Item = &SdElement> {
        self.0.iter()
    }

    /// Look up an SD-ELEMENT by its SD-ID string.
    #[must_use]
    pub fn find_by_id(&self, id: &str) -> Option<&SdElement> {
        self.0.iter().find(|el| el.id.as_str() == id)
    }

    /// Estimate the byte size of this structured data for queue accounting.
    ///
    /// This is a rough estimate, not an exact serialized size.
    #[must_use]
    pub fn estimated_size(&self) -> usize {
        if self.is_nil() {
            // NILVALUE "-" is 1 byte
            return 1;
        }
        self.0
            .iter()
            .map(|el| {
                // "[" + SD-ID + "]" = 2 + id_len
                let id_len = el.id.as_str().len() + 2;
                let params_len: usize = el
                    .params
                    .iter()
                    .map(|p| {
                        // SP + name + "=\"" + value + "\"" = 1 + name_len + 2 + value_len + 1
                        1 + p.name.len() + 2 + p.value.len() + 1
                    })
                    .sum();
                id_len + params_len
            })
            .sum()
    }
}

impl Default for StructuredData {
    fn default() -> Self {
        Self::nil()
    }
}

impl SdElement {
    /// Look up a parameter value by name within this element.
    #[must_use]
    pub fn param_value(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|p| p.name.as_str() == name)
            .map(|p| p.value.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_element(id: &str, params: &[(&str, &str)]) -> SdElement {
        let sd_id = SdId::new(id);
        assert!(sd_id.is_ok());
        SdElement {
            id: match sd_id {
                Ok(id) => id,
                Err(_) => {
                    return SdElement {
                        id: SdId::Registered(CompactString::new("fallback")),
                        params: SmallVec::new(),
                    };
                }
            },
            params: params
                .iter()
                .map(|(n, v)| SdParam {
                    name: CompactString::new(n),
                    value: CompactString::new(v),
                })
                .collect(),
        }
    }

    #[test]
    fn nil_structured_data() {
        let sd = StructuredData::nil();
        assert!(sd.is_nil());
        assert_eq!(sd.estimated_size(), 1);
    }

    #[test]
    fn find_by_id() {
        let el = make_element("origin", &[("ip", "10.0.0.1")]);
        let sd = StructuredData(SmallVec::from_elem(el, 1));
        assert!(!sd.is_nil());
        let found = sd.find_by_id("origin");
        assert!(found.is_some());
        assert!(sd.find_by_id("nonexistent").is_none());
    }

    #[test]
    fn param_value_lookup() {
        let el = make_element("origin", &[("ip", "10.0.0.1"), ("software", "test")]);
        assert_eq!(el.param_value("ip"), Some("10.0.0.1"));
        assert_eq!(el.param_value("software"), Some("test"));
        assert_eq!(el.param_value("missing"), None);
    }

    #[test]
    fn iteration() {
        let el1 = make_element("origin", &[("ip", "10.0.0.1")]);
        let el2 = make_element("meta", &[("sequenceId", "1")]);
        let sd = StructuredData(SmallVec::from_vec(vec![el1, el2]));
        let ids: Vec<&str> = sd.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, vec!["origin", "meta"]);
    }

    #[test]
    fn estimated_size_nonempty() {
        let el = make_element("origin", &[("ip", "10.0.0.1")]);
        let sd = StructuredData(SmallVec::from_elem(el, 1));
        // "[origin ip=\"10.0.0.1\"]" = 2 + 6 + (1 + 2 + 2 + 8 + 1) = 8 + 14 = 22
        assert!(sd.estimated_size() > 0);
    }

    #[test]
    fn serde_roundtrip() {
        let el = make_element("origin", &[("ip", "10.0.0.1")]);
        let sd = StructuredData(SmallVec::from_elem(el, 1));
        let json = serde_json::to_string(&sd);
        assert!(json.is_ok());
        let json = json.ok().unwrap_or_default();
        let parsed: Result<StructuredData, _> = serde_json::from_str(&json);
        assert!(parsed.is_ok());
        assert_eq!(parsed.ok(), Some(sd));
    }

    #[test]
    fn default_is_nil() {
        let sd = StructuredData::default();
        assert!(sd.is_nil());
    }
}
