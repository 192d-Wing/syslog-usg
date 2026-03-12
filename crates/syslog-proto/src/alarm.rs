// RFC 5674 — Alarms in Syslog
// Maps ITU X.733 alarm concepts to syslog structured data elements.

use compact_str::CompactString;
use smallvec::SmallVec;

use crate::sd_id::SdId;
use crate::severity::Severity;
use crate::structured_data::{SdElement, SdParam, StructuredData};

/// SD-ID for alarm structured data elements (RFC 5674 §2).
const ALARM_SD_ID: &str = "alarm";

// SD parameter names (RFC 5674 §2).
const PARAM_RESOURCE: &str = "resource";
const PARAM_PERC_SEVERITY: &str = "percSeverity";
const PARAM_EVENT_TYPE: &str = "eventType";
const PARAM_PROBABLE_CAUSE: &str = "probableCause";
const PARAM_TREND_INDICATION: &str = "trendIndication";

/// Errors arising from alarm SD element construction or parsing.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AlarmError {
    /// A required field is missing from the alarm SD element.
    #[error("missing required alarm field: {0}")]
    MissingField(&'static str),
    /// A field value is invalid.
    #[error("invalid alarm field '{field}': {reason}")]
    InvalidField {
        /// The field that was invalid.
        field: &'static str,
        /// Description of the problem.
        reason: String,
    },
}

/// Perceived severity of an alarm (RFC 5674 Table 1, ITU X.733).
///
/// Each variant maps to one or more syslog severity levels as specified
/// in RFC 5674 §2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PerceivedSeverity {
    /// Alarm has been cleared. Maps to syslog severity: debug or informational.
    Cleared,
    /// Severity cannot be determined. Maps to syslog severity: critical, alert, or emergency.
    Indeterminate,
    /// Critical alarm. Maps to syslog severity: critical.
    Critical,
    /// Major alarm. Maps to syslog severity: error.
    Major,
    /// Minor alarm. Maps to syslog severity: warning.
    Minor,
    /// Warning alarm. Maps to syslog severity: notice.
    Warning,
}

impl PerceivedSeverity {
    /// Returns the RFC 5674 string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cleared => "cleared",
            Self::Indeterminate => "indeterminate",
            Self::Critical => "critical",
            Self::Major => "major",
            Self::Minor => "minor",
            Self::Warning => "warning",
        }
    }

    /// Maps to the recommended syslog `Severity` per RFC 5674 Table 1.
    ///
    /// Where RFC 5674 allows multiple syslog severities, this returns the
    /// most specific one:
    /// - `Cleared` → `Informational`
    /// - `Indeterminate` → `Critical`
    #[must_use]
    pub const fn to_syslog_severity(self) -> Severity {
        match self {
            Self::Cleared => Severity::Informational,
            Self::Indeterminate => Severity::Critical,
            Self::Critical => Severity::Critical,
            Self::Major => Severity::Error,
            Self::Minor => Severity::Warning,
            Self::Warning => Severity::Notice,
        }
    }
}

impl core::fmt::Display for PerceivedSeverity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::str::FromStr for PerceivedSeverity {
    type Err = AlarmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "cleared" => Ok(Self::Cleared),
            "indeterminate" => Ok(Self::Indeterminate),
            "critical" => Ok(Self::Critical),
            "major" => Ok(Self::Major),
            "minor" => Ok(Self::Minor),
            "warning" => Ok(Self::Warning),
            _ => Err(AlarmError::InvalidField {
                field: PARAM_PERC_SEVERITY,
                reason: format!("unknown perceived severity: {s:?}"),
            }),
        }
    }
}

/// ITU X.733 event type classification (RFC 5674 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItuEventType {
    /// Other (code 1).
    Other,
    /// Communications alarm (code 2).
    CommunicationsAlarm,
    /// Quality of service alarm (code 3).
    QualityOfServiceAlarm,
    /// Processing error alarm (code 4).
    ProcessingErrorAlarm,
    /// Equipment alarm (code 5).
    EquipmentAlarm,
    /// Environmental alarm (code 6).
    EnvironmentalAlarm,
}

impl ItuEventType {
    /// Create from ITU numeric code.
    ///
    /// # Errors
    /// Returns `AlarmError::InvalidField` if the code is not 1-6.
    pub fn from_code(code: u8) -> Result<Self, AlarmError> {
        match code {
            1 => Ok(Self::Other),
            2 => Ok(Self::CommunicationsAlarm),
            3 => Ok(Self::QualityOfServiceAlarm),
            4 => Ok(Self::ProcessingErrorAlarm),
            5 => Ok(Self::EquipmentAlarm),
            6 => Ok(Self::EnvironmentalAlarm),
            _ => Err(AlarmError::InvalidField {
                field: PARAM_EVENT_TYPE,
                reason: format!("unknown ITU event type code: {code} (must be 1-6)"),
            }),
        }
    }

    /// Returns the numeric ITU event type code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Other => 1,
            Self::CommunicationsAlarm => 2,
            Self::QualityOfServiceAlarm => 3,
            Self::ProcessingErrorAlarm => 4,
            Self::EquipmentAlarm => 5,
            Self::EnvironmentalAlarm => 6,
        }
    }

    /// Returns the ITU X.733 descriptive string.
    #[must_use]
    pub const fn as_itu_str(self) -> &'static str {
        match self {
            Self::Other => "other",
            Self::CommunicationsAlarm => "communicationsAlarm",
            Self::QualityOfServiceAlarm => "qualityOfServiceAlarm",
            Self::ProcessingErrorAlarm => "processingErrorAlarm",
            Self::EquipmentAlarm => "equipmentAlarm",
            Self::EnvironmentalAlarm => "environmentalAlarm",
        }
    }
}

impl core::fmt::Display for ItuEventType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_itu_str())
    }
}

/// Trend indication for an alarm (RFC 5674 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrendIndication {
    /// The alarm severity is decreasing.
    LessSevere,
    /// The alarm severity is unchanged.
    NoChange,
    /// The alarm severity is increasing.
    MoreSevere,
}

impl TrendIndication {
    /// Returns the RFC 5674 string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LessSevere => "lessSevere",
            Self::NoChange => "noChange",
            Self::MoreSevere => "moreSevere",
        }
    }
}

impl core::str::FromStr for TrendIndication {
    type Err = AlarmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "lessSevere" => Ok(Self::LessSevere),
            "noChange" => Ok(Self::NoChange),
            "moreSevere" => Ok(Self::MoreSevere),
            _ => Err(AlarmError::InvalidField {
                field: PARAM_TREND_INDICATION,
                reason: format!("unknown trend indication: {s:?}"),
            }),
        }
    }
}

impl core::fmt::Display for TrendIndication {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An alarm as defined by RFC 5674.
///
/// Represents an ITU X.733-style alarm conveyed via syslog structured data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alarm {
    /// The alarming resource (RFC 5674 §2: MUST be present).
    pub resource: CompactString,
    /// Perceived severity of the alarm (RFC 5674 §2: MUST be present).
    pub perceived_severity: PerceivedSeverity,
    /// ITU event type classification (RFC 5674 §2: MUST be present).
    pub event_type: ItuEventType,
    /// Optional probable cause string.
    pub probable_cause: Option<CompactString>,
    /// Optional trend indication.
    pub trend_indication: Option<TrendIndication>,
}

impl Alarm {
    /// Convert this alarm to an SD element suitable for inclusion in a syslog message.
    ///
    /// # Errors
    /// Returns `AlarmError` if the SD-ID cannot be constructed (should not happen
    /// for the well-known "alarm" SD-ID).
    pub fn to_sd_element(&self) -> Result<SdElement, AlarmError> {
        let id = match SdId::new(ALARM_SD_ID) {
            Ok(id) => id,
            Err(e) => {
                return Err(AlarmError::InvalidField {
                    field: "sd-id",
                    reason: e.to_string(),
                });
            }
        };

        let mut params: SmallVec<[SdParam; 4]> = SmallVec::new();

        params.push(SdParam {
            name: CompactString::new(PARAM_RESOURCE),
            value: self.resource.clone(),
        });
        params.push(SdParam {
            name: CompactString::new(PARAM_PERC_SEVERITY),
            value: CompactString::new(self.perceived_severity.as_str()),
        });
        params.push(SdParam {
            name: CompactString::new(PARAM_EVENT_TYPE),
            value: CompactString::new(self.event_type.code().to_string()),
        });

        if let Some(ref cause) = self.probable_cause {
            params.push(SdParam {
                name: CompactString::new(PARAM_PROBABLE_CAUSE),
                value: cause.clone(),
            });
        }

        if let Some(trend) = self.trend_indication {
            params.push(SdParam {
                name: CompactString::new(PARAM_TREND_INDICATION),
                value: CompactString::new(trend.as_str()),
            });
        }

        Ok(SdElement { id, params })
    }

    /// Parse an `Alarm` from an SD element.
    ///
    /// # Errors
    /// Returns `AlarmError::MissingField` if a required parameter is absent,
    /// or `AlarmError::InvalidField` if a parameter value is invalid.
    pub fn from_sd_element(element: &SdElement) -> Result<Self, AlarmError> {
        let resource = match element.param_value(PARAM_RESOURCE) {
            Some(v) => CompactString::new(v),
            None => return Err(AlarmError::MissingField(PARAM_RESOURCE)),
        };

        let perceived_severity = match element.param_value(PARAM_PERC_SEVERITY) {
            Some(v) => v.parse::<PerceivedSeverity>()?,
            None => return Err(AlarmError::MissingField(PARAM_PERC_SEVERITY)),
        };

        let event_type = match element.param_value(PARAM_EVENT_TYPE) {
            Some(v) => {
                let code: u8 = v.parse::<u8>().map_err(|e| AlarmError::InvalidField {
                    field: PARAM_EVENT_TYPE,
                    reason: e.to_string(),
                })?;
                ItuEventType::from_code(code)?
            }
            None => return Err(AlarmError::MissingField(PARAM_EVENT_TYPE)),
        };

        let probable_cause = element
            .param_value(PARAM_PROBABLE_CAUSE)
            .map(CompactString::new);

        let trend_indication = match element.param_value(PARAM_TREND_INDICATION) {
            Some(v) => Some(v.parse::<TrendIndication>()?),
            None => None,
        };

        Ok(Self {
            resource,
            perceived_severity,
            event_type,
            probable_cause,
            trend_indication,
        })
    }

    /// Search structured data for an alarm SD element and attempt to parse it.
    ///
    /// Returns `None` if no element with SD-ID "alarm" is found.
    /// Returns `Some(Ok(alarm))` on successful parse, or `Some(Err(e))` if
    /// the element is present but invalid.
    #[must_use]
    pub fn extract_alarm(sd: &StructuredData) -> Option<Result<Alarm, AlarmError>> {
        sd.find_by_id(ALARM_SD_ID).map(Self::from_sd_element)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── PerceivedSeverity ──────────────────────────────────────────────

    #[test]
    fn perceived_severity_from_str_roundtrip() {
        let variants = [
            PerceivedSeverity::Cleared,
            PerceivedSeverity::Indeterminate,
            PerceivedSeverity::Critical,
            PerceivedSeverity::Major,
            PerceivedSeverity::Minor,
            PerceivedSeverity::Warning,
        ];
        for v in &variants {
            let s = v.as_str();
            let parsed = s.parse::<PerceivedSeverity>();
            assert!(parsed.is_ok(), "failed to parse {s:?}");
            if let Ok(p) = parsed {
                assert_eq!(p, *v);
            }
        }
    }

    #[test]
    fn perceived_severity_cleared_maps_to_informational() {
        assert_eq!(
            PerceivedSeverity::Cleared.to_syslog_severity(),
            Severity::Informational
        );
    }

    #[test]
    fn perceived_severity_indeterminate_maps_to_critical() {
        assert_eq!(
            PerceivedSeverity::Indeterminate.to_syslog_severity(),
            Severity::Critical
        );
    }

    #[test]
    fn perceived_severity_critical_maps_to_critical() {
        assert_eq!(
            PerceivedSeverity::Critical.to_syslog_severity(),
            Severity::Critical
        );
    }

    #[test]
    fn perceived_severity_major_maps_to_error() {
        assert_eq!(
            PerceivedSeverity::Major.to_syslog_severity(),
            Severity::Error
        );
    }

    #[test]
    fn perceived_severity_minor_maps_to_warning() {
        assert_eq!(
            PerceivedSeverity::Minor.to_syslog_severity(),
            Severity::Warning
        );
    }

    #[test]
    fn perceived_severity_warning_maps_to_notice() {
        assert_eq!(
            PerceivedSeverity::Warning.to_syslog_severity(),
            Severity::Notice
        );
    }

    #[test]
    fn perceived_severity_invalid_string() {
        let result = "bogus".parse::<PerceivedSeverity>();
        assert!(result.is_err());
    }

    // ── ItuEventType ──────────────────────────────────────────────────

    #[test]
    fn itu_event_type_from_code_roundtrip() {
        for code in 1u8..=6 {
            let et = ItuEventType::from_code(code);
            assert!(et.is_ok(), "failed for code {code}");
            if let Ok(et) = et {
                assert_eq!(et.code(), code);
            }
        }
    }

    #[test]
    fn itu_event_type_all_codes() {
        let expected = [
            (1, ItuEventType::Other),
            (2, ItuEventType::CommunicationsAlarm),
            (3, ItuEventType::QualityOfServiceAlarm),
            (4, ItuEventType::ProcessingErrorAlarm),
            (5, ItuEventType::EquipmentAlarm),
            (6, ItuEventType::EnvironmentalAlarm),
        ];
        for (code, variant) in &expected {
            let et = ItuEventType::from_code(*code);
            assert!(et.is_ok());
            if let Ok(et) = et {
                assert_eq!(et, *variant);
            }
        }
    }

    #[test]
    fn itu_event_type_invalid_code() {
        assert!(ItuEventType::from_code(0).is_err());
        assert!(ItuEventType::from_code(7).is_err());
        assert!(ItuEventType::from_code(255).is_err());
    }

    #[test]
    fn itu_event_type_as_itu_str() {
        assert_eq!(ItuEventType::Other.as_itu_str(), "other");
        assert_eq!(
            ItuEventType::CommunicationsAlarm.as_itu_str(),
            "communicationsAlarm"
        );
        assert_eq!(
            ItuEventType::EnvironmentalAlarm.as_itu_str(),
            "environmentalAlarm"
        );
    }

    // ── TrendIndication ───────────────────────────────────────────────

    #[test]
    fn trend_indication_roundtrip() {
        let variants = [
            TrendIndication::LessSevere,
            TrendIndication::NoChange,
            TrendIndication::MoreSevere,
        ];
        for v in &variants {
            let s = v.as_str();
            let parsed = s.parse::<TrendIndication>();
            assert!(parsed.is_ok(), "failed to parse {s:?}");
            if let Ok(p) = parsed {
                assert_eq!(p, *v);
            }
        }
    }

    #[test]
    fn trend_indication_invalid() {
        assert!("unknown".parse::<TrendIndication>().is_err());
    }

    // ── Alarm roundtrip (all fields) ──────────────────────────────────

    fn make_full_alarm() -> Alarm {
        Alarm {
            resource: CompactString::new("linkDown:eth0"),
            perceived_severity: PerceivedSeverity::Major,
            event_type: ItuEventType::CommunicationsAlarm,
            probable_cause: Some(CompactString::new("lossOfSignal")),
            trend_indication: Some(TrendIndication::MoreSevere),
        }
    }

    fn make_minimal_alarm() -> Alarm {
        Alarm {
            resource: CompactString::new("cpu:host42"),
            perceived_severity: PerceivedSeverity::Warning,
            event_type: ItuEventType::ProcessingErrorAlarm,
            probable_cause: None,
            trend_indication: None,
        }
    }

    #[test]
    fn alarm_to_sd_element_roundtrip_full() {
        let alarm = make_full_alarm();
        let elem = alarm.to_sd_element();
        assert!(elem.is_ok(), "to_sd_element failed: {elem:?}");
        if let Ok(elem) = elem {
            assert_eq!(elem.id.as_str(), ALARM_SD_ID);
            let parsed = Alarm::from_sd_element(&elem);
            assert!(parsed.is_ok(), "from_sd_element failed: {parsed:?}");
            if let Ok(parsed) = parsed {
                assert_eq!(parsed, alarm);
            }
        }
    }

    #[test]
    fn alarm_to_sd_element_roundtrip_minimal() {
        let alarm = make_minimal_alarm();
        let elem = alarm.to_sd_element();
        assert!(elem.is_ok(), "to_sd_element failed: {elem:?}");
        if let Ok(elem) = elem {
            let parsed = Alarm::from_sd_element(&elem);
            assert!(parsed.is_ok(), "from_sd_element failed: {parsed:?}");
            if let Ok(parsed) = parsed {
                assert_eq!(parsed, alarm);
            }
        }
    }

    #[test]
    fn alarm_with_all_optional_fields() {
        let alarm = make_full_alarm();
        let elem = alarm.to_sd_element();
        assert!(elem.is_ok());
        if let Ok(elem) = elem {
            assert!(elem.param_value(PARAM_PROBABLE_CAUSE).is_some());
            assert!(elem.param_value(PARAM_TREND_INDICATION).is_some());
        }
    }

    #[test]
    fn alarm_with_no_optional_fields() {
        let alarm = make_minimal_alarm();
        let elem = alarm.to_sd_element();
        assert!(elem.is_ok());
        if let Ok(elem) = elem {
            assert!(elem.param_value(PARAM_PROBABLE_CAUSE).is_none());
            assert!(elem.param_value(PARAM_TREND_INDICATION).is_none());
            // Should have exactly 3 params (required only)
            assert_eq!(elem.params.len(), 3);
        }
    }

    // ── extract_alarm ─────────────────────────────────────────────────

    #[test]
    fn extract_alarm_finds_alarm_in_sd() {
        let alarm = make_full_alarm();
        let elem = match alarm.to_sd_element() {
            Ok(e) => e,
            Err(_) => return,
        };

        // Build structured data with the alarm element plus another element
        let other_id = match SdId::new("origin") {
            Ok(id) => id,
            Err(_) => return,
        };
        let other_elem = SdElement {
            id: other_id,
            params: SmallVec::new(),
        };

        let sd = StructuredData(SmallVec::from_vec(vec![other_elem, elem]));
        let extracted = Alarm::extract_alarm(&sd);
        assert!(extracted.is_some());
        if let Some(result) = extracted {
            assert!(result.is_ok());
            if let Ok(extracted_alarm) = result {
                assert_eq!(extracted_alarm, alarm);
            }
        }
    }

    #[test]
    fn extract_alarm_returns_none_when_missing() {
        let sd = StructuredData::nil();
        assert!(Alarm::extract_alarm(&sd).is_none());
    }

    #[test]
    fn extract_alarm_returns_none_with_other_elements() {
        let id = match SdId::new("origin") {
            Ok(id) => id,
            Err(_) => return,
        };
        let elem = SdElement {
            id,
            params: SmallVec::new(),
        };
        let sd = StructuredData(SmallVec::from_elem(elem, 1));
        assert!(Alarm::extract_alarm(&sd).is_none());
    }

    // ── Error cases ───────────────────────────────────────────────────

    #[test]
    fn missing_resource_field() {
        let id = match SdId::new(ALARM_SD_ID) {
            Ok(id) => id,
            Err(_) => return,
        };
        let elem = SdElement {
            id,
            params: SmallVec::from_vec(vec![
                SdParam {
                    name: CompactString::new(PARAM_PERC_SEVERITY),
                    value: CompactString::new("major"),
                },
                SdParam {
                    name: CompactString::new(PARAM_EVENT_TYPE),
                    value: CompactString::new("2"),
                },
            ]),
        };
        let result = Alarm::from_sd_element(&elem);
        assert!(result.is_err());
        assert!(matches!(result, Err(AlarmError::MissingField("resource"))));
    }

    #[test]
    fn missing_perceived_severity_field() {
        let id = match SdId::new(ALARM_SD_ID) {
            Ok(id) => id,
            Err(_) => return,
        };
        let elem = SdElement {
            id,
            params: SmallVec::from_vec(vec![
                SdParam {
                    name: CompactString::new(PARAM_RESOURCE),
                    value: CompactString::new("test"),
                },
                SdParam {
                    name: CompactString::new(PARAM_EVENT_TYPE),
                    value: CompactString::new("1"),
                },
            ]),
        };
        let result = Alarm::from_sd_element(&elem);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(AlarmError::MissingField("percSeverity"))
        ));
    }

    #[test]
    fn missing_event_type_field() {
        let id = match SdId::new(ALARM_SD_ID) {
            Ok(id) => id,
            Err(_) => return,
        };
        let elem = SdElement {
            id,
            params: SmallVec::from_vec(vec![
                SdParam {
                    name: CompactString::new(PARAM_RESOURCE),
                    value: CompactString::new("test"),
                },
                SdParam {
                    name: CompactString::new(PARAM_PERC_SEVERITY),
                    value: CompactString::new("critical"),
                },
            ]),
        };
        let result = Alarm::from_sd_element(&elem);
        assert!(result.is_err());
        assert!(matches!(result, Err(AlarmError::MissingField("eventType"))));
    }

    #[test]
    fn invalid_perceived_severity_value() {
        let id = match SdId::new(ALARM_SD_ID) {
            Ok(id) => id,
            Err(_) => return,
        };
        let elem = SdElement {
            id,
            params: SmallVec::from_vec(vec![
                SdParam {
                    name: CompactString::new(PARAM_RESOURCE),
                    value: CompactString::new("test"),
                },
                SdParam {
                    name: CompactString::new(PARAM_PERC_SEVERITY),
                    value: CompactString::new("bogus"),
                },
                SdParam {
                    name: CompactString::new(PARAM_EVENT_TYPE),
                    value: CompactString::new("1"),
                },
            ]),
        };
        let result = Alarm::from_sd_element(&elem);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(AlarmError::InvalidField {
                field: "percSeverity",
                ..
            })
        ));
    }

    #[test]
    fn invalid_event_type_value() {
        let id = match SdId::new(ALARM_SD_ID) {
            Ok(id) => id,
            Err(_) => return,
        };
        let elem = SdElement {
            id,
            params: SmallVec::from_vec(vec![
                SdParam {
                    name: CompactString::new(PARAM_RESOURCE),
                    value: CompactString::new("test"),
                },
                SdParam {
                    name: CompactString::new(PARAM_PERC_SEVERITY),
                    value: CompactString::new("critical"),
                },
                SdParam {
                    name: CompactString::new(PARAM_EVENT_TYPE),
                    value: CompactString::new("99"),
                },
            ]),
        };
        let result = Alarm::from_sd_element(&elem);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(AlarmError::InvalidField {
                field: "eventType",
                ..
            })
        ));
    }
}
