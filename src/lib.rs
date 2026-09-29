#![forbid(unsafe_code)]

//! Identify by message: one named property of the Message's context, read
//! after the Message exists and called the claim.
//!
//! By the time this runs, default promotion has already put what the content
//! says about its sender into the context — an EDI sender id, a routing key,
//! a `From` the envelope reader lifted. This identifier is told which key
//! names the sender and reads it. The claim is *detected*: it was read out of
//! what is there, nobody presented it, and nothing proves it. That is what
//! ADR-0019 clause 5 means by identity travelling on the message layer, and
//! why a Party recognised only this way is a question for authorization.
//!
//! The key is configuration, in the promoted property vocabulary the content
//! technology chose — `edi.x12.isa06`, `hl7.msh.3`, `amqp.reply-to`. The
//! evidence names it, so the record says which key the claim came from:
//!
//! ```text
//! message.property   the key that was read   evidence
//! ```

use identify::{IdentifyError, MessageIdentifier, Presented};
use message::Message;
use xcore::Mechanism;
use xcore::ScalarValue;

/// The evidence name carrying the key the claim was read from.
pub const PROPERTY: &str = "message.property";

/// Reads one named property of the Message's context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageProperty {
    key: String,
}

impl MessageProperty {
    /// Read the property under `key`.
    #[must_use]
    pub fn new(key: impl Into<String>) -> Self {
        Self { key: key.into() }
    }

    /// The key this identifier reads.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }
}

impl MessageIdentifier for MessageProperty {
    fn mechanism(&self) -> Mechanism {
        xcore::mechanism::message()
    }

    fn identify(&self, message: &Message) -> Result<Option<Presented>, IdentifyError> {
        let value = match message.context().get(&self.key) {
            None | Some(ScalarValue::Null) => return Ok(None),
            Some(ScalarValue::Text(text)) => text.trim().to_string(),
            Some(ScalarValue::Integer(number)) => number.to_string(),
            Some(ScalarValue::Bool(flag)) => flag.to_string(),
            Some(ScalarValue::Decimal(number)) => number.to_string(),
            Some(ScalarValue::Binary(_)) => {
                return Err(IdentifyError::new(format!(
                    "the property `{}` is binary and does not name anyone",
                    self.key
                )));
            }
        };
        if value.is_empty() {
            return Err(IdentifyError::new(format!(
                "the property `{}` is empty and names nobody",
                self.key
            )));
        }

        Ok(Some(
            Presented::detected(self.mechanism(), value).with_evidence(PROPERTY, &self.key),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use context::MessageContext;
    use message::{MessageSection, MessageTreatment};
    use stream::Stream;
    use xcore::{Established, Layer, MessageId, SectionId, StreamId};

    fn message(context: MessageContext) -> Message {
        Message::received(
            MessageId::new(1),
            vec![MessageSection {
                section_id: SectionId::new(2),
                name: None,
                stream: Stream::new(StreamId::new(3), b"ISA*00*".to_vec(), None),
                contract: None,
            }],
            context,
            MessageTreatment::default(),
        )
    }

    #[test]
    fn a_promoted_property_is_presented_as_a_detected_claim_naming_its_key() {
        let context =
            MessageContext::new().with_value("edi.x12.isa06", ScalarValue::Text("PARTYX ".into()));

        let claim = MessageProperty::new("edi.x12.isa06")
            .identify(&message(context))
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "PARTYX");
        assert_eq!(claim.established, Established::Detected);
        assert_eq!(claim.layer(), Layer::Message);
        assert_eq!(claim.mechanism.name(), "message");
        assert_eq!(
            claim.evidence,
            vec![(PROPERTY.to_string(), "edi.x12.isa06".to_string())]
        );
    }

    #[test]
    fn a_message_without_the_property_presents_nothing() {
        let context =
            MessageContext::new().with_value("source.uri", ScalarValue::Text("file:///in".into()));

        assert!(
            MessageProperty::new("edi.x12.isa06")
                .identify(&message(context))
                .expect("read")
                .is_none()
        );
    }

    #[test]
    fn a_numeric_property_is_presented_as_its_text() {
        let context = MessageContext::new().with_value("party.number", ScalarValue::Integer(42));

        let claim = MessageProperty::new("party.number")
            .identify(&message(context))
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "42");
    }

    #[test]
    fn a_binary_property_is_an_error_naming_the_key() {
        let context =
            MessageContext::new().with_value("blob", ScalarValue::Binary(vec![0xff, 0x00]));

        let failure = MessageProperty::new("blob")
            .identify(&message(context))
            .expect_err("binary");

        assert!(failure.message.contains("`blob` is binary"), "{failure}");
    }

    #[test]
    fn an_empty_property_is_an_error_and_not_an_absence() {
        let context = MessageContext::new().with_value("sender", ScalarValue::Text("  ".into()));

        let failure = MessageProperty::new("sender")
            .identify(&message(context))
            .expect_err("empty");

        assert!(failure.message.contains("names nobody"), "{failure}");
    }
}
