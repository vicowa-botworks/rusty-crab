//! Replays the encoder fixtures against `crab-gojson`.
//!
//! The estimators reach the same encoder through a byte *count*, so a one-byte
//! difference there would surface as an off-by-one token estimate and say nothing
//! about which byte moved. This compares the bytes themselves.

use conformance::{go_value::to_go_value, Fixture, Report};
use serde_json::{json, Value};

#[test]
fn encode_matches_go_json_marshal() {
    let fixture = Fixture::load("go_json_encode_parameters.json");
    let mut report = Report::new(&fixture);

    for case in &fixture.cases {
        let input: FixtureParam = case.parse();
        let got = match &input.parameters {
            Some(v) => match crab_gojson::marshal(&to_go_value(v)) {
                Ok(bytes) => json!(String::from_utf8_lossy(&bytes).to_string()),
                // Go's json.Marshal returns "" plus an error in this case, and
                // the fixture records that as null.
                Err(_) => Value::Null,
            },
            // A nil interface marshals to the four bytes `null`; it is not an
            // error and not the same as an absent field.
            None => json!("null"),
        };
        report.record(case, got);
    }

    report.finish(12);
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureParam {
    /// `null` in the fixture means Go's nil interface, which marshals to the
    /// literal `null`; an absent key would mean something else, so this is
    /// `Option` rather than `Value` and the field is required.
    parameters: Option<Value>,
}
