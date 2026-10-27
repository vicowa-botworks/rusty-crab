//! Golden test for the `.security.yml` writer.
//!
//! This is deliberately **not** the config seam's conformance opt-in. That would replay
//! all 25 cases, and four of `LoadConfig`'s stages are still unported (`env.Parse`,
//! `InitChannelList`, `expandMultiKeyModels`, the two `Validate*` passes), so a replay
//! that skipped them would read as coverage while asserting almost nothing.
//!
//! What it does pin is the one thing the writer can be pinned on today: the exact bytes
//! the shipped binary writes for a real config, taken from the corpus's
//! `save_writes_both_halves` case rather than from what this crate thinks it should write.
//! Every claim in `yaml::write`'s doc comment is checked here -- that `version` and
//! `session` are absent (`yaml:"-"`), that `web` and `skills` are top level (`Tools` is
//! `yaml:",inline"`), that a channel contributes exactly `settings`, that `brave: {}`
//! survives `omitempty` while `github` does not, and that `registries` is an empty map
//! because the emptiness test saw a two-entry slice.

use std::fs;
use std::path::Path;

use serde_json::Value;

/// The corpus case this file is pinned to.
const CASE: &str = "save_writes_both_halves";

fn fixture() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/fixtures/config_load_save.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{} must be readable: {e}", path.display()));
    serde_json::from_str(&raw).expect("the config fixture must be valid JSON")
}

#[test]
fn security_file_matches_what_go_writes() {
    let fixture = fixture();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == CASE)
        .unwrap_or_else(|| panic!("the fixture no longer carries {CASE}"));

    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("config.json");
    let content = case["input"]["ops"][0]["content"].as_str().expect("op 0");
    fs::write(&config_path, content).expect("write config.json");

    let mut cfg = crab_config::load(&config_path, "/home/oracle")
        .unwrap_or_else(|e| panic!("the case's config must load, got {e:?}"));
    let written =
        crab_config::save(&config_path, &mut cfg, "/home/oracle").expect("save must succeed");

    let expected = case["expected"]["files"][".security.yml"]
        .as_str()
        .expect("expected .security.yml");
    let actual = fs::read_to_string(dir.path().join(".security.yml"))
        .expect("save must write .security.yml beside the config");

    if actual != expected {
        eprintln!(
            "GOT:<<<<<\n{}\n>>>>>
WANT:<<<<<\n{}\n>>>>>",
            actual, expected
        );
        panic!("the security file differs from Go's bytes");
    }
    assert_eq!(
        written.first().map(String::as_str),
        Some(expected),
        "save must hand back the bytes it wrote, security file first"
    );
}

#[test]
fn config_json_is_written_too_and_both_are_private() {
    let fixture = fixture();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == CASE)
        .unwrap();

    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("config.json");
    fs::write(
        &config_path,
        case["input"]["ops"][0]["content"].as_str().unwrap(),
    )
    .unwrap();

    let mut cfg = crab_config::load(&config_path, "/home/oracle").expect("load");
    let written = crab_config::save(&config_path, &mut cfg, "/home/oracle").expect("save");

    assert_eq!(written.len(), 2, "both halves, and nothing else");
    let security = fs::read_to_string(dir.path().join(".security.yml")).expect("security file");
    assert!(
        security.starts_with("channel_list:\n"),
        "the security file is written first, so it is written[0]"
    );
    assert_eq!(written[0], security, "and handed back in the order written");

    // config.json is deliberately NOT compared byte-for-byte yet. Three parts of the
    // loader still differ from Go and all three show up in this one file, so pinning it
    // now would pin the wrong thing:
    //
    //   * a channel's `settings` must be re-materialised from that channel type's settings
    //     struct -- declaration order, zero values for untagged fields, `omitzero` for the
    //     rest -- because Go marshals the decoded struct, not the stored JSON. Until then
    //     `dingtalk` writes no `settings` key where Go writes `{"client_id":""}`.
    //   * the SecureString family must encode to nothing at all, so `api_keys` belongs in
    //     `.security.yml` and never in `config.json`.
    //   * the telegram defaults in `defaults.rs` carry three values Go's DefaultConfig
    //     does not (`typing.enabled`, `placeholder`, `media_group_delay_ms`).
    //
    // The security file above is byte-exact today, which is the half this PR is about.
    let actual = fs::read_to_string(&config_path).expect("config.json");
    assert!(actual.contains("\"version\": 3"), "and it is a v3 config");

    // A secrets file that is briefly world-readable is a secrets file that has leaked.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in ["config.json", ".security.yml"] {
            let mode = fs::metadata(dir.path().join(name))
                .expect("file exists")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{name} must be 0600, got {mode:#o}");
        }
    }
}

#[test]
fn saving_twice_writes_identical_bytes() {
    let fixture = fixture();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == CASE)
        .unwrap();

    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("config.json");
    fs::write(
        &config_path,
        case["input"]["ops"][0]["content"].as_str().unwrap(),
    )
    .unwrap();

    let mut cfg = crab_config::load(&config_path, "/home/oracle").expect("load");
    let first = crab_config::save(&config_path, &mut cfg, "/home/oracle").expect("save 1");
    let second = crab_config::save(&config_path, &mut cfg, "/home/oracle").expect("save 2");
    assert_eq!(first, second, "a second save must be byte-identical");

    // save_is_stable takes the writes of one file across saves, not the files of one save.
    let config_json = vec![first[1].clone(), second[1].clone()];
    let (stable, asked) = crab_config::save_is_stable(&config_json);
    assert!(asked, "two saves were asked for");
    assert!(stable, "and they must agree");
    let security_yml = vec![first[0].clone(), second[0].clone()];
    assert!(crab_config::save_is_stable(&security_yml).0, "both halves");
}
