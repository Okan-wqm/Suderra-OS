// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use schema_compat::{
    object, parse_positive_int, path_role, positive_int_string, require_schema, require_string,
    required_schema_for_path, safe_rel_path, sha256_file, validate_git_sha, validate_sha256,
    OPERATOR_EVIDENCE_INGRESS_SCHEMA, RELEASE_TAG_BINDING_SCHEMA,
};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const REQUIRED_TAG_FIELDS: &[(&str, &str)] = &[
    ("version", "Suderra-Version"),
    ("source_sha", "Suderra-Source-SHA"),
    ("source_build_run_id", "Suderra-Source-Build-Run-ID"),
    (
        "source_build_run_attempt",
        "Suderra-Source-Build-Run-Attempt",
    ),
    ("preflight_run_id", "Suderra-Preflight-Run-ID"),
    ("preflight_run_attempt", "Suderra-Preflight-Run-Attempt"),
    ("preflight_artifact_id", "Suderra-Preflight-Artifact-ID"),
    ("ingress_manifest_sha256", "Suderra-Ingress-Manifest-SHA256"),
];

const ALLOWED_OPERATOR_DIRS: &[&str] = &[
    "release-lab-input",
    "release-approvals",
    "release-reproducibility",
    "release-governance",
];

const FORBIDDEN_OPERATOR_DIRS: &[&str] = &[
    "build-artifacts",
    "release-inputs",
    "release-security",
    "release-evidence-generated",
    "signed-release",
];

#[derive(Parser)]
#[command(
    name = "release-core",
    about = "Shadow Rust validators for Suderra release contracts"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate release tag binding metadata.
    TagBinding(TagBindingArgs),
    /// Validate operator evidence ingress manifests.
    OperatorEvidence(OperatorEvidenceArgs),
}

#[derive(Args)]
struct TagBindingArgs {
    #[command(subcommand)]
    command: TagBindingCommand,
}

#[derive(Subcommand)]
enum TagBindingCommand {
    /// Parse an annotated tag message into release-tag-binding JSON.
    Parse(ParseTagArgs),
    /// Validate the preflight run and artifact named by a tag binding.
    ValidateRun(ValidateRunArgs),
    /// Validate an ingress manifest digest against a tag binding.
    ValidateIngress(ValidateIngressArgs),
    /// Cross-bind tag, release input binding, and ingress metadata.
    ValidateCrossBinding(ValidateCrossBindingArgs),
}

#[derive(Args)]
struct ParseTagArgs {
    #[arg(long)]
    version: String,
    #[arg(long)]
    source_sha: String,
    #[arg(long)]
    annotation: PathBuf,
    #[arg(long)]
    output_json: Option<PathBuf>,
    #[arg(long)]
    trusted_fingerprints: Option<String>,
    #[arg(long)]
    trusted_fingerprints_file: Option<PathBuf>,
}

#[derive(Args)]
struct ValidateRunArgs {
    #[arg(long)]
    binding: PathBuf,
    #[arg(long)]
    run_json: PathBuf,
    #[arg(long)]
    artifacts_json: PathBuf,
    #[arg(long)]
    repository: String,
    #[arg(long)]
    output_artifact_name: Option<PathBuf>,
}

#[derive(Args)]
struct ValidateIngressArgs {
    #[arg(long)]
    binding: PathBuf,
    #[arg(long)]
    ingress_manifest: PathBuf,
}

#[derive(Args)]
struct ValidateCrossBindingArgs {
    #[arg(long)]
    binding: PathBuf,
    #[arg(long)]
    release_input: PathBuf,
    #[arg(long)]
    ingress_manifest: PathBuf,
}

#[derive(Args)]
struct OperatorEvidenceArgs {
    #[command(subcommand)]
    command: OperatorEvidenceCommand,
}

#[derive(Subcommand)]
enum OperatorEvidenceCommand {
    /// Validate an evidence-ingress-manifest.json artifact.
    Validate(ValidateOperatorEvidenceArgs),
}

#[derive(Args)]
struct ValidateOperatorEvidenceArgs {
    manifest: PathBuf,
    #[arg(long)]
    input_root: Option<PathBuf>,
    #[arg(long)]
    expected_version: Option<String>,
    #[arg(long)]
    expected_source_sha: Option<String>,
    #[arg(long)]
    expected_source_image_build_run_id: Option<String>,
    #[arg(long)]
    expected_source_image_build_run_attempt: Option<String>,
    #[arg(long)]
    allow_preflight_context: bool,
    #[arg(long)]
    require_signature: bool,
    #[arg(long)]
    certificate_identity: Option<String>,
    #[arg(long)]
    certificate_oidc_issuer: Option<String>,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::TagBinding(args) => match args.command {
            TagBindingCommand::Parse(args) => parse_tag_binding(args),
            TagBindingCommand::ValidateRun(args) => validate_tag_run(args),
            TagBindingCommand::ValidateIngress(args) => validate_tag_ingress(args),
            TagBindingCommand::ValidateCrossBinding(args) => validate_cross_binding(args),
        },
        Commands::OperatorEvidence(args) => match args.command {
            OperatorEvidenceCommand::Validate(args) => validate_operator_evidence(args),
        },
    }
}

fn read_json(path: &Path) -> Result<Value> {
    let text =
        fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("cannot parse JSON {}", path.display()))
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    let text = schema_compat::sorted_json_string_with_newline(value)?;
    fs::write(path, text).with_context(|| format!("cannot write {}", path.display()))
}

fn parse_tag_binding(args: ParseTagArgs) -> Result<()> {
    validate_version(&args.version)?;
    validate_git_sha(&args.source_sha, "--source-sha").map_err(anyhow::Error::msg)?;
    let annotation = fs::read_to_string(&args.annotation)
        .with_context(|| format!("cannot read {}", args.annotation.display()))?;
    let mut binding = parse_annotation(&annotation)?;
    require_binding_field(&binding, "version")?;
    require_binding_field(&binding, "source_sha")?;
    if string_field(&binding, "version")? != args.version {
        bail!("Suderra-Version does not match --version");
    }
    if string_field(&binding, "source_sha")? != args.source_sha {
        bail!("Suderra-Source-SHA does not match --source-sha");
    }
    validate_binding_object(&binding)?;
    let trusted = trusted_fingerprints(
        args.trusted_fingerprints.as_deref(),
        args.trusted_fingerprints_file.as_deref(),
    )?;
    if !trusted.is_empty() {
        let signer = verify_tag_signature(&args.version, &trusted)?;
        binding.insert("tag_signer_fingerprint".to_string(), Value::String(signer));
    }
    let output = Value::Object(binding);
    if let Some(path) = args.output_json {
        write_json(&path, &output)?;
    } else {
        print!(
            "{}",
            schema_compat::sorted_json_string_with_newline(&output)?
        );
    }
    Ok(())
}

fn parse_annotation(annotation: &str) -> Result<Map<String, Value>> {
    let mut fields: BTreeMap<&'static str, String> = BTreeMap::new();
    let mut marker_count = 0_u32;
    for line in annotation.lines() {
        let Some((raw_key, raw_value)) = line.split_once(':') else {
            continue;
        };
        let key = raw_key.trim();
        let value = raw_value.trim();
        if key == "Suderra-Release-Binding" {
            marker_count += 1;
            if value != "v1" {
                bail!("Suderra-Release-Binding must be v1");
            }
            continue;
        }
        for (field, annotation_key) in REQUIRED_TAG_FIELDS {
            if key == *annotation_key && fields.insert(field, value.to_string()).is_some() {
                bail!("duplicate tag binding field: {annotation_key}");
            }
        }
    }
    if marker_count != 1 {
        bail!("annotated release tag must include exactly one Suderra-Release-Binding: v1 line");
    }
    let missing: Vec<&str> = REQUIRED_TAG_FIELDS
        .iter()
        .filter_map(|(field, annotation_key)| {
            (!fields.contains_key(field)).then_some(*annotation_key)
        })
        .collect();
    if !missing.is_empty() {
        bail!(
            "annotated release tag is missing binding fields: {}",
            missing.join(", ")
        );
    }
    let mut object = Map::new();
    object.insert(
        "schema_version".to_string(),
        Value::String(RELEASE_TAG_BINDING_SCHEMA.to_string()),
    );
    for (field, value) in fields {
        object.insert(field.to_string(), Value::String(value));
    }
    Ok(object)
}

fn validate_tag_run(args: ValidateRunArgs) -> Result<()> {
    let binding_value = read_json(&args.binding)?;
    let binding = object(&binding_value, "tag binding").map_err(anyhow::Error::msg)?;
    validate_binding_object(binding)?;
    let run_value = read_json(&args.run_json)?;
    let run = object(&run_value, "preflight run").map_err(anyhow::Error::msg)?;

    expect_number_string(
        run.get("id"),
        "preflight run id",
        string_field(binding, "preflight_run_id")?,
    )?;
    expect_number_string(
        run.get("run_attempt"),
        "preflight run run_attempt",
        string_field(binding, "preflight_run_attempt")?,
    )?;
    expect_string(run, "head_sha", string_field(binding, "source_sha")?)?;
    expect_string(run, "head_branch", "main")?;
    expect_string(run, "status", "completed")?;
    expect_string(run, "conclusion", "success")?;
    expect_string(run, "name", "Release Preflight")?;
    expect_string(run, "event", "workflow_dispatch")?;
    expect_string(run, "path", ".github/workflows/release-preflight.yml")?;
    let repo = run
        .get("head_repository")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("preflight run head_repository must be an object"))?;
    expect_string(repo, "full_name", &args.repository)?;

    let artifacts_value = read_json(&args.artifacts_json)?;
    let artifacts = object(&artifacts_value, "preflight artifacts").map_err(anyhow::Error::msg)?;
    let items = artifacts
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("preflight artifacts JSON must include artifacts list"))?;
    let expected_name = expected_preflight_artifact_name(binding)?;
    let mut matches = Vec::new();
    for item in items {
        if item
            .as_object()
            .and_then(|object| object.get("name"))
            .and_then(Value::as_str)
            == Some(expected_name.as_str())
        {
            matches.push(item);
        }
    }
    if matches.len() != 1 {
        bail!(
            "expected exactly one preflight artifact named {}, got {}",
            expected_name,
            matches.len()
        );
    }
    let artifact = matches[0]
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("preflight artifact entry must be an object"))?;
    expect_number_string(
        artifact.get("id"),
        "preflight artifact id",
        string_field(binding, "preflight_artifact_id")?,
    )?;
    if artifact.get("expired").and_then(Value::as_bool) == Some(true) {
        bail!("preflight artifact is expired");
    }
    let size = artifact
        .get("size_in_bytes")
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow::anyhow!("preflight artifact must have a positive size"))?;
    if size <= 0 {
        bail!("preflight artifact must have a positive size");
    }
    if let Some(path) = args.output_artifact_name {
        fs::write(&path, format!("{expected_name}\n"))
            .with_context(|| format!("cannot write {}", path.display()))?;
    }
    Ok(())
}

fn validate_tag_ingress(args: ValidateIngressArgs) -> Result<()> {
    let binding_value = read_json(&args.binding)?;
    let binding = object(&binding_value, "tag binding").map_err(anyhow::Error::msg)?;
    validate_binding_object(binding)?;
    let expected = string_field(binding, "ingress_manifest_sha256")?;
    let actual = sha256_file(&args.ingress_manifest)
        .with_context(|| format!("cannot hash {}", args.ingress_manifest.display()))?;
    if actual != expected {
        bail!(
            "downloaded ingress manifest sha256 does not match tag binding: expected {}, got {}",
            expected,
            actual
        );
    }
    Ok(())
}

fn validate_cross_binding(args: ValidateCrossBindingArgs) -> Result<()> {
    let binding_value = read_json(&args.binding)?;
    let binding = object(&binding_value, "tag binding").map_err(anyhow::Error::msg)?;
    validate_binding_object(binding)?;
    let release_value = read_json(&args.release_input)?;
    let release_input =
        object(&release_value, "release input binding").map_err(anyhow::Error::msg)?;
    let ingress_value = read_json(&args.ingress_manifest)?;
    let ingress = object(&ingress_value, "ingress manifest").map_err(anyhow::Error::msg)?;

    let mut failures = Vec::new();
    let field_pairs = [
        ("version", "version"),
        ("source_sha", "source_sha"),
        ("source_build_run_id", "source_run_id"),
        ("source_build_run_attempt", "source_run_attempt"),
    ];
    for (tag_field, release_field) in field_pairs {
        let expected = string_field(binding, tag_field)?;
        if value_as_string(release_input.get(release_field)) != Some(expected.to_string()) {
            failures.push(format!(
                "release input {release_field} must match tag {tag_field}"
            ));
        }
        if value_as_string(ingress.get(release_field)) != Some(expected.to_string()) {
            failures.push(format!(
                "ingress {release_field} must match tag {tag_field}"
            ));
        }
    }
    let profile = expected_profile(string_field(binding, "version")?);
    if release_input.get("profile").and_then(Value::as_str) != Some(profile) {
        failures.push(format!("release input profile must be {profile}"));
    }
    if ingress.get("profile").and_then(Value::as_str) != Some(profile) {
        failures.push(format!("ingress profile must be {profile}"));
    }
    for field in [
        "build_workflow_name",
        "matrix_sha256",
        "buildroot_source_identity_schema_version",
        "buildroot_index_sha",
        "buildroot_upstream_ref",
        "buildroot_source_mode",
        "buildroot_patchset_sha256",
        "buildroot_patch_files",
        "buildroot_effective_source_id",
        "buildroot_applied_diff_sha256",
        "buildroot_expected_patched",
        "buildroot_rust_version",
        "buildroot_rust_bin_version",
        "buildroot_expected_diff_sha256",
        "buildroot_staged_diff_sha256",
        "buildroot_worktree_diff_sha256",
        "suderra_source_sha",
        "suderra_external_tree_sha256",
        "suderra_external_dirty_paths",
        "suderra_release_source_id",
    ] {
        if (release_input.contains_key(field) || ingress.contains_key(field))
            && release_input.get(field) != ingress.get(field)
        {
            failures.push(format!("ingress {field} must match release input binding"));
        }
    }
    let actual = sha256_file(&args.ingress_manifest)
        .with_context(|| format!("cannot hash {}", args.ingress_manifest.display()))?;
    if actual != string_field(binding, "ingress_manifest_sha256")? {
        failures.push("ingress manifest sha256 must match tag binding".to_string());
    }
    if !failures.is_empty() {
        bail!("{}", failures.join("; "));
    }
    Ok(())
}

fn validate_operator_evidence(args: ValidateOperatorEvidenceArgs) -> Result<()> {
    let manifest_value = read_json(&args.manifest)?;
    let manifest =
        object(&manifest_value, "evidence ingress manifest").map_err(anyhow::Error::msg)?;
    let mut failures = Vec::new();
    push_err(
        &mut failures,
        require_schema(manifest, OPERATOR_EVIDENCE_INGRESS_SCHEMA),
    );

    let version = match require_string(manifest, "version") {
        Ok(version) => {
            push_any(&mut failures, validate_version(version));
            version.to_string()
        }
        Err(error) => {
            failures.push(error);
            String::new()
        }
    };
    let source_sha = match require_string(manifest, "source_sha") {
        Ok(source_sha) => {
            push_err(&mut failures, validate_git_sha(source_sha, "$.source_sha"));
            source_sha.to_string()
        }
        Err(error) => {
            failures.push(error);
            String::new()
        }
    };

    if let Some(expected) = args.expected_version.as_deref() {
        if version != expected {
            failures.push(format!("$.version: must match {expected}"));
        }
    }
    if let Some(expected) = args.expected_source_sha.as_deref() {
        if source_sha != expected {
            failures.push(format!("$.source_sha: must match {expected}"));
        }
    }

    validate_run_id_match(
        &mut failures,
        manifest,
        "source_image_build_run_id",
        args.expected_source_image_build_run_id.as_deref(),
    );
    validate_run_id_match(
        &mut failures,
        manifest,
        "source_image_build_run_attempt",
        args.expected_source_image_build_run_attempt.as_deref(),
    );
    validate_producer(&mut failures, manifest);
    validate_operator_bundle(&mut failures, manifest);
    validate_operator_window(&mut failures, manifest);

    let mut manifest_paths = BTreeSet::new();
    validate_operator_files(
        &mut failures,
        manifest,
        args.input_root.as_deref(),
        &version,
        &mut manifest_paths,
    );
    validate_required_paths(&mut failures, manifest, &manifest_paths);
    if let Some(input_root) = args.input_root.as_deref() {
        validate_input_root(
            &mut failures,
            input_root,
            &version,
            &manifest_paths,
            args.allow_preflight_context,
        );
    }
    if args.require_signature {
        validate_signature(
            &mut failures,
            &args.manifest,
            args.certificate_identity.as_deref(),
            args.certificate_oidc_issuer.as_deref(),
        );
    }

    if !failures.is_empty() {
        bail!("{}", failures.join("; "));
    }
    println!(
        "validated operator evidence ingress manifest: {}",
        args.manifest.display()
    );
    Ok(())
}

fn validate_binding_object(binding: &Map<String, Value>) -> Result<()> {
    require_schema(binding, RELEASE_TAG_BINDING_SCHEMA).map_err(anyhow::Error::msg)?;
    validate_version(string_field(binding, "version")?)?;
    validate_git_sha(string_field(binding, "source_sha")?, "$.source_sha")
        .map_err(anyhow::Error::msg)?;
    validate_sha256(
        string_field(binding, "ingress_manifest_sha256")?,
        "$.ingress_manifest_sha256",
    )
    .map_err(anyhow::Error::msg)?;
    for field in [
        "source_build_run_id",
        "source_build_run_attempt",
        "preflight_run_id",
        "preflight_run_attempt",
        "preflight_artifact_id",
    ] {
        parse_positive_int(string_field(binding, field)?, field).map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

fn require_binding_field<'a>(binding: &'a Map<String, Value>, field: &str) -> Result<&'a Value> {
    binding
        .get(field)
        .ok_or_else(|| anyhow::anyhow!("tag binding missing {field}"))
}

fn string_field<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("$.{field}: must be a non-empty string"))
}

fn expect_string(object: &Map<String, Value>, field: &str, expected: &str) -> Result<()> {
    let actual = object.get(field).and_then(Value::as_str);
    if actual != Some(expected) {
        bail!("{field} must be {expected:?}, got {:?}", actual);
    }
    Ok(())
}

fn expect_number_string(value: Option<&Value>, field: &str, expected: &str) -> Result<()> {
    let Some(value) = value else {
        bail!("{field} is missing");
    };
    let actual = positive_int_string(value, field).map_err(anyhow::Error::msg)?;
    if actual != expected {
        bail!("{field} must be {expected}, got {actual}");
    }
    Ok(())
}

fn expected_preflight_artifact_name(binding: &Map<String, Value>) -> Result<String> {
    let version = string_field(binding, "version")?;
    Ok(format!(
        "release-preflight-{}-{}-{}",
        expected_profile(version),
        version,
        string_field(binding, "source_sha")?
    ))
}

fn expected_profile(version: &str) -> &'static str {
    if version.contains('-') {
        "release-candidate"
    } else {
        "production-candidate"
    }
}

fn value_as_string(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Number(value)) => Some(value.to_string()),
        _ => None,
    }
}

fn validate_version(version: &str) -> Result<()> {
    let Some(rest) = version.strip_prefix('v') else {
        bail!("version must be a SemVer tag such as v0.1.0-rc.1");
    };
    let (core, pre) = match rest.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (rest, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        bail!("version must be a SemVer tag such as v0.1.0-rc.1");
    }
    if let Some(pre) = pre {
        let Some(first) = pre.bytes().next() else {
            bail!("version must be a SemVer tag such as v0.1.0-rc.1");
        };
        if !first.is_ascii_alphanumeric()
            || !pre
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
        {
            bail!("version must be a SemVer tag such as v0.1.0-rc.1");
        }
    }
    Ok(())
}

fn trusted_fingerprints(raw: Option<&str>, file: Option<&Path>) -> Result<BTreeSet<String>> {
    let mut values = BTreeSet::new();
    if let Some(raw) = raw {
        extend_fingerprints(&mut values, raw);
    }
    if let Some(path) = file {
        let text =
            fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
        extend_fingerprints(&mut values, &text);
    }
    Ok(values)
}

fn extend_fingerprints(values: &mut BTreeSet<String>, raw: &str) {
    for item in raw.split(|byte: char| byte.is_whitespace() || byte == ',') {
        let item = item.trim();
        if !item.is_empty() {
            values.insert(item.to_ascii_uppercase());
        }
    }
}

fn verify_tag_signature(version: &str, trusted: &BTreeSet<String>) -> Result<String> {
    let output = Command::new("git")
        .args(["verify-tag", "--raw", &format!("refs/tags/{version}")])
        .output()
        .context("failed to run git verify-tag")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "{}",
            if stderr.trim().is_empty() {
                stdout.trim().to_string()
            } else {
                stderr.trim().to_string()
            }
        );
    }
    let raw = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut valid = Vec::new();
    for line in raw.lines() {
        let Some(rest) = line.split("[GNUPG:] VALIDSIG ").nth(1) else {
            continue;
        };
        if let Some(fingerprint) = rest.split_whitespace().next() {
            let fingerprint = fingerprint.to_ascii_uppercase();
            if trusted.contains(&fingerprint) {
                return Ok(fingerprint);
            }
            valid.push(fingerprint);
        }
    }
    if valid.is_empty() {
        bail!("release tag signature did not report a VALIDSIG fingerprint");
    }
    bail!(
        "release tag signer fingerprint is not trusted: {}",
        valid.join(", ")
    );
}

fn validate_run_id_match(
    failures: &mut Vec<String>,
    manifest: &Map<String, Value>,
    field: &str,
    expected: Option<&str>,
) {
    match manifest.get(field) {
        Some(value) => match positive_int_string(value, &format!("$.{field}")) {
            Ok(actual) => {
                if let Some(expected) = expected {
                    if actual != expected {
                        failures.push(format!("$.{field}: must match expected Image Build run"));
                    }
                }
            }
            Err(error) => failures.push(error),
        },
        None => failures.push(format!("$.{field}: must be a positive integer")),
    }
}

fn validate_producer(failures: &mut Vec<String>, manifest: &Map<String, Value>) {
    let Some(producer) = manifest.get("producer").and_then(Value::as_object) else {
        failures.push("$.producer: must be an object".to_string());
        return;
    };
    for field in [
        "provider",
        "repository",
        "workflow",
        "run_id",
        "run_attempt",
        "actor",
    ] {
        if producer
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            failures.push(format!("$.producer.{field}: must be a non-empty string"));
        }
    }
}

fn validate_operator_bundle(failures: &mut Vec<String>, manifest: &Map<String, Value>) {
    let Some(bundle) = manifest.get("operator_bundle").and_then(Value::as_object) else {
        failures.push("$.operator_bundle: must be an object".to_string());
        return;
    };
    let allowed_host = match bundle.get("allowed_host").and_then(Value::as_str) {
        Some(value) if !value.is_empty() && !value.contains('/') && !value.contains(':') => value,
        _ => {
            failures.push("$.operator_bundle.allowed_host: must be a bare hostname".to_string());
            ""
        }
    };
    validate_operator_https_url(
        failures,
        "$.operator_bundle.url",
        bundle.get("url").and_then(Value::as_str),
        allowed_host,
    );
    for field in ["sha256", "signature_sha256", "certificate_sha256"] {
        match bundle.get(field).and_then(Value::as_str) {
            Some(value) => push_err(
                failures,
                validate_sha256(value, &format!("$.operator_bundle.{field}")),
            ),
            None => failures.push(format!(
                "$.operator_bundle.{field}: must be a lowercase sha256 digest"
            )),
        }
    }
    if bundle
        .get("certificate_identity")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        failures
            .push("$.operator_bundle.certificate_identity: must be a non-empty string".to_string());
    }
    if bundle
        .get("certificate_oidc_issuer")
        .and_then(Value::as_str)
        != Some("https://token.actions.githubusercontent.com")
    {
        failures.push(
            "$.operator_bundle.certificate_oidc_issuer: must be GitHub Actions OIDC".to_string(),
        );
    }
    if bundle.get("verified").and_then(Value::as_bool) != Some(true) {
        failures.push("$.operator_bundle.verified: must be true".to_string());
    }
}

fn validate_operator_https_url(
    failures: &mut Vec<String>,
    field: &str,
    value: Option<&str>,
    allowed_host: &str,
) {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        failures.push(format!("{field}: must be a non-empty HTTPS URL"));
        return;
    };
    let Some(rest) = value.strip_prefix("https://") else {
        failures.push(format!("{field}: must use https"));
        return;
    };
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() {
        failures.push(format!("{field}: must include a host"));
        return;
    }
    if authority.contains('@') {
        failures.push(format!("{field}: must not embed credentials"));
    }
    let host = authority
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if !allowed_host.is_empty() && host != allowed_host {
        failures.push(format!(
            "{field}: host must match operator bundle allowlist"
        ));
    }
}

fn validate_operator_window(failures: &mut Vec<String>, manifest: &Map<String, Value>) {
    let generated = match require_string(manifest, "generated_at") {
        Ok(value) => value,
        Err(error) => {
            failures.push(error);
            ""
        }
    };
    let expires = match require_string(manifest, "expires_at") {
        Ok(value) => value,
        Err(error) => {
            failures.push(error);
            ""
        }
    };
    for (field, value) in [("generated_at", generated), ("expires_at", expires)] {
        if !(value.is_empty() || value.ends_with('Z') && value.contains('T')) {
            failures.push(format!("$.{field}: must be an ISO-8601 UTC timestamp"));
        }
    }
    if !generated.is_empty() && !expires.is_empty() && expires <= generated {
        failures.push("$.expires_at: must be after generated_at".to_string());
    }
}

fn validate_operator_files(
    failures: &mut Vec<String>,
    manifest: &Map<String, Value>,
    input_root: Option<&Path>,
    version: &str,
    manifest_paths: &mut BTreeSet<String>,
) {
    let Some(files) = manifest.get("files").and_then(Value::as_array) else {
        failures.push("$.files: must be a non-empty list".to_string());
        return;
    };
    if files.is_empty() {
        failures.push("$.files: must be a non-empty list".to_string());
    }
    for (index, item) in files.iter().enumerate() {
        let path_prefix = format!("$.files[{index}]");
        let Some(record) = item.as_object() else {
            failures.push(format!("{path_prefix}: must be an object"));
            continue;
        };
        if record.get("source").and_then(Value::as_str) != Some("operator-evidence") {
            failures.push(format!("{path_prefix}.source: must be operator-evidence"));
        }
        let rel = match record.get("path").and_then(Value::as_str) {
            Some(value) => match safe_rel_path(value) {
                Ok(rel) => rel,
                Err(error) => {
                    failures.push(format!("{path_prefix}.path: {error}"));
                    continue;
                }
            },
            None => {
                failures.push(format!("{path_prefix}.path: must be a string"));
                continue;
            }
        };
        let rel_string = rel.to_string_lossy().to_string();
        validate_operator_version_path(failures, &rel, version);
        if !manifest_paths.insert(rel_string.clone()) {
            failures.push(format!("{path_prefix}.path: must be unique"));
        }
        if record.get("role").and_then(Value::as_str) != Some(path_role(&rel)) {
            failures.push(format!(
                "{path_prefix}.role: does not match evidence path role"
            ));
        }
        let bytes = match record.get("bytes").and_then(Value::as_u64) {
            Some(bytes) if bytes > 0 => bytes,
            _ => {
                failures.push(format!("{path_prefix}.bytes: must be a positive integer"));
                0
            }
        };
        match record.get("sha256").and_then(Value::as_str) {
            Some(value) => push_err(
                failures,
                validate_sha256(value, &format!("{path_prefix}.sha256")),
            ),
            None => failures.push(format!(
                "{path_prefix}.sha256: must be a lowercase sha256 digest"
            )),
        }
        if let Some(root) = input_root {
            let actual = root.join(&rel);
            match fs::metadata(&actual) {
                Ok(metadata) if metadata.is_file() && metadata.len() > 0 => {
                    if bytes != 0 && metadata.len() != bytes {
                        failures.push(format!(
                            "{path_prefix}.bytes: does not match referenced file"
                        ));
                    }
                    if let Some(expected) = record.get("sha256").and_then(Value::as_str) {
                        match sha256_file(&actual) {
                            Ok(actual_sha) if actual_sha == expected => {}
                            Ok(_) => failures.push(format!(
                                "{path_prefix}.sha256: does not match referenced file"
                            )),
                            Err(error) => failures.push(format!(
                                "{path_prefix}.sha256: cannot hash referenced file: {error}"
                            )),
                        }
                    }
                    validate_referenced_schema(failures, &actual, &rel);
                }
                _ => failures.push(format!(
                    "{path_prefix}.path: referenced evidence file is missing or empty: {rel_string}"
                )),
            }
        }
    }
}

fn validate_required_paths(
    failures: &mut Vec<String>,
    manifest: &Map<String, Value>,
    manifest_paths: &BTreeSet<String>,
) {
    let Some(required) = manifest.get("required_paths").and_then(Value::as_array) else {
        failures.push("$.required_paths: must be a list".to_string());
        return;
    };
    for item in required {
        let Some(path) = item.as_str() else {
            failures.push("$.required_paths: entries must be strings".to_string());
            continue;
        };
        if !manifest_paths.contains(path) {
            failures.push(format!(
                "operator evidence manifest missing required file record: {path}"
            ));
        }
    }
}

fn validate_input_root(
    failures: &mut Vec<String>,
    input_root: &Path,
    version: &str,
    manifest_paths: &BTreeSet<String>,
    allow_preflight_context: bool,
) {
    let scanned = scan_operator_files(failures, input_root, version);
    for path in scanned.difference(manifest_paths) {
        failures.push(format!(
            "operator evidence manifest omits files present in artifact: {path}"
        ));
    }
    for path in manifest_paths.difference(&scanned) {
        failures.push(format!(
            "operator evidence manifest lists files missing from artifact: {path}"
        ));
    }
    for dirname in FORBIDDEN_OPERATOR_DIRS {
        if input_root.join(dirname).exists() && !allow_preflight_context {
            failures.push(format!(
                "{dirname}: must not be supplied through operator evidence ingress"
            ));
        }
    }
    let ingress_manifest = input_root
        .join("release-ingress")
        .join(version)
        .join("ingress-manifest.json");
    if ingress_manifest.exists() && !allow_preflight_context {
        failures.push(
            "release-ingress/<version>/ingress-manifest.json must be produced only by Release Preflight"
                .to_string(),
        );
    }
}

fn scan_operator_files(failures: &mut Vec<String>, root: &Path, version: &str) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    for dirname in ALLOWED_OPERATOR_DIRS {
        let top = root.join(dirname);
        if !top.exists() {
            continue;
        }
        match fs::symlink_metadata(&top) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                failures.push(format!(
                    "{dirname}: must be a directory and must not be a symlink"
                ));
                continue;
            }
            Ok(_) => {}
            Err(error) => {
                failures.push(format!("{dirname}: cannot inspect evidence tree: {error}"));
                continue;
            }
        }
        scan_dir(failures, root, &top, version, &mut paths);
    }
    paths
}

fn scan_dir(
    failures: &mut Vec<String>,
    root: &Path,
    dir: &Path,
    version: &str,
    paths: &mut BTreeSet<String>,
) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            failures.push(format!("{}: cannot read directory: {error}", dir.display()));
            return;
        }
    };
    for entry in entries {
        let Ok(entry) = entry else {
            failures.push(format!("{}: cannot read directory entry", dir.display()));
            continue;
        };
        let path = entry.path();
        let rel = match path.strip_prefix(root) {
            Ok(rel) => rel,
            Err(_) => continue,
        };
        let rel_string = rel.to_string_lossy().to_string();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                failures.push(format!("{rel_string}: cannot inspect file: {error}"));
                continue;
            }
        };
        if metadata.file_type().is_symlink() {
            failures.push(format!("{rel_string}: symlinks are not allowed"));
            continue;
        }
        if metadata.is_dir() {
            scan_dir(failures, root, &path, version, paths);
        } else if metadata.is_file() {
            match safe_rel_path(&rel_string) {
                Ok(rel) => validate_operator_version_path(failures, &rel, version),
                Err(error) => failures.push(format!("{rel_string}: {error}")),
            }
            if metadata.len() == 0 {
                failures.push(format!("{rel_string}: evidence file must be non-empty"));
            }
            paths.insert(rel_string);
        }
    }
}

fn validate_operator_version_path(failures: &mut Vec<String>, rel: &Path, version: &str) {
    let parts: Vec<String> = rel
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => part.to_str().map(str::to_string),
            _ => None,
        })
        .collect();
    let Some(top) = parts.first() else {
        failures.push("empty evidence path".to_string());
        return;
    };
    if !ALLOWED_OPERATOR_DIRS.contains(&top.as_str()) {
        failures.push(format!(
            "{}: top-level directory is not allowed in operator evidence ingress",
            rel.display()
        ));
        return;
    }
    if parts.get(1).map(String::as_str) != Some(version) {
        failures.push(format!(
            "{}: evidence path must be scoped to {version}",
            rel.display()
        ));
    }
}

fn validate_referenced_schema(failures: &mut Vec<String>, actual: &Path, rel: &Path) {
    let Some(expected_schema) = required_schema_for_path(rel) else {
        return;
    };
    match read_json(actual) {
        Ok(value) => match value.as_object() {
            Some(object)
                if object.get("schema_version").and_then(Value::as_str)
                    == Some(expected_schema) => {}
            Some(_) => failures.push(format!(
                "{}: schema_version must be {expected_schema}",
                actual.display()
            )),
            None => failures.push(format!(
                "{}: required evidence must be a JSON object",
                actual.display()
            )),
        },
        Err(error) => failures.push(format!(
            "{}: required evidence must be valid JSON: {error}",
            actual.display()
        )),
    }
}

fn validate_signature(
    failures: &mut Vec<String>,
    manifest: &Path,
    certificate_identity: Option<&str>,
    certificate_oidc_issuer: Option<&str>,
) {
    let signature = manifest.with_file_name(format!(
        "{}.sig",
        manifest
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("evidence-ingress-manifest.json")
    ));
    let certificate = manifest.with_file_name(format!(
        "{}.cert",
        manifest
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("evidence-ingress-manifest.json")
    ));
    for sidecar in [&signature, &certificate] {
        match fs::metadata(sidecar) {
            Ok(metadata) if metadata.is_file() && metadata.len() > 0 => {}
            _ => failures.push(format!(
                "{}: missing evidence ingress signature sidecar",
                sidecar.display()
            )),
        }
    }
    if failures
        .iter()
        .any(|failure| failure.contains("signature sidecar"))
    {
        return;
    }
    let Some(identity) = certificate_identity else {
        failures.push(
            "evidence ingress signature verification requires certificate identity and OIDC issuer"
                .to_string(),
        );
        return;
    };
    let Some(issuer) = certificate_oidc_issuer else {
        failures.push(
            "evidence ingress signature verification requires certificate identity and OIDC issuer"
                .to_string(),
        );
        return;
    };
    let certificate_arg = certificate.to_string_lossy().to_string();
    let signature_arg = signature.to_string_lossy().to_string();
    let manifest_arg = manifest.to_string_lossy().to_string();
    let output = Command::new("cosign")
        .args([
            "verify-blob",
            "--certificate",
            certificate_arg.as_str(),
            "--certificate-identity",
            identity,
            "--certificate-oidc-issuer",
            issuer,
            "--signature",
            signature_arg.as_str(),
            manifest_arg.as_str(),
        ])
        .output();
    match output {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            failures.push(if stderr.trim().is_empty() {
                stdout.trim().to_string()
            } else {
                stderr.trim().to_string()
            });
        }
        Err(error) => failures.push(format!(
            "cosign evidence ingress verification failed: {error}"
        )),
    }
}

fn push_err(failures: &mut Vec<String>, result: Result<(), String>) {
    if let Err(error) = result {
        failures.push(error);
    }
}

fn push_any(failures: &mut Vec<String>, result: Result<()>) {
    if let Err(error) = result {
        failures.push(error.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_complete_tag_annotation() {
        let annotation = "\
Suderra-Release-Binding: v1
Suderra-Version: v0.1.0-rc.1
Suderra-Source-SHA: 1111111111111111111111111111111111111111
Suderra-Source-Build-Run-ID: 10
Suderra-Source-Build-Run-Attempt: 1
Suderra-Preflight-Run-ID: 11
Suderra-Preflight-Run-Attempt: 1
Suderra-Preflight-Artifact-ID: 12
Suderra-Ingress-Manifest-SHA256: 2222222222222222222222222222222222222222222222222222222222222222
";
        let parsed = parse_annotation(annotation).unwrap();
        assert_eq!(
            parsed.get("schema_version").and_then(Value::as_str),
            Some(RELEASE_TAG_BINDING_SCHEMA)
        );
        validate_binding_object(&parsed).unwrap();
    }

    #[test]
    fn rejects_duplicate_tag_fields() {
        let annotation = "\
Suderra-Release-Binding: v1
Suderra-Version: v0.1.0-rc.1
Suderra-Version: v0.1.0-rc.1
";
        assert!(parse_annotation(annotation).is_err());
    }

    #[test]
    fn builds_expected_preflight_artifact_name() {
        let binding = json!({
            "schema_version": RELEASE_TAG_BINDING_SCHEMA,
            "version": "v0.1.0-rc.1",
            "source_sha": "1111111111111111111111111111111111111111",
            "source_build_run_id": "10",
            "source_build_run_attempt": "1",
            "preflight_run_id": "11",
            "preflight_run_attempt": "1",
            "preflight_artifact_id": "12",
            "ingress_manifest_sha256": "2222222222222222222222222222222222222222222222222222222222222222"
        });
        let object = binding.as_object().unwrap();
        assert_eq!(
            expected_preflight_artifact_name(object).unwrap(),
            "release-preflight-release-candidate-v0.1.0-rc.1-1111111111111111111111111111111111111111"
        );
    }
}
