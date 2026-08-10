//! depscope — scope your Rust dependency supply chain.
//!
//! This crate parses a `Cargo.lock` file into a source-agnostic view and
//! applies a small set of supply-chain risk heuristics. The logic here is
//! deliberately pure and unit-tested so it can be embedded or driven by a CLI.

#![forbid(unsafe_code)]

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Where a dependency's source artifact comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// Root workspace member (no source entry in Cargo.lock).
    Root,
    /// crates.io (git or sparse registry).
    Registry,
    /// Git repository (not crates.io).
    Git,
    /// Local path / workspace path dependency.
    Path,
    /// Anything else (directory source, custom registry, etc.).
    Other,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::Root => "root",
            SourceKind::Registry => "registry",
            SourceKind::Git => "git",
            SourceKind::Path => "path",
            SourceKind::Other => "other",
        }
    }
}

/// A flattened, source-agnostic view of one locked package.
#[derive(Debug, Clone)]
pub struct Pkg {
    pub name: String,
    pub version: String,
    pub source: SourceKind,
    pub has_checksum: bool,
}

/// Severity of a flagged risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Low,
    Medium,
    High,
}

/// A single supply-chain risk attached to a package.
#[derive(Debug, Clone, Serialize)]
pub struct Risk {
    pub name: String,
    pub version: String,
    pub level: Level,
    pub reason: String,
}

fn classify_source(src: Option<&cargo_lock::SourceId>) -> SourceKind {
    match src {
        None => SourceKind::Root,
        Some(s) => {
            if s.is_git() {
                SourceKind::Git
            } else if s.is_path() {
                SourceKind::Path
            } else if s.is_registry() {
                SourceKind::Registry
            } else {
                SourceKind::Other
            }
        }
    }
}

/// Parse a `Cargo.lock` file into the flattened [`Pkg`] view.
pub fn from_lockfile(path: impl AsRef<Path>) -> anyhow::Result<Vec<Pkg>> {
    let lock = cargo_lock::Lockfile::load(path)?;
    let mut pkgs = Vec::with_capacity(lock.packages.len());
    for p in &lock.packages {
        let source = classify_source(p.source.as_ref());
        pkgs.push(Pkg {
            name: p.name.to_string(),
            version: p.version.to_string(),
            source,
            has_checksum: p.checksum.is_some(),
        });
    }
    Ok(pkgs)
}

/// Apply supply-chain risk heuristics to a set of packages.
///
/// Pure and deterministic: identical input yields identical output, which is
/// what makes it safe to drive both the CLI and CI gates from the same code.
pub fn detect_risks(pkgs: &[Pkg]) -> Vec<Risk> {
    let mut risks: Vec<Risk> = Vec::new();

    for p in pkgs {
        match p.source {
            SourceKind::Git => risks.push(Risk {
                name: p.name.clone(),
                version: p.version.clone(),
                level: Level::High,
                reason: "Sourced from a Git repository, not crates.io — verify provenance and pin to an immutable revision.".into(),
            }),
            SourceKind::Path => risks.push(Risk {
                name: p.name.clone(),
                version: p.version.clone(),
                level: Level::Medium,
                reason: "Local path dependency — not resolved from a registry; builds depend on local filesystem state.".into(),
            }),
            SourceKind::Other => risks.push(Risk {
                name: p.name.clone(),
                version: p.version.clone(),
                level: Level::Medium,
                reason: "Non-standard source (directory/custom registry) — confirm it is an intended, trusted source.".into(),
            }),
            SourceKind::Registry => {
                if !p.has_checksum {
                    risks.push(Risk {
                        name: p.name.clone(),
                        version: p.version.clone(),
                        level: Level::High,
                        reason: "Registry package is missing a checksum in Cargo.lock — integrity cannot be verified.".into(),
                    });
                }
            }
            SourceKind::Root => {}
        }

        // Pre-1.0 (unstable API) — only meaningful for resolved dependencies.
        if p.source != SourceKind::Root && major(&p.version) == 0 {
            risks.push(Risk {
                name: p.name.clone(),
                version: p.version.clone(),
                level: Level::Low,
                reason: "Pre-1.0 version — API is not stabilized; upgrades may break.".into(),
            });
        }
    }

    // Duplicate versions of the same crate widen the attack surface.
    let mut by_name: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for p in pkgs {
        if p.source == SourceKind::Root {
            continue;
        }
        by_name
            .entry(p.name.as_str())
            .or_default()
            .insert(p.version.as_str());
    }
    for (name, versions) in by_name {
        if versions.len() > 1 {
            let joined = versions.iter().copied().collect::<Vec<_>>().join(", ");
            risks.push(Risk {
                name: name.to_string(),
                version: joined.clone(),
                level: Level::Medium,
                reason: format!("Multiple versions locked ({joined}); consider unifying to reduce attack surface and bloat."),
            });
        }
    }

    // Highest severity first, then by name for stable output.
    risks.sort_by(|a, b| b.level.cmp(&a.level).then_with(|| a.name.cmp(&b.name)));
    risks
}

fn major(v: &str) -> u64 {
    v.split('.')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Count packages overall and grouped by source kind.
#[derive(Debug, Serialize)]
pub struct Summary {
    pub total: usize,
    pub by_source: BTreeMap<String, usize>,
}

pub fn summarize(pkgs: &[Pkg]) -> Summary {
    let mut by_source: BTreeMap<String, usize> = BTreeMap::new();
    for p in pkgs {
        *by_source.entry(p.source.as_str().to_string()).or_insert(0) += 1;
    }
    Summary {
        total: pkgs.len(),
        by_source,
    }
}

/// A minimal CycloneDX-style SBOM component.
#[derive(Debug, Serialize)]
pub struct SbomComponent {
    pub r#type: &'static str,
    pub name: String,
    pub version: String,
    pub purl: String,
    pub scope: &'static str,
}

/// A minimal CycloneDX 1.5 SBOM document.
#[derive(Debug, Serialize)]
pub struct Sbom {
    pub bom_format: &'static str,
    pub spec_version: &'static str,
    pub components: Vec<SbomComponent>,
}

pub fn to_sbom(pkgs: &[Pkg]) -> Sbom {
    let components = pkgs
        .iter()
        .filter(|p| p.source != SourceKind::Root)
        .map(|p| SbomComponent {
            r#type: "library",
            name: p.name.clone(),
            version: p.version.clone(),
            purl: format!("pkg:cargo/{}@{}", p.name, p.version),
            scope: if p.source == SourceKind::Git {
                "required"
            } else {
                "optional"
            },
        })
        .collect();
    Sbom {
        bom_format: "CycloneDX",
        spec_version: "1.5",
        components,
    }
}

pub fn sbom_json(pkgs: &[Pkg]) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(&to_sbom(pkgs))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str, version: &str, source: SourceKind, has_checksum: bool) -> Pkg {
        Pkg {
            name: name.into(),
            version: version.into(),
            source,
            has_checksum,
        }
    }

    #[test]
    fn no_risks_for_clean_registry() {
        let pkgs = vec![
            pkg("serde", "1.0.0", SourceKind::Registry, true),
            pkg("tokio", "1.2.3", SourceKind::Registry, true),
        ];
        assert!(detect_risks(&pkgs).is_empty());
    }

    #[test]
    fn git_source_is_high_and_pre_1_0_low() {
        let pkgs = vec![pkg("evil", "0.1.0", SourceKind::Git, false)];
        let risks = detect_risks(&pkgs);
        assert_eq!(risks.len(), 2, "git High + pre-1.0 Low");
        assert!(risks
            .iter()
            .any(|r| r.level == Level::High && r.reason.contains("Git")));
        assert!(risks.iter().any(|r| r.level == Level::Low));
    }

    #[test]
    fn registry_missing_checksum_is_high() {
        let pkgs = vec![pkg("nochk", "1.0.0", SourceKind::Registry, false)];
        let risks = detect_risks(&pkgs);
        assert!(risks
            .iter()
            .any(|r| r.level == Level::High && r.reason.contains("checksum")));
    }

    #[test]
    fn duplicate_versions_flagged() {
        let pkgs = vec![
            pkg("dup", "1.0.0", SourceKind::Registry, true),
            pkg("dup", "2.0.0", SourceKind::Registry, true),
        ];
        assert!(detect_risks(&pkgs)
            .iter()
            .any(|r| r.reason.contains("Multiple versions")));
    }

    #[test]
    fn pre_1_0_is_low() {
        let pkgs = vec![pkg("beta", "0.4.0", SourceKind::Registry, true)];
        let risks = detect_risks(&pkgs);
        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].level, Level::Low);
    }

    #[test]
    fn root_not_flagged() {
        let pkgs = vec![pkg("myapp", "0.1.0", SourceKind::Root, false)];
        assert!(detect_risks(&pkgs).is_empty());
    }

    #[test]
    fn sbom_excludes_root_and_builds_purl() {
        let pkgs = vec![
            pkg("myapp", "0.1.0", SourceKind::Root, false),
            pkg("serde", "1.0.0", SourceKind::Registry, true),
        ];
        let sbom = to_sbom(&pkgs);
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.components[0].purl, "pkg:cargo/serde@1.0.0");
        assert_eq!(sbom.bom_format, "CycloneDX");
    }

    #[test]
    fn ordering_by_severity_desc() {
        let pkgs = vec![
            pkg("a", "1.0.0", SourceKind::Registry, false), // High (no checksum)
            pkg("b", "0.1.0", SourceKind::Registry, true),  // Low
        ];
        let risks = detect_risks(&pkgs);
        assert!(risks[0].level >= risks[1].level);
    }
}
