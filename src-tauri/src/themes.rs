//! Story categories, themes, lab ideas and weekly projects.
//! Deterministic and offline: no AI needed for any of this.

use serde::Serialize;

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    ExploitedNow,
    BigIncident,
    Uk,
    News,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::ExploitedNow => "EXPLOITED NOW",
            Category::BigIncident => "BIG INCIDENT",
            Category::Uk => "UK",
            Category::News => "NEWS",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    EdgeExploit,
    Ransomware,
    Phishing,
    Identity,
    SupplyChain,
    Malware,
    DataBreach,
    Patching,
    StateActor,
}

pub const ALL_THEMES: &[Theme] = &[
    Theme::EdgeExploit,
    Theme::Ransomware,
    Theme::Phishing,
    Theme::Identity,
    Theme::SupplyChain,
    Theme::Malware,
    Theme::DataBreach,
    Theme::Patching,
    Theme::StateActor,
];

impl Theme {
    pub fn name(self) -> &'static str {
        match self {
            Theme::EdgeExploit => "Edge device exploitation",
            Theme::Ransomware => "Ransomware",
            Theme::Phishing => "Phishing & social engineering",
            Theme::Identity => "Identity & cloud",
            Theme::SupplyChain => "Supply chain",
            Theme::Malware => "Malware & botnets",
            Theme::DataBreach => "Data breaches",
            Theme::Patching => "Patching & vulnerabilities",
            Theme::StateActor => "State-backed hacking",
        }
    }
    pub fn key(self) -> &'static str {
        match self {
            Theme::EdgeExploit => "edge_exploit",
            Theme::Ransomware => "ransomware",
            Theme::Phishing => "phishing",
            Theme::Identity => "identity",
            Theme::SupplyChain => "supply_chain",
            Theme::Malware => "malware",
            Theme::DataBreach => "data_breach",
            Theme::Patching => "patching",
            Theme::StateActor => "state_actor",
        }
    }
    pub fn from_key(k: &str) -> Option<Theme> {
        ALL_THEMES.iter().copied().find(|t| t.key() == k)
    }
    fn keywords(self) -> &'static [&'static str] {
        match self {
            Theme::EdgeExploit => &[
                "vpn",
                "firewall",
                "fortinet",
                "fortigate",
                "ivanti",
                "citrix",
                "netscaler",
                "palo alto",
                "pan-os",
                "sonicwall",
                "cisco asa",
                "edge device",
                "gateway",
                "router",
            ],
            Theme::Ransomware => &["ransomware", "extortion", "lockbit", "encrypt", "ransom"],
            Theme::Phishing => &[
                "phishing",
                "phish",
                "social engineering",
                "vishing",
                "smishing",
                "impersonat",
                "lure",
            ],
            Theme::Identity => &[
                "mfa",
                "oauth",
                "entra",
                "azure ad",
                "okta",
                "identity",
                "session",
                "token",
                "cloud",
                "aws",
                "microsoft 365",
                "credential",
            ],
            Theme::SupplyChain => &[
                "supply chain",
                "supply-chain",
                "npm",
                "pypi",
                "package",
                "dependency",
                "open source",
                "github",
            ],
            Theme::Malware => &[
                "malware",
                "botnet",
                "infostealer",
                "stealer",
                "trojan",
                "loader",
                "backdoor",
                "rat ",
            ],
            Theme::DataBreach => &[
                "breach",
                "leak",
                "exposed",
                "stolen data",
                "data theft",
                "customers' data",
                "personal data",
            ],
            Theme::Patching => &["patch", "update", "cve-", "vulnerability", "flaw", "fixes"],
            Theme::StateActor => &[
                "china",
                "chinese",
                "russia",
                "russian",
                "iran",
                "north korea",
                "lazarus",
                "state-sponsored",
                "nation-state",
                "apt",
            ],
        }
    }
}

/// Themes present in a story, strongest first.
pub fn themes_of(text: &str) -> Vec<Theme> {
    let lower = text.to_lowercase();
    let mut scored: Vec<(Theme, usize)> = ALL_THEMES
        .iter()
        .map(|t| {
            (
                *t,
                t.keywords().iter().filter(|k| lower.contains(*k)).count(),
            )
        })
        .filter(|(_, n)| *n > 0)
        .collect();
    // "Patching" matches almost any security story, so it only leads when
    // nothing more specific applies.
    scored.sort_by_key(|(t, n)| std::cmp::Reverse((*t != Theme::Patching, *n)));
    scored.into_iter().map(|(t, _)| t).collect()
}

pub fn categorize(text: &str, in_kev: bool, uk_source: bool) -> Category {
    let l = text.to_lowercase();
    let exploited = in_kev
        || [
            "actively exploited",
            "exploited in the wild",
            "exploited in attacks",
            "zero-day",
            "0-day",
            "under active exploitation",
        ]
        .iter()
        .any(|k| l.contains(k));
    if exploited {
        return Category::ExploitedNow;
    }
    let incident = [
        "ransomware",
        "breach",
        "cyberattack",
        "cyber attack",
        "hacked",
        "outage",
        "stolen",
        "extortion",
    ]
    .iter()
    .any(|k| l.contains(k));
    if incident {
        return Category::BigIncident;
    }
    if uk_source
        || [
            " uk ",
            "united kingdom",
            "britain",
            "british",
            "ncsc",
            "nhs",
            "london",
        ]
        .iter()
        .any(|k| format!(" {l} ").contains(k))
    {
        return Category::Uk;
    }
    Category::News
}

pub fn why_it_matters(cat: Category, themes: &[Theme]) -> String {
    match cat {
        Category::ExploitedNow => "Attackers are already using this. Defenders are patching and hunting for it today, so expect it in SOC alerts and interview questions.".into(),
        Category::BigIncident => "A real-world incident: a ready-made case study of how attacks actually unfold, from first access to impact.".into(),
        Category::Uk => "UK-specific: this shapes what UK employers and regulators expect from their security teams.".into(),
        Category::News => match themes.first() {
            Some(t) => format!("Part of a wider trend in {}. Worth knowing the shape of it.", t.name().to_lowercase()),
            None => "Useful background on where the industry is heading.".into(),
        },
    }
}

#[derive(Clone, Debug)]
pub struct IdeaTemplate {
    pub title: &'static str,
    pub detail: &'static str,
}

pub fn idea_for(theme: Theme) -> IdeaTemplate {
    match theme {
        Theme::EdgeExploit => IdeaTemplate { title: "Detect exploit attempts against an edge device", detail: "Replay public exploit traffic (pcap) through Suricata and write a rule that fires on it." },
        Theme::Ransomware => IdeaTemplate { title: "Catch ransomware-style file encryption", detail: "Use Wazuh file integrity monitoring to alert when many files change extension quickly." },
        Theme::Phishing => IdeaTemplate { title: "Build a lookalike-domain checker", detail: "Script that flags domains similar to a brand (typos, swapped letters) using a public domain list." },
        Theme::Identity => IdeaTemplate { title: "Alert on impossible-travel logins", detail: "Parse sample sign-in logs and flag the same account logging in from distant places too quickly." },
        Theme::SupplyChain => IdeaTemplate { title: "Audit a project's dependencies", detail: "Run npm audit / pip-audit on an open-source project and write up the riskiest findings." },
        Theme::Malware => IdeaTemplate { title: "Spot beaconing traffic", detail: "Find regular, timed outbound connections in Suricata logs: the signature of malware checking in." },
        Theme::DataBreach => IdeaTemplate { title: "Detect bulk data exfiltration", detail: "Alert in Wazuh when a host sends unusually large volumes of data outbound." },
        Theme::Patching => IdeaTemplate { title: "Build a KEV patch checker", detail: "Script that compares software installed in your lab against CISA's KEV list." },
        Theme::StateActor => IdeaTemplate { title: "Map an APT report to ATT&CK", detail: "Take one public threat report and map each step to MITRE ATT&CK techniques." },
    }
}

#[derive(Serialize, serde::Deserialize, Clone, Debug)]
pub struct ProjectPlan {
    pub theme: String,
    pub title: String,
    pub why: String,
    pub tools: Vec<String>,
    pub steps: Vec<String>,
    pub done_when: String,
}

pub fn project_for(theme: Theme, story_count: usize) -> ProjectPlan {
    let (title, tools, steps, done): (&str, &[&str], &[&str], &str) = match theme {
        Theme::EdgeExploit => (
            "Detect edge-device exploitation in your lab",
            &["Suricata", "Wazuh", "Wireshark"],
            &[
                "Find a public pcap or PoC traffic sample for a recent edge-device CVE",
                "Replay it with tcpreplay against your Suricata sensor",
                "Write a Suricata rule that matches the exploit pattern",
                "Forward the alert into Wazuh and write a one-page summary",
            ],
            "Your rule fires on the replayed exploit traffic and shows up in Wazuh.",
        ),
        Theme::Ransomware => (
            "Detect ransomware behaviour before it spreads",
            &["Wazuh", "Python"],
            &[
                "Turn on Wazuh file integrity monitoring for a test folder",
                "Write a harmless script that renames 200 files to .locked",
                "Create a Wazuh rule for many file changes in a short window",
                "Document the detection and how you'd respond",
            ],
            "Running the script triggers your custom Wazuh alert within a minute.",
        ),
        Theme::Phishing => (
            "Build a phishing-domain early-warning tool",
            &["Python", "dnstwist"],
            &[
                "Pick a brand and generate lookalike domains",
                "Check which lookalikes are actually registered",
                "Flag ones with mail (MX) records set up",
                "Write a short report of the riskiest domains",
            ],
            "Your script outputs a ranked list of live lookalike domains.",
        ),
        Theme::Identity => (
            "Hunt suspicious logins in identity logs",
            &["Python", "Wazuh"],
            &[
                "Get a sample sign-in log dataset",
                "Flag impossible travel and logins at odd hours",
                "Flag repeated MFA prompts on one account",
                "Turn the best check into a Wazuh rule",
            ],
            "Your detections flag the planted bad logins with no more than a few false alarms.",
        ),
        Theme::SupplyChain => (
            "Run a supply-chain audit on a real project",
            &["npm audit", "pip-audit", "OSV"],
            &[
                "Pick a popular open-source project",
                "Generate a full dependency list",
                "Scan it for known vulnerabilities",
                "Write up the 3 riskiest findings and fixes",
            ],
            "A short write-up listing real findings with a suggested fix for each.",
        ),
        Theme::Malware => (
            "Detect malware beaconing on your network",
            &["Suricata", "Python"],
            &[
                "Simulate a beacon: a script calling a test server every 60s",
                "Capture the traffic with Suricata",
                "Write a script that finds regular-interval connections",
                "Tune it so normal traffic doesn't trigger it",
            ],
            "Your detector flags the simulated beacon and ignores normal browsing.",
        ),
        Theme::DataBreach => (
            "Catch data exfiltration",
            &["Wazuh", "Suricata"],
            &[
                "Simulate exfiltration: copy a large file to an external test host",
                "Find it in network logs",
                "Write a rule for unusually large outbound transfers",
                "Document the thresholds you chose and why",
            ],
            "The simulated exfiltration raises an alert; normal use doesn't.",
        ),
        Theme::Patching => (
            "Build a 'what do I patch first' checker",
            &["Python", "CISA KEV"],
            &[
                "Inventory software versions in your lab",
                "Download the CISA KEV list",
                "Match your inventory against it",
                "Output a prioritised patch list",
            ],
            "Running the script prints which of your installed products appear on KEV.",
        ),
        Theme::StateActor => (
            "Turn a threat report into detections",
            &["MITRE ATT&CK Navigator", "Wazuh"],
            &[
                "Pick a recent public report on a state-backed group",
                "Map each step to ATT&CK techniques",
                "Pick two techniques you can detect in your lab",
                "Write and test detections for them",
            ],
            "An ATT&CK layer file plus two working detections.",
        ),
    };
    ProjectPlan {
        theme: theme.key().into(),
        title: title.into(),
        why: format!(
            "Built from {story_count} stories this week about {}. Weekend-sized.",
            theme.name().to_lowercase()
        ),
        tools: tools.iter().map(|s| s.to_string()).collect(),
        steps: steps.iter().map(|s| s.to_string()).collect(),
        done_when: done.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories() {
        assert_eq!(
            categorize("Fortinet zero-day exploited in attacks", false, false),
            Category::ExploitedNow
        );
        assert_eq!(
            categorize("Some product update", true, false),
            Category::ExploitedNow
        );
        assert_eq!(
            categorize("Ransomware gang hits hospital", false, false),
            Category::BigIncident
        );
        assert_eq!(
            categorize("NCSC publishes guidance", false, true),
            Category::Uk
        );
        assert_eq!(
            categorize("Vendor launches product", false, false),
            Category::News
        );
    }

    #[test]
    fn themes_detected() {
        let t = themes_of("Hackers exploit Ivanti VPN flaw to deploy ransomware");
        assert!(t.contains(&Theme::EdgeExploit));
        assert!(t.contains(&Theme::Ransomware));
        let t = themes_of("Patch now: update fixes flaw CVE-2026-1 in Fortinet VPN firewall");
        assert_eq!(
            t[0],
            Theme::EdgeExploit,
            "specific theme must beat generic patching"
        );
    }

    #[test]
    fn every_theme_has_idea_and_project() {
        for t in ALL_THEMES {
            assert!(!idea_for(*t).title.is_empty());
            let p = project_for(*t, 3);
            assert_eq!(p.steps.len(), 4);
            assert_eq!(Theme::from_key(t.key()), Some(*t));
        }
    }
}
