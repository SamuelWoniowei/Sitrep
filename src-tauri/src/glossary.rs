//! Built-in plain-English glossary. Works fully offline; the local AI (when
//! available) can add definitions for terms not listed here.

use serde::Serialize;

#[derive(Serialize, Clone, Copy, Debug)]
pub struct Term {
    pub term: &'static str,
    /// Lower-case phrases that indicate the term appears in a story.
    #[serde(skip)]
    pub matches: &'static [&'static str],
    pub plain: &'static str,
    pub analogy: &'static str,
}

pub const TERMS: &[Term] = &[
    Term { term: "Zero-day", matches: &["zero-day", "0-day", "zero day"], plain: "A flaw attackers are using before the vendor has a fix available.", analogy: "A burglar finding a broken lock before the locksmith knows it exists." },
    Term { term: "CVE", matches: &["cve-"], plain: "A public ID number given to a specific known security flaw, so everyone talks about the same bug.", analogy: "A case number for a bug." },
    Term { term: "Actively exploited", matches: &["actively exploited", "exploited in the wild", "exploited in attacks", "under active exploitation"], plain: "Attackers are already using this flaw against real targets, not just in theory.", analogy: "The burglar isn't planning: they're already trying doors on your street." },
    Term { term: "Ransomware", matches: &["ransomware"], plain: "Malware that locks or steals an organisation's data and demands payment.", analogy: "Someone changes the locks on your house and sells you the key." },
    Term { term: "Double extortion", matches: &["double extortion", "leak site", "data leak site"], plain: "Ransomware gangs steal data before encrypting it, then threaten to publish it too.", analogy: "They take your diary before changing the locks." },
    Term { term: "Phishing", matches: &["phishing", "phish"], plain: "Tricking people into clicking a link, opening a file or handing over login details.", analogy: "A fake delivery note asking you to 'confirm your address'." },
    Term { term: "Initial access broker", matches: &["initial access broker", "access broker"], plain: "A criminal who breaks into networks and sells that access to other attackers.", analogy: "Someone who copies office keys and sells them online." },
    Term { term: "Lateral movement", matches: &["lateral movement", "moved laterally", "move laterally"], plain: "After getting in, attackers hop from one machine to others inside the network.", analogy: "A burglar who got in through the garage now walking room to room." },
    Term { term: "Privilege escalation", matches: &["privilege escalation", "elevation of privilege", "escalate privileges"], plain: "Turning limited access into admin-level control.", analogy: "A visitor's badge quietly upgraded to a master key." },
    Term { term: "Remote code execution (RCE)", matches: &["remote code execution", " rce", "code execution"], plain: "A flaw that lets an attacker run their own commands on someone else's system over the network.", analogy: "Being able to work someone's computer from across the internet." },
    Term { term: "Patch", matches: &["patch", "security update", "fixes"], plain: "A software update that fixes a flaw.", analogy: "The locksmith's repair for the broken lock." },
    Term { term: "Supply-chain attack", matches: &["supply chain", "supply-chain"], plain: "Attacking a trusted supplier or software package to reach all of its customers at once.", analogy: "Poisoning the water at the reservoir instead of one tap." },
    Term { term: "Botnet", matches: &["botnet"], plain: "A network of hacked devices controlled together by an attacker.", analogy: "An army of zombie computers taking orders." },
    Term { term: "DDoS", matches: &["ddos", "denial-of-service", "denial of service"], plain: "Flooding a service with traffic until it slows down or goes offline.", analogy: "A thousand people blocking a shop's doorway so customers can't get in." },
    Term { term: "Credential stuffing", matches: &["credential stuffing"], plain: "Trying leaked username and password pairs on lots of other sites.", analogy: "Trying a stolen key in every door on the street." },
    Term { term: "MFA", matches: &["mfa", "multi-factor", "two-factor", "2fa"], plain: "Needing a second proof (a code, an app prompt, a key) on top of a password.", analogy: "A door that needs both a key and a PIN." },
    Term { term: "MFA fatigue", matches: &["mfa fatigue", "push bombing", "mfa bombing"], plain: "Spamming someone with login approval prompts until they tap 'approve' to make it stop.", analogy: "Ringing the doorbell until someone opens up just to make it stop." },
    Term { term: "APT", matches: &["apt", "advanced persistent threat", "state-sponsored", "nation-state"], plain: "A well-resourced, usually government-linked hacking group that stays hidden for a long time.", analogy: "A professional spy, not a smash-and-grab thief." },
    Term { term: "Threat actor", matches: &["threat actor", "hacking group", "threat group"], plain: "The person or group behind an attack.", analogy: "The 'who' in whodunnit." },
    Term { term: "IOC", matches: &["indicator of compromise", "indicators of compromise", "iocs"], plain: "A clue that a system was hacked: a bad IP address, file hash or domain.", analogy: "Fingerprints left at the scene." },
    Term { term: "TTPs", matches: &["ttps", "tactics, techniques"], plain: "How an attacker typically operates: their tactics, techniques and procedures.", analogy: "A criminal's signature style." },
    Term { term: "MITRE ATT&CK", matches: &["att&ck", "mitre"], plain: "A public catalogue of attacker techniques that defenders use as a shared language.", analogy: "A field guide to how burglars work." },
    Term { term: "SIEM", matches: &["siem"], plain: "A system that collects logs from everywhere and raises alerts on suspicious patterns.", analogy: "CCTV control room for the whole network." },
    Term { term: "EDR", matches: &["edr", "endpoint detection"], plain: "Security software on laptops and servers that watches behaviour and can stop attacks.", analogy: "A guard posted in every room, not just at the front door." },
    Term { term: "Edge device", matches: &["vpn", "firewall", "edge device", "gateway", "appliance"], plain: "Equipment at the boundary of a network, like VPNs and firewalls, that faces the internet.", analogy: "The front door: the first thing attackers try." },
    Term { term: "Data breach", matches: &["data breach", "breach", "leaked data", "data leak"], plain: "When information is accessed or stolen by someone who shouldn't have it.", analogy: "Someone walking out with the filing cabinet." },
    Term { term: "Infostealer", matches: &["infostealer", "info-stealer", "stealer malware"], plain: "Malware that quietly grabs saved passwords, cookies and crypto wallets from a device.", analogy: "A pickpocket living in your browser." },
    Term { term: "Session hijacking", matches: &["session hijack", "session cookie", "cookie theft", "token theft"], plain: "Stealing a logged-in session so the attacker skips the password and MFA entirely.", analogy: "Taking someone's wristband instead of buying a ticket." },
    Term { term: "Living off the land", matches: &["living off the land", "lolbin", "lolbas"], plain: "Attackers using tools already built into the system so they blend in.", analogy: "A burglar using your own ladder." },
    Term { term: "C2 server", matches: &["command and control", "command-and-control", "c2 server", "c2 "], plain: "The attacker's server that hacked machines check in with for instructions.", analogy: "The getaway driver's radio." },
    Term { term: "Vulnerability", matches: &["vulnerability", "vulnerabilities", "flaw"], plain: "A weakness in software or setup that an attacker could use.", analogy: "An unlatched window." },
    Term { term: "CVSS", matches: &["cvss"], plain: "A 0–10 score for how severe a flaw is in theory. 9+ is critical.", analogy: "A hazard rating, not proof anyone is attacking." },
    Term { term: "KEV catalogue", matches: &["known exploited", "kev"], plain: "CISA's list of flaws confirmed to be exploited in real attacks: the 'patch this first' list.", analogy: "The police list of locks burglars are actually picking right now." },
    Term { term: "Social engineering", matches: &["social engineering", "impersonat", "vishing", "pretext"], plain: "Manipulating people, not systems, into giving access.", analogy: "Talking your way past reception." },
    Term { term: "Cloud misconfiguration", matches: &["misconfigur", "exposed bucket", "publicly exposed"], plain: "Cloud storage or services left open by mistake, exposing data to anyone.", analogy: "Leaving the warehouse door wide open overnight." },
];

pub fn find(term: &str) -> Option<&'static Term> {
    TERMS.iter().find(|t| t.term.eq_ignore_ascii_case(term))
}

/// Glossary terms that appear in a piece of text, most specific first.
pub fn terms_in(text: &str, max: usize) -> Vec<&'static Term> {
    let lower = format!(" {} ", text.to_lowercase());
    let mut hits: Vec<(&'static Term, usize)> = TERMS
        .iter()
        .filter_map(|t| {
            t.matches
                .iter()
                .filter(|m| lower.contains(*m))
                .map(|m| m.len())
                .max()
                .map(|len| (t, len))
        })
        .collect();
    // Prefer longer (more specific) matches; generic words like "patch" last.
    hits.sort_by_key(|h| std::cmp::Reverse(h.1));
    hits.into_iter().take(max).map(|(t, _)| t).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_terms() {
        let t = terms_in(
            "Hackers exploited a zero-day in a VPN appliance (CVE-2026-1)",
            3,
        );
        let names: Vec<_> = t.iter().map(|t| t.term).collect();
        assert!(names.contains(&"Zero-day"));
        assert!(names.contains(&"Edge device"));
    }

    #[test]
    fn all_terms_have_content() {
        for t in TERMS {
            assert!(!t.plain.is_empty() && !t.analogy.is_empty() && !t.matches.is_empty());
        }
    }
}
