/** Short, well-documented security facts. Built in; nothing is fetched. */
export type Fact = { tag: string; text: string }

export const FACTS: Fact[] = [
  { tag: 'MALWARE', text: 'The Morris worm of 1988 was one of the first internet worms. It slowed a large share of the few tens of thousands of computers then online, and led to the creation of the first CERT.' },
  { tag: 'MALWARE', text: 'The first known ransomware, the "AIDS Trojan" (1989), was posted out on floppy disks and asked victims to send $189 to a PO box in Panama.' },
  { tag: 'MALWARE', text: 'Creeper (1971) was an experimental program that hopped between computers showing "I\'m the creeper, catch me if you can!". A program called Reaper was written to delete it.' },
  { tag: 'MALWARE', text: 'Brain (1986), often called the first PC virus, was written by two brothers in Pakistan and even contained their address and phone number.' },
  { tag: 'MALWARE', text: 'WannaCry (2017) was slowed down when a researcher registered an unregistered domain hard-coded in the malware. The domain cost about $10.69.' },
  { tag: 'MALWARE', text: 'Stuxnet, found in 2010, used several zero-day flaws and targeted industrial controllers. It is the textbook example of malware aimed at physical equipment.' },
  { tag: 'MALWARE', text: 'The Mirai botnet (2016) took over cameras and routers simply by trying a short list of factory-default passwords.' },
  { tag: 'HISTORY', text: 'In "The Cuckoo\'s Egg" story (1986), astronomer Clifford Stoll started tracking an intruder after noticing a 75-cent accounting error in a computer log.' },
  { tag: 'HISTORY', text: 'The word "bug" was in engineering use long before 1947, but a moth taped into the Harvard Mark II log that year made the story famous.' },
  { tag: 'HISTORY', text: 'The "hacker" label began in the 1950s and 60s at MIT, where a model-railroad club used it for clever, playful tinkering.' },
  { tag: 'HISTORY', text: 'The CVE list started in 1999 so that everyone could use one name for one flaw. Before that, each vendor named bugs differently.' },
  { tag: 'HISTORY', text: 'The UK\'s NCSC opened in 2016 and is part of GCHQ. Its "Active Cyber Defence" work includes taking down phishing sites in bulk.' },
  { tag: 'HISTORY', text: 'CISA\'s Known Exploited Vulnerabilities catalogue launched in November 2021. If a flaw is on it, attackers are really using it.' },
  { tag: 'HISTORY', text: 'Microsoft has shipped security fixes on the second Tuesday of each month since 2003. Defenders call it Patch Tuesday.' },
  { tag: 'CRYPTO', text: 'Julius Caesar reportedly shifted letters by three to hide military messages. That shift cipher still carries his name.' },
  { tag: 'CRYPTO', text: 'A flaw helped break the Enigma machine: a letter could never be encrypted to itself, which gave codebreakers a handy clue.' },
  { tag: 'CRYPTO', text: 'Public-key cryptography was invented inside GCHQ before it was published, but the work stayed secret until 1997.' },
  { tag: 'CRYPTO', text: 'Diffie and Hellman published their key-exchange idea in 1976. It lets two strangers agree on a secret over an open channel.' },
  { tag: 'CRYPTO', text: 'ROT13 is its own undo button: apply it twice and you are back to the original text. It is obfuscation, not security.' },
  { tag: 'CRYPTO', text: 'In 2017 researchers produced the first practical SHA-1 collision ("SHAttered"), which is why SHA-1 is retired for signatures.' },
  { tag: 'CRYPTO', text: 'Salting passwords before hashing defeats rainbow tables, because the same password no longer produces the same hash twice.' },
  { tag: 'TOOLS', text: 'Nmap was first released in 1997 as an article in Phrack magazine. It is still the first tool most defenders learn.' },
  { tag: 'TOOLS', text: 'Wireshark used to be called Ethereal. It was renamed in 2006.' },
  { tag: 'TOOLS', text: 'Wazuh began as a fork of the open-source OSSEC host intrusion detection system.' },
  { tag: 'TOOLS', text: 'Kerberos is named after Cerberus, the three-headed dog of Greek myth: three parties are involved in the protocol.' },
  { tag: 'TOOLS', text: 'CAPTCHA stands for "Completely Automated Public Turing test to tell Computers and Humans Apart".' },
  { tag: 'TOOLS', text: 'MITRE ATT&CK began as an internal project in 2013 to record how real attackers behave, step by step.' },
  { tag: 'BUGS', text: 'Heartbleed (2014) came from a missing length check in OpenSSL\'s "heartbeat" feature. A single missing check exposed memory on many servers.' },
  { tag: 'BUGS', text: 'Log4Shell (December 2021) scored a perfect 10.0 and hit software that many teams did not realise contained the Log4j library.' },
  { tag: 'BUGS', text: '"Zero-day" means the vendor has had zero days to fix the flaw because attackers found it first.' },
  { tag: 'HABITS', text: 'The padlock in a browser means the connection is encrypted. It does not mean the site is honest. Phishing sites use padlocks too.' },
  { tag: 'HABITS', text: 'Year after year, "123456" sits near the top of the most common passwords. A password manager makes that problem disappear.' },
  { tag: 'HABITS', text: 'Phishing is a play on "fishing". The "ph" is a nod to phone phreakers, early phone-network hobbyists.' },
  { tag: 'HABITS', text: 'Industry breach reports repeatedly find that people are involved in around two thirds or more of breaches. Attackers often target people, not software.' },
  { tag: 'HABITS', text: 'Kevin Mitnick said he got most access by talking to people, not by cracking code. Social engineering is still the cheapest attack.' },
]

/** One fact per day, stable through the day, different tomorrow. */
export function factForDay(d: Date, shift = 0): Fact {
  const day = Math.floor(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()) / 86400000)
  return FACTS[(day + shift) % FACTS.length]
}
