import { useState, useMemo } from "react";

const allCards = [
  // ============================================================
  // HIGH PRIORITY — YOUR WEAKEST AREAS (Study These First!)
  // ============================================================
  
  // RISK MANAGEMENT (Your Hardest - 9 mistakes!)
  { category: "🔴 HIGH PRIORITY", q: "Risk ID vs Assessment vs Analysis — what's the sequence? (You mixed these up 3 times!)", a: "1. Risk IDENTIFICATION = FINDING potential risks\n2. Risk ASSESSMENT = EVALUATING discovered risks\n3. Risk ANALYSIS = Deeper evaluation\n4. Risk MANAGEMENT = Overall umbrella\n\n⚠️ THIS IS YOUR #1 REPEATED PATTERN!\n⚠️ Sequence: ID → ASSESS → ANALYZE → MANAGE" },
  { category: "🔴 HIGH PRIORITY", q: "ALE formula — which is correct? (You got this wrong twice!)", a: "CORRECT: ALE = SLE × ARO\nALSO: SLE = AV × EF\n\n⚠️ NOT ALE = AV × EF!\n⚠️ This is a critical exam trap!" },
  { category: "🔴 HIGH PRIORITY", q: "Risk Avoidance vs Transference vs Deterrence — which is which?", a: "Avoidance = ELIMINATE the risk entirely (shut down/disable)\nTransference = Pass to SOMEONE ELSE (insurance, contracting)\nDeterrence = DISCOURAGE attacks (warning signs)\n\n⚠️ Contracting out = TRANSFERENCE\n⚠️ Shutting down = AVOIDANCE" },
  { category: "🔴 HIGH PRIORITY", q: "Exception vs Exemption in risk acceptance?", a: "EXCEPTION = choosing NOT TO APPLY controls for a specific risk (permanent)\nEXEMPTION = TEMPORARILY not complying with a standard/policy (temporary)\n\n⚠️ Exception = permanent choice. Exemption = temp non-compliance." },
  
  // PASSWORDS (Repeated 4+ times!)
  { category: "🔴 HIGH PRIORITY", q: "Spraying vs Birthday — which bypasses lockout? (You got this wrong 4 TIMES!)", a: "SPRAYING = ALWAYS bypasses lockout\n  → Few passwords × MANY accounts\n  → Each account sees only 1 failed attempt\n\nBirthday = Crypto hash collision attack\n  → NOTHING to do with lockout!\n\n⚠️ THIS IS YOUR MOST REPEATED MISTAKE!" },
  { category: "🔴 HIGH PRIORITY", q: "Min vs Max Password Age — which is which? (You reversed them twice!)", a: "MIN Password Age = how long you MUST KEEP before ALLOWED to change (WAIT period)\nMAX Password Age = how long before FORCED to change (EXPIRATION)\n\n⚠️ Min = wait period. Max = expiration period.\n⚠️ Don't reverse these!" },
  
  // AGREEMENTS (Repeated 5 times!)
  { category: "🔴 HIGH PRIORITY", q: "SLA vs SOW — which is which? (You swapped these 5 TIMES!)", a: "SLA = Service Level Agreement = PERFORMANCE requirements\nSOW = Statement of Work = WHAT WORK will be done\n\n⚠️ THIS IS YOUR #2 MOST REPEATED MISTAKE!\n⚠️ 'Performance' → SLA. 'Work scope' → SOW." },
  { category: "🔴 HIGH PRIORITY", q: "MOA vs MOU vs MSA — which is binding?", a: "MOA = BINDING, specific responsibilities\nMOU = NONBINDING, mutual goals (ONLY one that's nonbinding!)\nMSA = BINDING, foundational terms\n\n⚠️ MOU is the ONLY nonbinding agreement!" },
  
  // XSS/CSRF (Repeated 3 times!)
  { category: "🔴 HIGH PRIORITY", q: "XSS vs CSRF trust directions — which is which? (You mixed these up 3 TIMES!)", a: "XSS: BROWSER trusts WEBSITE\n  → Script injected into trusted site\n  → Script runs in USER'S BROWSER\n\nCSRF: WEBSITE trusts BROWSER\n  → User tricked into unauthorized requests\n  → Request runs on SERVER\n\n⚠️ Memory: CSRF = Client Requests Forge Server actions" },
  
  // VULNERABILITY MANAGEMENT (7 mistakes in one quiz!)
  { category: "🔴 HIGH PRIORITY", q: "STIX vs TAXII vs AIS — which is which? (You reversed these!)", a: "STIX = LANGUAGE for describing cyber threats\nTAXII = TRANSPORT mechanism for threat info\nAIS = US gov SHARING initiative (Automated Indicator Sharing)\n\n⚠️ You keep swapping STIX and AIS!" },
  { category: "🔴 HIGH PRIORITY", q: "False Positive vs False Negative — which is which?", a: "False Positive = alarm raised when NO attack\nFalse Negative = NO alarm when attack DID happen\n\n⚠️ You said false positive for 'no alarm when attack happened' — that's FALSE NEGATIVE!" },
  { category: "🔴 HIGH PRIORITY", q: "FRR vs FAR vs CER — biometric errors?", a: "FRR = False Rejection Rate = REJECTS authorized user\nFAR = False Acceptance Rate = ACCEPTS unauthorized user\nCER = Crossover Error Rate = where FAR = FRR\n\n⚠️ You said CER for 'rejects user' — that's FRR!" },
  { category: "🔴 HIGH PRIORITY", q: "Vuln Scanning vs Pen Testing — active or passive?", a: "Vuln Scanning = PASSIVELY tests\nPen Testing = ACTIVELY tests, bypasses controls, exploits\n\n⚠️ You said vuln scanning 'actively tests' — WRONG!" },
  { category: "🔴 HIGH PRIORITY", q: "What is Exposure Factor (EF)?", a: "EF = The DEGREE OF LOSS (as a PERCENTAGE) that a realized threat would have on a specific asset.\n\n⚠️ NOT likelihood of exploitation (that's ARO)!\n⚠️ EF = % of asset value lost" },
  
  // SECURITY CONTROLS
  { category: "🔴 HIGH PRIORITY", q: "Technical vs Managerial vs Operational vs Physical — which is which?", a: "Technical = implemented by SYSTEMS (firewalls, encryption)\nManagerial = written POLICIES (security policy, risk assessments)\nOperational = done by PEOPLE daily (backups, patches, config mgmt)\nPhysical = protects MATERIAL assets (guards, fencing, locks)\n\n⚠️ Firewall = TECHNICAL (not physical!)\n⚠️ Backup = OPERATIONAL (not physical!)" },
  
  // ENCRYPTION
  { category: "🔴 HIGH PRIORITY", q: "Symmetric vs Asymmetric — what's the key difference?", a: "Symmetric = SAME key for encrypt and decrypt (secret key)\n  → FASTER, less overhead\n  → AES, DES, 3DES\n\nAsymmetric = KEY PAIR (public + private keys)\n  → SLOWER, more overhead\n  → RSA, ECC, DHE\n\n⚠️ Symmetric ≠ public-key (that's asymmetric!)" },
  { category: "🔴 HIGH PRIORITY", q: "ECDSA vs ECDHE — what does each do?", a: "ECDSA = Digital SIGNATURES using ECC\nECDHE = Key EXCHANGE using ECC\n\n⚠️ You said ECDHE for IoT signing — WRONG!\n⚠️ ECDSA = signatures. ECDHE = exchange." },
  
  // DATA PROTECTION
  { category: "🔴 HIGH PRIORITY", q: "Data At Rest vs In Transit vs In Use — encryption status?", a: "At Rest = CAN be encrypted (FDE, SED, EFS)\nIn Transit = CAN be encrypted (VPN, IPsec, TLS)\nIn Use = MUST be UNENCRYPTED (CPU needs raw data!)\n\n⚠️ Only 'in use' requires unencrypted form." },
  
  // ============================================================
  // REGULAR CATEGORIES (Organized by topic)
  // ============================================================
  
  // --- ATTACK TYPES ---
  { category: "Attacks", q: "What type of injection targets directory services like Active Directory?", a: "LDAP Injection\n\nKey phrase: 'managing/accessing networked resources'" },
  { category: "Attacks", q: "What type of injection targets data that is stored and transported?", a: "XML Injection\n\nKey phrase: 'store and transport data'" },
  { category: "Attacks", q: "What is the ACTION/METHOD behind an XSS attack?", a: "Code Injection\n\n⚠️ NOT session hijacking — that's the RESULT, not the method!" },
  { category: "Attacks", q: "What's the difference between a Threat Vector and a Consequence?", a: "Threat Vector = HOW the attack happens (method)\nConsequence = WHAT happens after (result)\n\nEx: Malware = vector. Data breach = consequence." },
  { category: "Attacks", q: "Is phishing a client-based or agentless threat?", a: "Client-Based\n\n⚠️ It requires email client software + user action. Agentless = network-level attacks like packet sniffing." },
  { category: "Attacks", q: "What facilitates privilege escalation? (Pick 3)", a: "1. System/app vulnerabilities\n2. System/app misconfigurations\n3. Social engineering\n\n⚠️ Password hashing does NOT — it's a defense!" },

  // --- CRYPTO ATTACKS ---
  { category: "Crypto", q: "Which attack BYPASSES account lockout policies?", a: "Spraying Attack\n\n⚠️ Few passwords × MANY accounts = each account sees only 1 failed attempt. Never triggers lockout!" },
  { category: "Crypto", q: "What is a Birthday Attack?", a: "An attack that finds HASH COLLISIONS using probability.\n\n⚠️ It's a CRYPTO concept — has nothing to do with bypassing lockout!" },
  { category: "Crypto", q: "What does Pass the Hash do?", a: "Authenticates to a remote server using a captured hash — WITHOUT needing the cleartext password." },
  { category: "Crypto", q: "What is the difference between a Dictionary and Brute-Force attack?", a: "Dictionary = tries common/known passwords\nBrute-Force = tries ALL possible combinations\n\nBoth target a single account and get locked out." },

  // --- NETWORK SECURITY ---
  { category: "Network", q: "What's the difference between IDS and IPS?", a: "IDS = Detection only (alerts)\nIPS = Prevention (blocks threats)\n\n⚠️ IDS CANNOT block! Add 'P' for Prevention = blocks." },
  { category: "Network", q: "Which firewall layer is faster and why?", a: "Layer 4 (Stateful) = FASTER, basic inspection\nLayer 7 (Next-Gen) = SLOWER, deep content inspection\n\nMore inspection = slower performance!" },
  { category: "Network", q: "What is DNS Cache Poisoning?", a: "Remaps a domain to a ROGUE IP address in the DNS cache.\n\n⚠️ Not 'URL hijacking' — that's not the correct term." },
  { category: "Network", q: "Bluejacking vs Bluesnarfing — what's the difference?", a: "Bluejacking = sends unsolicited MESSAGES\nBluesnarfing = GAINS unauthorized ACCESS to data\n\n⚠️ 'Gaining access' = Bluesnarfing!" },

  // --- VPN & IPSEC ---
  { category: "VPN/IPsec", q: "What does IKE do in IPsec?", a: "IKE = Internet Key Exchange\nIt sets up the tunnel and NEGOTIATES encryption keys.\n\n⚠️ ESP does the actual encryption — IKE just sets it up!" },
  { category: "VPN/IPsec", q: "ESP vs AH — what's the key difference?", a: "ESP = Encapsulating Security Payload → ENCRYPTS + authenticates\nAH = Authentication Header → Authenticates ONLY (no encryption)" },
  { category: "VPN/IPsec", q: "What's the difference between Split Tunnel and Full Tunnel VPN?", a: "Split Tunnel = Some traffic through VPN, some goes public\nFull Tunnel = ALL traffic routed through VPN" },

  // --- AUTHENTICATION ---
  { category: "Auth ★", q: "TACACS+ vs RADIUS: Which encrypts the ENTIRE payload?", a: "TACACS+ encrypts the ENTIRE payload\nRADIUS encrypts PASSWORD ONLY\n\n⚠️ Memory trick: T = Total encryption. R = just password." },
  { category: "Auth ★", q: "TACACS+ vs RADIUS: Which one SEPARATES authentication and authorization?", a: "TACACS+ SEPARATES auth and authz\nRADIUS COMBINES auth and authz\n\n⚠️ Alphabet trick: R = Combines (C). T = Separates (S). C comes before S!" },
  { category: "Auth ★", q: "What is PEAP and what does it do?", a: "PEAP = Protected EAP\nIt encapsulates authentication inside an encrypted TLS tunnel.\n\n⚠️ RADIUS is the SERVER. PEAP is the METHOD used with it." },
  { category: "Auth ★", q: "Which EAP method is the MOST secure?", a: "EAP-TLS — it uses certificates on BOTH client and server.\n\nPEAP = server cert only. EAP-TLS = both sides." },

  // --- WIRELESS ---
  { category: "Wireless", q: "What is 802.1X?", a: "Port-based Network Access Control\n\n⚠️ NOT 802.11! 802.11 is the wireless standard. 802.1X controls WHO gets access to the network." },
  { category: "Wireless", q: "What's the strongest personal wireless security?", a: "WPA3-SAE (Simultaneous Authentication of Equals)\n\nIt's the strongest for personal/home networks." },

  // --- MOBILE ---
  { category: "Mobile", q: "Containerization vs Storage Segmentation — what's the difference?", a: "Containerization = ISOLATES corporate apps from personal apps\nStorage Segmentation = CONTROLS/separates corporate and personal DATA\n\n⚠️ Isolates APPS vs Controls DATA" },
  { category: "Mobile", q: "What does MDM stand for and what does it do?", a: "MDM = Mobile Device Management\nIt provides CENTRALIZED management of mobile devices.\n\n⚠️ Think MDM first for ANY mobile management question!" },

  // --- RAID & DR ---
  { category: "RAID/DR", q: "What is the minimum number of drives for RAID 10?", a: "4 drives minimum\n\n⚠️ NOT 5! RAID 10 = stripe of mirrors (RAID 1 mirroring + RAID 0 striping)" },
  { category: "RAID/DR", q: "Which DR site has the fastest recovery?", a: "Hot Site — it has real-time replicated data and is always ready.\n\nHot = fastest/most expensive. Cold = slowest/cheapest." },
  { category: "RAID/DR", q: "Clustering vs Replication — what's the difference?", a: "Clustering = Groups servers for HIGH AVAILABILITY\nReplication = Creates a copy on a SEPARATE system in real-time\n\n⚠️ Clustering = HA. Replication ≠ mirroring!" },

  // --- CLOUD ---
  { category: "Cloud", q: "CSP vs MSP — what's the difference?", a: "CSP = Cloud Service Provider (provides cloud services)\nMSP = Managed Service Provider (manages IT services)\n\n⚠️ 'Cloud provider' = CSP!" },
  { category: "Cloud", q: "ICS vs SCADA — which is broader?", a: "ICS = Industrial Control Systems (BROAD — covers all industrial controls)\nSCADA = Supervisory Control & Data Acquisition (SPECIFIC type of ICS)\n\n⚠️ ICS is the umbrella. SCADA is under it." },

  // --- DATA PROTECTION ---
  { category: "Data", q: "Which data state MUST be unencrypted and why?", a: "Data in Use must be UNENCRYPTED\n\nThe CPU/RAM cannot process encrypted data — it needs the raw data to work with it.\n\n⚠️ Data at Rest CAN be encrypted!" },
  { category: "Data", q: "Who is the DPO and what do they do?", a: "DPO = Data Protection Officer\nOversees compliance with data protection LAWS (GDPR, privacy)\n\n⚠️ NOT the CTO! CTO manages tech strategy." },
  { category: "Data", q: "IoC vs AIS — which is the actual forensic evidence?", a: "IoC = Indicator of Compromise = the actual EVIDENCE of an attack\nAIS = Automated Indicator Sharing = the SYSTEM that shares IoCs\n\n⚠️ IoC = evidence. AIS = sharing platform." },

  // --- SECURE PROTOCOLS ---
  { category: "Protocols", q: "POP3S vs IMAPS: Which one can MANAGE emails on the server?", a: "IMAPS can manage emails on the server\nPOP3S only downloads and deletes — NO management\n\n⚠️ 'Management' → IMAPS ONLY!\n'Retrieval' → either POP3S or IMAPS" },
  { category: "Protocols", q: "What is SFTP and what port does it use?", a: "SFTP = SSH File Transfer Protocol\nRuns on port 22 (same as SSH)\n\n⚠️ SFTP uses SSH — it is NOT FTP over SSL (that's FTPS)!" },
  { category: "Protocols", q: "What replaced Telnet for secure remote access?", a: "SSH (Secure Shell) on port 22\n\nIt provides encryption, authentication, and integrity for remote sessions." },
  { category: "Protocols", q: "Is SMTPS still used for secure email sending?", a: "No — SMTPS is DEPRECATED\n\nThe modern secure method is SMTP + STARTTLS on port 587." },

  // --- ACCESS CONTROLS ---
  { category: "Access Ctrl", q: "Which access control model is the STRICTEST?", a: "MAC (Mandatory Access Control)\n\nAdmin controls everything — users CANNOT change policies. Uses labels and clearance levels." },
  { category: "Access Ctrl", q: "What's the difference between RBAC and ABAC?", a: "RBAC = permissions based on JOB ROLE\nABAC = permissions based on multiple ATTRIBUTES (subject, action, resource, environment)\n\nABAC is more flexible and uses natural language-like rules." },
  { category: "Access Ctrl", q: "What is the Principle of Least Privilege?", a: "Users can ONLY access what their job requires — nothing more.\n\nPrevents accessing info/resources beyond the scope of their responsibilities." },

  // --- PASSWORDS ---
  { category: "Passwords", q: "Minimum Password Age vs Maximum Password Age — what's the difference?", a: "Minimum = How long you must KEEP a password before you're ALLOWED to change it\nMaximum = How long before you're FORCED to change it\n\n⚠️ Min = wait period. Max = expiration!" },
  { category: "Passwords", q: "What does salting do and why is it important?", a: "Salting adds pseudo-random data to a password BEFORE hashing.\n\nIt defeats rainbow table attacks because each hash is unique even for the same password." },
  { category: "Passwords", q: "What is key stretching?", a: "A technique that repeatedly applies a resource-intensive algorithm to increase computational effort needed to crack passwords.\n\nMakes brute-force, dictionary, and rainbow table attacks much harder." },

  // --- INCIDENT RESPONSE ---
  { category: "Incident Resp", q: "E-Discovery vs Digital Forensics — what's the difference?", a: "E-Discovery = Collects evidence FOR LEGAL PROCEEDINGS (lawyer's job)\nDigital Forensics = INVESTIGATES what happened technically (detective's job)\n\n⚠️ 'Legal proceeding' → E-Discovery!" },
  { category: "Incident Resp", q: "Tabletop Exercise vs Simulation — what's the key difference?", a: "Tabletop = DISCUSSION only, no systems activated\nSimulation = IN-DEPTH, activates real systems and performs real actions\n\n⚠️ 'Realistic hands-on' = Simulation!" },
  { category: "Incident Resp", q: "What is a Chain of Custody?", a: "A documented record of the handling and movement of evidence to ensure its integrity and admissibility in court." },
  { category: "Incident Resp", q: "What does Threat Hunting mean?", a: "A PROACTIVE search for Indicators of Compromise (IoC) to find and address threats BEFORE they become full incidents.\n\n⚠️ Proactive = Threat Hunting. Reactive = Incident Response." },

  // --- RISK MANAGEMENT ---
  { category: "Risk Mgmt ★", q: "What is the correct ORDER of the risk process?", a: "1. Risk IDENTIFICATION (find risks)\n2. Risk ASSESSMENT (evaluate them)\n3. Risk ANALYSIS (dig deeper)\n4. Risk MANAGEMENT (overall process)\n\n⚠️ You can't assess before you identify!" },
  { category: "Risk Mgmt ★", q: "What is the formula for SLE and ALE?", a: "SLE = AV × EF (Single Loss Expectancy)\nALE = SLE × ARO (Annual Loss Expectancy)\n\n⚠️ ALE is NOT AV × EF — that's SLE!\nAV = Asset Value. EF = Exposure Factor. ARO = Annual Rate of Occurrence." },
  { category: "Risk Mgmt ★", q: "Exposure Factor (EF) vs ARO — what does each measure?", a: "EF = Exposure Factor = percentage of asset value LOST if threat occurs\nARO = Annual Rate of Occurrence = how OFTEN the threat happens per year\n\n⚠️ EF = degree of LOSS. ARO = how OFTEN." },
  { category: "Risk Mgmt ★", q: "Risk Appetite vs Risk Tolerance — what's the difference?", a: "Risk Appetite = GENERAL attitude toward risk-taking (broad)\nRisk Tolerance = SPECIFIC level of risk willing to accept (narrow)\n\n⚠️ Appetite = general feeling. Tolerance = specific limit." },
  { category: "Risk Mgmt ★", q: "Risk Avoidance vs Risk Deterrence — what's the difference?", a: "Risk Avoidance = ELIMINATE the risk entirely (shut it down)\nRisk Deterrence = DISCOURAGE attacks (make it harder)\n\n⚠️ 'Disabling/shutting down' = Avoidance!" },
  { category: "Risk Mgmt ★", q: "RPO vs RTO — what does each measure?", a: "RPO = Recovery Point Objective = max acceptable DATA LOSS (measured in time)\nRTO = Recovery Time Objective = max time to RESTORE operations\n\n⚠️ RPO = data loss limit. RTO = restore time limit." },
  { category: "Risk Mgmt ★", q: "MTTF vs MTBF vs MTTR — what's the difference?", a: "MTTF = Mean Time To FIRST Failure (new component)\nMTBF = Mean Time BETWEEN Failures (repairable component)\nMTTR = Mean Time To REPAIR\n\n⚠️ MTTF = to first failure. MTBF = between failures." },
  { category: "Risk Mgmt ★", q: "STIX vs TAXII vs AIS — what does each do?", a: "STIX = LANGUAGE for describing cyber threats\nTAXII = TRANSPORT mechanism for sharing threat intel\nAIS = US government SHARING initiative\n\n⚠️ STIX = Language. TAXII = Transport. AIS = Sharing." },
  { category: "Risk Mgmt ★", q: "FRR vs FAR vs CER — what does each mean?", a: "FRR = False Rejection Rate = REJECTS an authorized user\nFAR = False Acceptance Rate = ACCEPTS an unauthorized user\nCER = Crossover Error Rate = where FAR and FRR are EQUAL\n\n⚠️ FRR = kicks out good guy. FAR = lets in bad guy." },

  // --- DIGITAL CERTIFICATES & PKI ---
  { category: "Certs/PKI ★", q: "Digital Certificate vs Digital Signature — what's the difference?", a: "Certificate = VERIFIES IDENTITY (who are you?)\nSignature = VERIFIES AUTHENTICITY & INTEGRITY (did you send this?)\n\n⚠️ These are completely different jobs!\nCertificate = identity document. Signature = authenticity proof." },
  { category: "Certs/PKI ★", q: "What is the role of RA in PKI?", a: "RA = Registration Authority\n1. ACCEPTS requests for digital certificates\n2. AUTHENTICATES the entity making the request\n\n⚠️ RA does NOT issue certificates — that's the CA's job!" },
  { category: "Certs/PKI ★", q: "CA vs RA — what does each do?", a: "CA = Certificate Authority → ISSUES, revokes, manages certificates\nRA = Registration Authority → ACCEPTS requests + AUTHENTICATES the requester\n\n⚠️ RA is the gatekeeper. CA is the issuer." },
  { category: "Certs/PKI ★", q: "CRL vs OCSP — what's the difference?", a: "CRL = Certificate Revocation List → PERIODIC publication of ALL revoked certs\nOCSP = Online Cert Status Protocol → ON-DEMAND check of a SINGLE cert\n\n⚠️ Need to check ONE cert fast? → OCSP (fastest!)\nNeed full list of all revoked? → CRL" },
  { category: "Certs/PKI ★", q: "What is a self-signed certificate also called?", a: "NONE OF THE ABOVE — it has no special alias!\n\n⚠️ 'Client certificate' refers to certs used for client authentication, NOT self-signing.\nSelf-signed = issued by the entity to ITSELF. Free, not trusted by browsers by default." },
  { category: "Certs/PKI ★", q: "Wildcard vs SAN certificate — what's the difference?", a: "Wildcard = secures multiple SUBDOMAINS of ONE domain\n  → *.example.com covers sub1.example.com, sub2.example.com\nSAN = secures multiple DIFFERENT domain names\n  → one cert for example.com AND other-site.com" },
  { category: "Certs/PKI ★", q: "What is a CSR?", a: "CSR = Certificate Signing Request\nA cryptographic file GENERATED BY the entity requesting a certificate FROM the CA.\n\n⚠️ The entity creates the CSR → sends to CA → CA issues the certificate." },

  // --- HASHING ---
  { category: "Hashing", q: "What is a hash function and what does it guarantee?", a: "A mathematical algorithm that maps ANY size data → fixed-size hash (digest/checksum)\n\n★ Key guarantee: ANY change to input = completely different hash output\n\n⚠️ One-way only — you can't reverse a hash back to the original data!" },
  { category: "Hashing", q: "MD5 vs SHA vs SHA-3 — which is which?", a: "MD5 = DEPRECATED — known vulnerabilities, not for security\nSHA = Family of cryptographic hash functions (general use)\nSHA-3 = STRONGEST / highest security level\n\n⚠️ 'Deprecated hash?' → MD5. 'Strongest hash?' → SHA-3." },
  { category: "Hashing", q: "What is HMAC and how is it different from a regular hash?", a: "HMAC = Hash + secret KEY\n\nRegular hash = verifies DATA INTEGRITY only\nHMAC = verifies AUTHENTICITY + INTEGRITY (both!)\n\n⚠️ The secret key proves the sender actually sent it." },
  { category: "Hashing", q: "What is CRC and why is it different from crypto hashes?", a: "CRC = Cyclic Redundancy Check\n\nIt's a NON-cryptographic hash — used for ERROR-CHECKING only.\n\n⚠️ Not secure! Used for detecting transmission errors, not for security.\nMD5, SHA, HMAC = cryptographic. CRC = not cryptographic." },

  // --- DIGITAL SIGNATURES ---
  { category: "Dig Signatures ★", q: "Which algorithms are used for digital SIGNATURES? (3 answers)", a: "1. ECDSA\n2. RSA\n3. DSA\n\n⚠️ ECDHE is NOT a signature algorithm — it's KEY EXCHANGE!\nGPG/PGP are not algorithms — they're software tools." },
  { category: "Dig Signatures ★", q: "What is RSA based on? (Common trap!)", a: "RSA uses LARGE PRIME NUMBERS.\n\n⚠️ NOT discrete logarithm! That's DSA and DHE.\nRSA = large primes. DSA/DHE = discrete logarithm.\n\nRSA can: encrypt, sign, and do key exchange (versatile!)." },
  { category: "Dig Signatures ★", q: "ECDSA vs ECDHE — what does each do?", a: "ECDSA = Digital SIGNATURES using ECC\nECDHE = Key EXCHANGE using ECC\n\n⚠️ Both use ECC but they do DIFFERENT JOBS!\nFor IoT SIGNING → ECDSA\nFor IoT KEY EXCHANGE → ECDHE\n\nYou picked ECDHE for IoT signing — wrong category!" },
  { category: "Dig Signatures ★", q: "Best digital signature algorithm for IoT / smartcards / mobile?", a: "ECDSA — because it uses ECC which has:\n• Small key sizes\n• Low processing requirements\n• Efficient for constrained devices\n\n⚠️ NOT ECDHE (that's key exchange)!\n⚠️ NOT RSA (too heavy for low-power devices)." },
  { category: "Dig Signatures ★", q: "DSA — what can and can't it do?", a: "DSA = Digital Signature Algorithm\n\n✓ CAN: Create and verify digital signatures\n✗ CANNOT: Encrypt data (DSA is NOT an encryption algorithm!)\n\n⚠️ Uses discrete logarithm (not large primes — that's RSA)." },

  // --- THREAT ACTORS ---
  { category: "Threat Actors ★", q: "Threat actor resource/sophistication tiers — what's the order?", a: "LOW → HIGH:\n1. Unskilled Attacker = LOW resources, LOW sophistication\n2. Hacktivist = LOW-MEDIUM resources, LOW-MEDIUM sophistication\n3. Organized Crime = MEDIUM-HIGH resources, MEDIUM-HIGH sophistication\n4. Nation-State = HIGH resources, HIGH sophistication\n\n⚠️ You shifted everyone UP one tier — don't do that!" },
  { category: "Threat Actors ★", q: "What motivates each threat actor type?", a: "Nation-State: Espionage, political beliefs, disruption, WAR\nUnskilled: Disruption, financial gain, revenge\nHacktivist: ETHICAL/political beliefs, disruption\nInsider: Revenge, financial gain, service disruption\nOrg Crime: FINANCIAL gain, data exfiltration, EXTORTION\nShadow IT: Convenience, lack of awareness" },
  { category: "Threat Actors ★", q: "What is Shadow IT?", a: "Using IT systems, software, or services WITHOUT the IT department's approval or oversight.\n\n⚠️ It's an INTERNAL threat.\nMotivation: Convenience, meeting specific needs, lack of awareness of risks." },
  { category: "Threat Actors ★", q: "What is an APT?", a: "APT = Advanced Persistent Threat\n\nSophisticated and PROLONGED cyberattacks by well-funded, organized groups — typically NATION-STATES.\n\n⚠️ Key words: sophisticated, prolonged, well-funded → APT / Nation-State." },

  // --- THREAT VECTORS ---
  { category: "Threat Vectors", q: "What are the two threat vectors specific to removable devices?", a: "1. Malware delivery (USB drops malware onto system)\n2. Data exfiltration (USB used to steal data OUT)\n\n⚠️ Social engineering is NOT specific to removable devices — it's a broad technique that works via many channels." },
  { category: "Threat Vectors", q: "Client-based vs Agentless threat vectors — what's the difference?", a: "Client-Based = requires SOFTWARE on the device + user action\n  → Drive-by download, malicious macros, USB attacks, infected executables, email attachments\nAgentless = works at NETWORK level, no software needed\n  → Network protocol vulnerabilities, packet sniffing\n\n⚠️ Phishing = client-based (needs email client!)" },
  { category: "Threat Vectors", q: "What are the image-based threat vectors?", a: "1. Steganography (hidden data inside images)\n2. Image spoofing / deepfakes\n3. Malware-embedded images\n\n⚠️ BEC attacks and brand impersonation are NOT image-based vectors." },
  { category: "Threat Vectors", q: "Phishing vs Smishing vs Vishing — which channel is each?", a: "Phishing = EMAIL-based\nSmishing = SMS/text message-based\nVishing = VOICE/telephone-based\n\n⚠️ Easy memory trick: Smi-shing = SMS. Vi-shing = Voice." },

  // --- SOCIAL ENGINEERING ---
  { category: "Social Eng", q: "Misinformation vs Disinformation — what's the difference?", a: "Misinformation = false info spread UNINTENTIONALLY\nDisinformation = false info spread with INTENT to deceive\n\n⚠️ Intent is the key difference. Misinfo = accidental. Disinfo = deliberate." },
  { category: "Social Eng", q: "What is a watering hole attack?", a: "Attacker compromises a WEBSITE that the target frequently visits, then waits for the target to visit.\n\n⚠️ The platform = websites. It's like poisoning a watering hole that prey drinks from." },
  { category: "Social Eng", q: "Pretexting vs Impersonation — what's the difference?", a: "Pretexting = creates a FABRICATED SCENARIO to trick victim into revealing info\nImpersonation = relies on IDENTITY FRAUD (pretending to be someone else)\n\n⚠️ Pretexting = fake situation. Impersonation = fake identity." },
  { category: "Social Eng", q: "What is the BEST countermeasure against social engineering?", a: "User Education\n\n⚠️ Not situational awareness, not security controls — USER EDUCATION is the best defense against social engineering." },

  // --- SECURITY VULNERABILITIES ---
  { category: "Sec Vulns ★", q: "Are network-related vulnerabilities (DoS, RCE) considered OS-based?", a: "YES — they ARE OS-based vulnerabilities.\n\n⚠️ You said they were NOT. But DoS and RCE absolutely exploit OS-level resources.\nALL listed vulnerability types were OS-based — the answer was 'All of the above.'" },
  { category: "Sec Vulns ★", q: "XSS vs CSRF — which trust direction is which? (Common trap!)", a: "XSS: Browser trusts WEBSITE → attacker's script runs in USER'S BROWSER\n  ✓ 'Exploits trust browser has in website'\n  ✓ 'Script injected into trusted website'\n  ✓ 'Browser executes attacker's script'\n\nCSRF: Website trusts BROWSER → attacker's requests run on SERVER\n  ✓ 'Exploits trust website has in user's browser'\n  ✓ 'Website executes attacker's requests'\n\n⚠️ You mixed CSRF descriptions into the XSS answer!" },
  { category: "Sec Vulns ★", q: "What is a TOC/TOU vulnerability?", a: "Time Of Check / Time Of Use\n\nThe state of a resource is VERIFIED at one point but may CHANGE before it's actually used.\n\n⚠️ The gap between checking and using is the vulnerability window." },
  { category: "Sec Vulns ★", q: "Jailbreaking vs Rooting vs Sideloading — what's each?", a: "Jailbreaking = removing Apple iOS restrictions\nRooting = gaining admin access on ANDROID devices\nSideloading = installing apps from NON-official sources\n\n⚠️ Jailbreak = iOS. Root = Android. Sideload = any platform, unofficial install." },

  // --- NETWORK ATTACKS ---
  { category: "Net Attacks", q: "Amplified vs Reflected vs Volumetric DDoS — what's each?", a: "Amplified = exploits protocols to generate LARGER responses than original request\nReflected = uses third-party servers to REFLECT traffic toward target\nVolumetric = overwhelms target with sheer VOLUME of traffic\n\n⚠️ DNS amplification = amplified DDoS (small query → huge response)." },
  { category: "Net Attacks", q: "What is an on-path (MitM) attack?", a: "Attacker places themselves ON the communication route between two devices.\nThey can INTERCEPT or MODIFY packets between the two communicating parties.\n\n⚠️ Also called Man-in-the-Middle (MitM). They're IN the path, not just listening." },
  { category: "Net Attacks", q: "Session ID — where is it stored and what does it do?", a: "Session ID = unique identifier assigned by WEBSITE to a specific USER\nStored on CLIENT SIDE (user's browser) — in a cookie or URL parameter\nNOT stored on the server side\n\n⚠️ Does NOT contain credentials (username/password)." },

  // --- MALWARE ---
  { category: "Malware", q: "Virus vs Worm — what's the key difference?", a: "Virus = requires a HOST APPLICATION to run. Attaches itself to other programs.\nWorm = STANDALONE. Propagates itself over networks without needing a host.\n\n⚠️ Virus = needs a ride. Worm = travels on its own." },
  { category: "Malware", q: "What is a Logic Bomb?", a: "Malicious code activated by a SPECIFIC EVENT (trigger).\n\n⚠️ It's dormant until the trigger condition is met — like a time bomb with a fuse." },
  { category: "Malware", q: "Rootkit vs Backdoor vs Trojan — what does each do?", a: "Rootkit = masks intrusion + gets admin access (hides itself)\nBackdoor = hidden access point into a system\nTrojan = legitimate-looking program with hidden malicious code\n\n⚠️ Rootkit = hides. Backdoor = secret door. Trojan = disguise." },
  { category: "Malware", q: "Bloatware vs PUP — what's the difference?", a: "Bloatware = PRE-INSTALLED by manufacturer. Hurts performance.\nPUP = Potentially Unwanted Program. Can be pre-installed OR downloaded/bundled.\n    Hurts performance, privacy, AND security.\n\n⚠️ Bloatware = manufacturer puts it there. PUP = broader — also includes bundled software." },

  // --- DATA PROTECTION CONCEPTS ---
  { category: "Data Protect", q: "What protects data at rest vs data in transit? (Name the methods)", a: "At Rest: FDE, SED, EFS (encryption on stored data)\nIn Transit: VPN, IPsec, TLS (encryption on moving data)\n\n⚠️ IPsec and TLS = transit. SED and FDE = rest. EFS = rest (individual files).\nVPN, SSH, IPsec are NOT encryption 'tools' — they're protocols." },
  { category: "Data Protect", q: "Encryption vs Hashing vs Masking vs Tokenization vs Obfuscation — what's each?", a: "Encryption = plaintext → ciphertext (REVERSIBLE with key)\nHashing = input → fixed-size string (ONE-WAY, can't reverse)\nMasking = replaces sensitive data with FICTITIOUS data (same format)\nTokenization = replaces data with non-sensitive TOKEN (stored separately, retrievable)\nObfuscation = makes code/data hard to understand (NOT necessarily encrypted)" },
  { category: "Data Protect", q: "PII vs PHI vs PCI DSS — what does each protect?", a: "PII = Personally Identifiable Information (uniquely identifies a person)\nPHI = Protected Health Information (protected by HIPAA)\nPCI DSS = Payment Card Industry Data Security Standard (credit cardholder data)\n\n⚠️ GDPR = EU personal data privacy. HIPAA = US health data." },
  { category: "Data Protect", q: "Geofencing vs Geolocation — what's the difference?", a: "Geofencing = CONTROLS usage of device within a designated area (restricts)\nGeolocation = LOCATES the device (GPS tracks where it is)\n\n⚠️ Geofencing = restriction/boundary. Geolocation = finding location." },

  // --- APPLICATION ATTACKS ---
  { category: "App Attacks ★", q: "CSRF characteristics — which 3 are correct? (REPEATED MISTAKE!)", a: "CSRF = Website trusts BROWSER. These 3 are CSRF:\n✓ Exploits trust a WEBSITE has in the user's browser\n✓ User is TRICKED into submitting unauthorized web requests\n✓ WEBSITE executes attacker's requests\n\n⚠️⚠️⚠️ You've gotten this wrong 3 TIMES by swapping in XSS descriptions!\nXSS descriptions that are NOT CSRF: 'browser trusts website', 'script injected', 'browser executes script'" },
  { category: "App Attacks ★", q: "What is a directory traversal (dot-dot-slash) attack?", a: "An attack that uses '../' sequences to navigate OUTSIDE the intended directory and access files the app shouldn't expose.\n\n⚠️ Also called: dot-dot-slash attack\nANY URL with ../ sequences targeting /etc/passwd or similar = directory traversal indicator." },

  // --- INDICATORS OF MALICIOUS ACTIVITY ---
  { category: "Malicious Ind", q: "Key malicious activity indicators — what does each signal?", a: "Account Lockout → Password brute-forcing attempt\nConcurrent Session Usage → Single account used from MULTIPLE locations simultaneously\nImpossible Travel → Account accessed from physically impossible location\nBlocked Content → Firewall/security measure PREVENTED malicious payload\nMissing Logs → Attempt to HIDE evidence of malicious activity\nOut-of-Cycle Logging → Logs produced outside normal intervals (abnormal volume)" },
  { category: "Malicious Ind", q: "IoC vs CVE vs AIS vs OSINT — what's each?", a: "IoC = Indicator of Compromise → FORENSIC EVIDENCE of attack/unauthorized access\nCVE = Common Vulnerabilities and Exposures → vulnerability DATABASE\nAIS = Automated Indicator Sharing → SHARING system\nOSINT = Open Source Intelligence → publicly available info gathering\n\n⚠️ 'Forensic evidence?' → IoC (not CVE, AIS, or OSINT!)" },

  // --- ENCRYPTION ---
  { category: "Encryption ★", q: "SED vs FDE vs EFS — what's the difference?", a: "SED = Self-Encrypting Drive → HARDWARE encryption ON the drive\nFDE = Full Disk Encryption → SOFTWARE encrypts entire device\nEFS = Encrypting File System → Windows INDIVIDUAL file encryption\n\n⚠️ SED = hardware. FDE = software full disk. EFS = individual files." },
  { category: "Encryption ★", q: "Which are encryption SOFTWARE TOOLS? (GPG, PGP, VPN, SSH, IPsec)", a: "GPG and PGP are encryption software tools.\n\n⚠️ VPN, SSH, IPsec are protocols/systems — NOT encryption tools!\nGPG/PGP = tools designed specifically for implementing encryption algorithms." },
  { category: "Encryption ★", q: "Symmetric vs Asymmetric — which is which?", a: "Symmetric = SAME key encrypts & decrypts (secret-key)\n  → AES, DES, 3DES, RC4, IDEA\nAsymmetric = Key PAIR (public + private)\n  → RSA, ECC, DHE, ECDHE, ECDSA\n\n⚠️ Symmetric = FASTER. Asymmetric = SLOWER but more secure for key exchange." },
  { category: "Encryption ★", q: "Which algorithm generates temporary keys and provides forward secrecy?", a: "DHE (Diffie-Hellman Ephemeral)\n\n⚠️ NOT PGP! PGP is an encryption TOOL.\nDHE = the PROTOCOL that generates temp keys each session.\nPFS = the PROPERTY (forward secrecy) that DHE provides.\nThese are 3 completely different things!" },
  { category: "Encryption ★", q: "DHE vs PFS vs PGP — what is each?", a: "DHE = KEY EXCHANGE PROTOCOL (generates temporary keys)\nPFS = PROPERTY of forward secrecy (achieved BY DHE)\nPGP = Encryption SOFTWARE TOOL\n\n⚠️ DHE is the method. PFS is the result. PGP is unrelated — it's a tool!" },
  { category: "Encryption ★", q: "Which symmetric algorithm is the LEAST vulnerable / strongest?", a: "AES (Advanced Encryption Standard)\n\n⚠️ DES = deprecated. 3DES = also weak vs AES. RC4 = weak stream cipher.\nAES is the current gold standard." },
  { category: "Encryption ★", q: "Which algorithm is best for IoT / low-power / mobile devices?", a: "ECC (Elliptic Curve Cryptography)\n\nSmall key size + low computational power needed.\n\n⚠️ RSA needs large primes = too heavy for constrained devices.\nECC = best for IoT, embedded systems, mobile." },
  { category: "Encryption ★", q: "What does RSA use and what can it do?", a: "RSA uses large PRIME NUMBERS.\n\nIt can do 3 things:\n1. Secure key exchange\n2. Create digital signatures\n3. Encrypt data\n\n⚠️ RSA = the versatile asymmetric algorithm." },
  { category: "Encryption ★", q: "Block cipher modes — which is weakest and which is strongest?", a: "WEAKEST: ECB (Electronic Codebook) — each block independent, NOT recommended\nSTRONGEST: GCM — combines CTM encryption WITH authentication\n\nOthers: CBC = chaining. CFB = turns block into stream. CTM = counter mode." },
  { category: "Encryption ★", q: "What does SFTP use — is it FTP over SSL?", a: "NO — SFTP is an extension of SSH, NOT FTP over SSL.\n\nSFTP runs on port 22 (SSH's port).\nFTPS = FTP over SSL/TLS (ports 989/990)\n\n⚠️ Common trap: SFTP ≠ FTP+SSL. It's SSH File Transfer." },

  // --- SECURITY CONTROLS ---
  { category: "Sec Controls ★", q: "What are the 4 CATEGORIES of security controls?", a: "1. Technical (Logical) — executed by computer systems\n2. Managerial (Administrative) — written policies\n3. Operational — day-to-day procedures by people\n4. Physical — protects material assets\n\n⚠️ Each one answers: WHO or WHAT executes it?" },
  { category: "Sec Controls ★", q: "Is a Firewall a Physical security control?", a: "NO — it's a TECHNICAL control.\n\n⚠️ Firewalls are logical/software. Physical controls are things like fencing, locks, and guards that protect material assets." },
  { category: "Sec Controls ★", q: "Is Data Backup a Physical security control?", a: "NO — it's an OPERATIONAL control.\n\n⚠️ Backups are a process/procedure performed by people. Physical = protects material things." },
  { category: "Sec Controls ★", q: "What are the 6 TYPES of security controls?", a: "1. Preventive — STOP before it happens\n2. Deterrent — DISCOURAGE attacks\n3. Detective — FIND after it happens\n4. Corrective — FIX after incident\n5. Compensating — FILL THE GAP when primary fails\n6. Directive — TELL people what to do (policies)" },
  { category: "Sec Controls ★", q: "What is a Compensating security control?", a: "An ALTERNATIVE control used when the primary control is missing or inadequate — it fills the gap.\n\nExamples: Backup power, MFA, Network segmentation, Application sandboxing\n\n⚠️ Ask: 'What fills the gap when the normal control isn't enough?'" },
  { category: "Sec Controls ★", q: "Why is Application Sandboxing a Compensating control?", a: "Because it FILLS THE GAP when you can't fully vet/test an application.\n\nIt isolates the untrusted app so if it's compromised, damage is contained.\n\n⚠️ This is a tricky one — sandboxing compensates for lack of full app security testing!" },
  { category: "Sec Controls ★", q: "What are Directive security controls?", a: "Controls implemented through POLICIES and PROCEDURES — they TELL people what to do.\n\nExamples: IRP (Incident Response Plan), AUP (Acceptable Use Policy)\n\n⚠️ IDS, MFA, IPS are NOT directive — they're technical!" },
  { category: "Sec Controls ★", q: "Detective controls — give 5 examples.", a: "1. Log monitoring\n2. Security audits\n3. CCTV\n4. IDS (Intrusion Detection System)\n5. Vulnerability scanning\n\n⚠️ Detective = FIND threats AFTER they happen. They don't block!" },
  { category: "Sec Controls ★", q: "Corrective controls — give 4 examples.", a: "1. Recovering data from backup\n2. Applying patches to fix vulnerabilities\n3. Executing IRPs (Incident Response Plans)\n4. Activating DRPs (Disaster Recovery Plans)\n\n⚠️ Corrective = FIX things AFTER an incident." },
  { category: "Sec Controls ★", q: "What's the difference between Preventive and Deterrent controls?", a: "Preventive = actually STOPS the threat (encryption, firewalls, AV)\nDeterrent = DISCOURAGES the threat but doesn't stop it (warning signs, lighting, fencing)\n\n⚠️ Deterrent makes it less attractive. Preventive actually blocks it." },

  // --- DATA PROTECTION CONCEPTS ---
  { category: "Data Protect", q: "GDPR vs HIPAA vs PCI DSS — what does each protect?", a: "GDPR = EU citizens' personal data privacy\nHIPAA = PHI (Protected Health Information) in US\nPCI DSS = Credit cardholder data\n\n⚠️ PII = Personally Identifiable Information (general term)." },
  { category: "Data Protect", q: "Data at Rest vs In Transit vs In Use — encryption status?", a: "At Rest = CAN be encrypted (FDE, SED, EFS)\nIn Transit = CAN be encrypted (VPN, IPsec, TLS)\nIn Use = MUST be UNENCRYPTED (CPU needs raw data!)\n\n⚠️ Only 'in use' requires unencrypted form." },
  { category: "Data Protect", q: "Encryption vs Hashing vs Masking vs Tokenization vs Obfuscation — what's each?", a: "Encryption = reversible with key (plaintext → ciphertext)\nHashing = one-way, cannot reverse (fixed-size output)\nMasking = replaces with FICTITIOUS data (keeps format)\nTokenization = replaces with NON-SENSITIVE token (stored separately)\nObfuscation = makes hard to understand (not necessarily encrypted)" },
  { category: "Data Protect", q: "What is geofencing?", a: "Technology that CONTROLS device usage within a DESIGNATED AREA.\n\n⚠️ Not geolocation (determines location). Not GPS (locator app functionality)." },

  // --- APPLICATION ATTACKS (CSRF EMPHASIS) ---
  { category: "App Attacks ★", q: "CSRF vs XSS — trust directions (AGAIN!)", a: "CSRF: Website trusts BROWSER\n  → User tricked into unauthorized REQUESTS\n  → WEBSITE executes attacker's requests\n\nXSS: BROWSER trusts website\n  → Script injected into trusted SITE\n  → BROWSER executes attacker's script\n\n⚠️ THIS IS THE THIRD TIME! Memorize the trust direction!" },
  { category: "App Attacks ★", q: "What is a directory traversal attack?", a: "Also called dot-dot-slash attack.\n\nUses ../ patterns in URLs to access unauthorized files.\n\nAny URL with ../ is a potential indicator:\n  http://example.com/var/../../etc/passwd" },

  // --- INDICATORS OF MALICIOUS ACTIVITY ---
  { category: "Malicious Ind", q: "IoC vs AIS — what's the difference?", a: "IoC = Indicator of Compromise = FORENSIC EVIDENCE of attack\nAIS = Automated Indicator Sharing = US gov SHARING initiative\n\n⚠️ IoC is the evidence itself. AIS is the system for sharing it." },
  { category: "Malicious Ind", q: "What does each malicious activity indicator signal?", a: "Account Lockout = password BRUTE-FORCING\nConcurrent Session Usage = same account, multiple locations simultaneously\nImpossible Travel = access from physically impossible location\nBlocked Content = firewall prevented malicious payload\nOut-of-Cycle Logging = logs outside regular intervals\nMissing Logs = attempt to HIDE evidence" },

  // --- RESILIENCE & RECOVERY ---
  { category: "RAID/DR ★", q: "RAID 5 vs RAID 6 — fault tolerance difference?", a: "RAID 5: Handles 1 drive failure (min 3 drives, striping + parity)\nRAID 6: Handles UP TO 2 drive failures (min 4 drives, double parity)\n\n⚠️ You missed: Both offer 'increased performance and fault tolerance with data re-creation by remaining drives'\n⚠️ RAID 6 does NOT continue with MORE than 2 failures — array destroyed!" },
  { category: "RAID/DR ★", q: "Clustering vs Parallel Processing — what's the difference?", a: "Clustering = GROUPS servers for HIGH AVAILABILITY and fault tolerance\nParallel Processing = DIVIDES tasks into subtasks, distributes across systems for SIMULTANEOUS execution\n\n⚠️ You said clustering for parallel processing — wrong!" },
  { category: "RAID/DR ★", q: "What are the key DR/HA concepts?", a: "Load Balancing = distributes WORKLOAD for performance\nClustering = groups servers for HA/fault tolerance\nReplication = real-time copy on separate system\nJournaling = recover changes since last backup\nFailover = switches to redundant system on disruption\nSnapshot = VM state at a point in time\nCOOP = US gov continuity of operations planning" },

  // --- VULNERABILITY MANAGEMENT ---
  { category: "Vuln Mgmt ★", q: "Vulnerability Scanning vs Penetration Testing — active or passive?", a: "Vuln Scanning = PASSIVELY tests, identifies lack of controls and misconfigs\nPen Testing = ACTIVELY tests, bypasses controls, exploits vulnerabilities\n\n⚠️ You said vuln scanning 'actively tests' — WRONG. That's pen testing!" },
  { category: "Vuln Mgmt ★", q: "STIX vs TAXII vs AIS — which is which? (You reversed these!)", a: "STIX = LANGUAGE for describing cyber threat info\nTAXII = TRANSPORT mechanism for cyber threat info\nAIS = US gov SHARING initiative (Automated Indicator Sharing)\n\n⚠️ You said STIX = US gov initiative. That's AIS!\n⚠️ Pattern #9 repeated — you keep reversing these!" },
  { category: "Vuln Mgmt ★", q: "False Positive vs False Negative — which is which?", a: "False Positive = alarm raised when NO attack (innocent flagged as threat)\nFalse Negative = NO alarm when attack DID happen (threat missed)\n\n⚠️ You said false positive for 'no alarm when attack happened' — that's false NEGATIVE!" },
  { category: "Vuln Mgmt ★", q: "FRR vs FAR vs CER — biometric error rates?", a: "FRR = False Rejection Rate = REJECTS authorized user (kicks out good guy)\nFAR = False Acceptance Rate = ACCEPTS unauthorized user (lets in bad guy)\nCER = Crossover Error Rate = where FAR = FRR\n\n⚠️ You said CER for 'rejects authorized user' — that's FRR!" },
  { category: "Vuln Mgmt ★", q: "What is Exposure Factor (EF) in vulnerability analysis?", a: "EF = The DEGREE OF LOSS that a realized threat would have on a specific asset.\nExpressed as a PERCENTAGE of asset value that would be lost.\n\n⚠️ NOT likelihood of exploitation (that's ARO)!\n⚠️ NOT impact on organization (that's broader).\nEF = specific % of THIS asset lost." },
  { category: "Vuln Mgmt ★", q: "What is the dark web?", a: "The dark web:\n✓ Requires specialized software to access (Tor, I2P)\n✓ Not indexed by traditional search engines\n✓ Associated with stolen data, malware, cyber threats\n✗ Does NOT form a large part of the deep web (it's a SMALL part!)\n\n⚠️ You said 'requires specialized software' doesn't apply — WRONG!" },
  { category: "Vuln Mgmt ★", q: "CVSS vs CVE vs ATT&CK — what does each do?", a: "CVSS = SCORES severity of vulnerabilities (rating system)\nCVE = DATABASE of publicly known vulnerabilities\nATT&CK = FRAMEWORK for understanding TTPs used in attacks\n\nTTP = Tactics, Techniques, Procedures (HOW attackers operate)" },

  // --- WIRELESS SECURITY ---
  { category: "Wireless", q: "WPA3-SAE vs WPA2/WPA3-Enterprise — when to use each?", a: "WPA3-SAE = STRONGEST for networks WITHOUT authentication server (small networks, home)\nWPA2/WPA3-Enterprise = Requires RADIUS server + 802.1X (large corporate networks)\n\n⚠️ Enterprise mode = suitable for large corporate, requires RADIUS." },

  // --- PASSWORDS ---
  { category: "Passwords ★", q: "Min vs Max password age — which is which? (You reversed them AGAIN!)", a: "MIN Password Age = how long you MUST KEEP before ALLOWED to change (wait period)\nMAX Password Age = how long before FORCED to change (expiration)\n\n⚠️ Min = wait. Max = expiration.\n⚠️ THIS IS PATTERN #4 — you keep reversing these!" },
  { category: "Passwords ★", q: "Spraying vs Birthday — which bypasses lockout? (FOURTH TIME!)", a: "SPRAYING = ALWAYS bypasses account lockout\n  → Few passwords × MANY accounts\n  → Each account sees only 1 attempt\n\nBirthday = CRYPTO attack (hash collisions)\n  → Nothing to do with lockout!\n\n⚠️ THIS IS THE FOURTH TIME YOU'VE MIXED THESE UP!" },
  { category: "Passwords", q: "What is key stretching and how does it help?", a: "Repeatedly applies a resource-intensive function to input data.\n\nIncreases computational effort to derive original key/password.\n\nMakes data more resistant to brute-force, dictionary, and rainbow table attacks.\n\n⚠️ Works alongside salting for password protection." },

  // --- RISK MANAGEMENT (HARDEST - 9 MISTAKES!) ---
  { category: "Risk Mgmt ★", q: "Risk ID vs Assessment vs Analysis vs Management — what's the sequence? (You mixed these up TWICE!)", a: "1. Risk IDENTIFICATION = FINDING potential risks\n2. Risk ASSESSMENT = EVALUATING discovered risks\n3. Risk ANALYSIS = Deeper evaluation\n4. Risk MANAGEMENT = Overall umbrella process\n\n⚠️ Sequence: ID → ASSESS → ANALYZE → MANAGE\n⚠️ THIS IS PATTERN #5 — you keep confusing these steps!" },
  { category: "Risk Mgmt ★", q: "Ad hoc vs One-time vs Recurring vs Continuous — which is which?", a: "Ad Hoc = response to specific EVENTS (breach, org change)\nOne-Time = specific PURPOSE/project (new product launch)\nRecurring = regular scheduled (quarterly/annual)\nContinuous = real-time monitoring\n\n⚠️ Event-driven = ad hoc. Project-specific = one-time." },
  { category: "Risk Mgmt ★", q: "ALE vs SLE formulas — which is which? (You mixed them up AGAIN!)", a: "SLE = AV × EF (Single Loss Expectancy)\nALE = SLE × ARO (Annual Loss Expectancy)\n\n⚠️ NOT ALE = AV × EF!\n⚠️ THIS IS PATTERN #6 — remember the sequence!" },
  { category: "Risk Mgmt ★", q: "What is ARO? (You said SLA!)", a: "ARO = Annual Rate of Occurrence\n\nEstimate based on HISTORICAL DATA of how often a threat would successfully exploit a vulnerability.\n\n⚠️ NOT SLA (Service Level Agreement)!" },
  { category: "Risk Mgmt ★", q: "Exception vs Exemption — what's the difference?", a: "EXCEPTION = choosing NOT TO APPLY controls/safeguards for a specific risk\nEXEMPTION = TEMPORARILY not complying with a standard/policy\n\n⚠️ Exception = permanent choice. Exemption = temporary non-compliance." },
  { category: "Risk Mgmt ★", q: "Risk Avoidance vs Transference vs Deterrence — which is which?", a: "Avoidance = ELIMINATE the risk entirely (disable/shut down)\nTransference = Transfer to SOMEONE ELSE (insurance, contracting out)\nDeterrence = DISCOURAGE attacks (warning signs)\n\n⚠️ THIS IS PATTERN #8 REPEATED!\n⚠️ Contracting out specialized work = TRANSFERENCE (not avoidance)!\n⚠️ Shutting down system = AVOIDANCE (not deterrence)!" },

  // --- INCIDENT RESPONSE ---
  { category: "Incident Resp", q: "What activities belong to EACH IR stage?", a: "PREPARATION: Establish IR capability, team, policy\nDETECTION & ANALYSIS: Identify, understand scope/impact/root cause\nCONTAINMENT/ERADICATION/RECOVERY: Mitigate, eliminate, restore\nPOST-INCIDENT: Update plans/policies, root cause analysis\n\n⚠️ Establishing IR policy = PREPARATION (not containment!)" },
  { category: "Incident Resp", q: "Tabletop vs Simulation — what's the difference?", a: "Tabletop = DISCUSSION-based, walk through scenarios, NO system activation\nSimulation = IN-DEPTH, activates systems, performs real actions\n\n⚠️ Tabletop = talk about it. Simulation = do it." },

  // --- AGREEMENTS ---
  { category: "Agreements ★", q: "SLA vs SOW — which is which? (FIFTH TIME mixing these up!)", a: "SLA = Service Level Agreement = PERFORMANCE requirements\nSOW = Statement of Work = WHAT WORK will be done\n\n⚠️ THIS IS PATTERN #4 — FIFTH TIME!\n⚠️ 'Performance' → SLA. 'Work scope' → SOW." },
  { category: "Agreements ★", q: "MOA vs MOU vs MSA — which is binding?", a: "MOA = Memorandum of Agreement = BINDING, specific responsibilities\nMOU = Memorandum of Understanding = NONBINDING, mutual goals\nMSA = Master Service Agreement = BINDING, foundational terms\n\n⚠️ MOU = ONLY nonbinding!\n⚠️ MSA = foundational/master (not MOU)!" },

  // --- PENETRATION TESTING ---
  { category: "Pen Testing", q: "Red vs Blue vs White vs Purple teams — what does each do?", a: "RED = Attackers\nBLUE = Defenders\nWHITE = Referees/overseers\nPURPLE = RED + BLUE collaboration (NOT all three!)\n\n⚠️ Purple = red+blue working together, NOT integrated role of all teams!" },
  { category: "Pen Testing", q: "White-box vs Gray-box vs Black-box testing — what's the difference?", a: "White-box = FULL knowledge of system internals\nGray-box = LIMITED access to information\nBlack-box = NO prior knowledge\n\n⚠️ More knowledge = lighter box. No knowledge = black box." },
  { category: "Pen Testing", q: "Active vs Passive reconnaissance — which is which? (You reversed them!)", a: "PASSIVE = publicly available info, NO interaction (OSINT)\nACTIVE = invasive tools, INTERACTS with target (pinging, port scanning, fingerprinting)\n\n⚠️ You said active = public info. WRONG!\n⚠️ Passive = no touching. Active = poking around." },

  // --- AGREEMENTS ---
  { category: "Agreements", q: "SLA vs SOW — what's the difference?", a: "SLA = Service Level Agreement = defines PERFORMANCE REQUIREMENTS\nSOW = Statement of Work = describes WHAT WORK will be done\n\n⚠️ 'Performance requirements' → SLA. 'Work/project' → SOW." },
  { category: "Agreements", q: "MOA vs MOU — what's the KEY difference?", a: "MOA = Memorandum of Agreement = LEGALLY BINDING, specific responsibilities\nMOU = Memorandum of Understanding = NONBINDING, general cooperation goals\n\n⚠️ MOU is the ONLY nonbinding one!" },
  { category: "Agreements", q: "What is an MSA?", a: "MSA = Master Service Agreement\nA legally binding contract that sets FOUNDATIONAL TERMS for future agreements between two parties." },
  { category: "Agreements", q: "What is a BPA?", a: "BPA = Business Partnership Agreement\nOutlines rights, responsibilities, and obligations between BUSINESS PARTNERS." },
  { category: "Agreements", q: "What is an NDA?", a: "NDA = Non-Disclosure Agreement\nA legal contract that restricts someone from sharing CONFIDENTIAL information." },
];

const categories = ["All", ...new Set(allCards.map(c => c.category))];

export default function App() {
  const [selectedCat, setSelectedCat] = useState("All");
  const [currentIdx, setCurrentIdx] = useState(0);
  const [flipped, setFlipped] = useState(false);
  const [known, setKnown] = useState({});
  const [mode, setMode] = useState("quiz"); // quiz or review
  const [shuffled, setShuffled] = useState(false);
  const [deck, setDeck] = useState(allCards);

  const filtered = useMemo(() => {
    let cards = selectedCat === "All" ? deck : deck.filter(c => c.category === selectedCat);
    return cards;
  }, [selectedCat, deck]);

  const card = filtered[currentIdx] || filtered[0];
  const progress = Object.keys(known).filter(k => known[k] === true).length;
  const total = filtered.length;
  const knownInFiltered = filtered.filter((c, i) => known[`${selectedCat}-${i}`] === true).length;

  const shuffle = () => {
    const arr = [...allCards].sort(() => Math.random() - 0.5);
    setDeck(arr);
    setShuffled(true);
    setCurrentIdx(0);
    setFlipped(false);
  };

  const next = () => {
    setFlipped(false);
    setTimeout(() => setCurrentIdx((currentIdx + 1) % filtered.length), 150);
  };

  const prev = () => {
    setFlipped(false);
    setTimeout(() => setCurrentIdx((currentIdx - 1 + filtered.length) % filtered.length), 150);
  };

  const markKnown = (val) => {
    setKnown(prev => ({ ...prev, [`${selectedCat}-${currentIdx}`]: val }));
    setTimeout(() => next(), 300);
  };

  const isKnown = known[`${selectedCat}-${currentIdx}`];

  return (
    <div style={{ minHeight: "100vh", background: "linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%)", padding: "16px", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>
      {/* HEADER */}
      <div style={{ textAlign: "center", marginBottom: "12px" }}>
        <h1 style={{ margin: 0, fontSize: "22px", color: "#f1f5f9", fontWeight: 700, letterSpacing: "-0.5px" }}>
          🎯 Security+ Study Cards
        </h1>
        <p style={{ margin: "4px 0 0", color: "#64748b", fontSize: "13px" }}>
          For testing — flip cards to reveal answers
        </p>
      </div>

      {/* MODE TOGGLE */}
      <div style={{ display: "flex", justifyContent: "center", gap: "8px", marginBottom: "10px" }}>
        {["quiz", "review"].map(m => (
          <button key={m} onClick={() => setMode(m)} style={{
            padding: "5px 14px", borderRadius: "20px", border: "1px solid",
            borderColor: mode === m ? "#3b82f6" : "#334155",
            background: mode === m ? "#3b82f6" : "transparent",
            color: mode === m ? "#fff" : "#94a3b8", fontSize: "12px", cursor: "pointer", fontWeight: 600,
            textTransform: "capitalize", transition: "all 0.2s"
          }}>
            {m === "quiz" ? "📋 Quiz Mode" : "📖 Review Mode"}
          </button>
        ))}
        <button onClick={shuffle} style={{
          padding: "5px 14px", borderRadius: "20px", border: "1px solid #334155",
          background: "transparent", color: "#94a3b8", fontSize: "12px", cursor: "pointer", fontWeight: 600, transition: "all 0.2s"
        }}>
          🔀 Shuffle
        </button>
      </div>

      {/* CATEGORY PILLS */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", justifyContent: "center", marginBottom: "12px", maxWidth: "720px", margin: "0 auto 12px" }}>
        {categories.map(cat => {
          const isActive = selectedCat === cat;
          const hasStar = cat.includes("★");
          return (
            <button key={cat} onClick={() => { setSelectedCat(cat); setCurrentIdx(0); setFlipped(false); }} style={{
              padding: "4px 11px", borderRadius: "16px", border: "1px solid",
              borderColor: isActive ? (hasStar ? "#f59e0b" : "#3b82f6") : "#334155",
              background: isActive ? (hasStar ? "rgba(245,158,11,0.15)" : "rgba(59,130,246,0.15)") : "transparent",
              color: isActive ? (hasStar ? "#f59e0b" : "#60a5fa") : "#64748b",
              fontSize: "11px", cursor: "pointer", fontWeight: 600, transition: "all 0.2s",
              whiteSpace: "nowrap"
            }}>
              {cat}
            </button>
          );
        })}
      </div>

      {/* PROGRESS BAR */}
      <div style={{ maxWidth: "600px", margin: "0 auto 14px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
          <span style={{ color: "#64748b", fontSize: "11px" }}>Card {currentIdx + 1} of {filtered.length}</span>
          <span style={{ color: "#64748b", fontSize: "11px" }}>
            {selectedCat === "All" ? `${progress} known` : `${knownInFiltered} known in this category`}
          </span>
        </div>
        <div style={{ height: "3px", background: "#1e293b", borderRadius: "2px", overflow: "hidden", border: "1px solid #334155" }}>
          <div style={{ height: "100%", width: `${((currentIdx + 1) / filtered.length) * 100}%`, background: "linear-gradient(90deg, #3b82f6, #8b5cf6)", borderRadius: "2px", transition: "width 0.3s" }} />
        </div>
      </div>

      {/* FLIP CARD */}
      <div style={{ maxWidth: "600px", margin: "0 auto" }}>
        <div onClick={() => setFlipped(!flipped)} style={{
          perspective: "1000px", cursor: "pointer", height: "280px", marginBottom: "14px"
        }}>
          <div style={{
            position: "relative", width: "100%", height: "100%",
            transformStyle: "preserve-3d",
            transform: flipped ? "rotateY(180deg)" : "rotateY(0deg)",
            transition: "transform 0.5s cubic-bezier(0.4, 0.2, 0.2, 1)"
          }}>
            {/* FRONT - QUESTION */}
            <div style={{
              position: "absolute", width: "100%", height: "100%", backfaceVisibility: "hidden",
              background: "linear-gradient(145deg, #1e293b, #1a2332)",
              borderRadius: "16px", border: "1px solid #334155",
              padding: "24px", display: "flex", flexDirection: "column", justifyContent: "space-between",
              boxShadow: "0 4px 24px rgba(0,0,0,0.3)"
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{
                  background: card.category.includes("★") ? "rgba(245,158,11,0.15)" : "rgba(59,130,246,0.12)",
                  color: card.category.includes("★") ? "#f59e0b" : "#60a5fa",
                  padding: "3px 10px", borderRadius: "12px", fontSize: "11px", fontWeight: 600,
                  border: `1px solid ${card.category.includes("★") ? "rgba(245,158,11,0.3)" : "rgba(59,130,246,0.2)"}`
                }}>
                  {card.category}
                </span>
                <span style={{ color: "#475569", fontSize: "11px" }}>tap to flip</span>
              </div>
              <div>
                <p style={{ color: "#e2e8f0", fontSize: "17px", lineHeight: 1.5, margin: 0, fontWeight: 500 }}>
                  {card.q}
                </p>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <div style={{ width: "28px", height: "28px", borderRadius: "50%", background: "rgba(59,130,246,0.15)", border: "1px solid #3b82f6", display: "flex", alignItems: "center", justifyContent: "center" }}>
                  <span style={{ color: "#60a5fa", fontSize: "14px" }}>❓</span>
                </div>
                <span style={{ color: "#475569", fontSize: "12px" }}>Question</span>
                {isKnown === true && <span style={{ marginLeft: "auto", color: "#22c55e", fontSize: "11px", fontWeight: 600 }}>✓ Known</span>}
                {isKnown === false && <span style={{ marginLeft: "auto", color: "#ef4444", fontSize: "11px", fontWeight: 600 }}>✗ Study more</span>}
              </div>
            </div>

            {/* BACK - ANSWER */}
            <div style={{
              position: "absolute", width: "100%", height: "100%", backfaceVisibility: "hidden",
              transform: "rotateY(180deg)",
              background: "linear-gradient(145deg, #1a2e1a, #162016)",
              borderRadius: "16px", border: "1px solid #2d5a2d",
              padding: "24px", display: "flex", flexDirection: "column", justifyContent: "space-between",
              boxShadow: "0 4px 24px rgba(0,0,0,0.3)"
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ background: "rgba(34,197,94,0.12)", color: "#4ade80", padding: "3px 10px", borderRadius: "12px", fontSize: "11px", fontWeight: 600, border: "1px solid rgba(34,197,94,0.3)" }}>
                  Answer
                </span>
                <span style={{ color: "#475569", fontSize: "11px" }}>tap to flip back</span>
              </div>
              <div style={{ flex: 1, display: "flex", alignItems: "center" }}>
                <p style={{ color: "#d4edda", fontSize: "14px", lineHeight: 1.6, margin: 0, whiteSpace: "pre-line" }}>
                  {card.a}
                </p>
              </div>
              <div style={{ display: "flex", gap: "6px" }}>
                <span style={{ color: "#475569", fontSize: "11px", marginBottom: "2px" }}>Did you know it?</span>
              </div>
            </div>
          </div>
        </div>

        {/* BUTTONS */}
        <div style={{ display: "flex", gap: "8px", justifyContent: "center", marginBottom: "16px" }}>
          <button onClick={prev} style={{
            padding: "8px 18px", borderRadius: "10px", border: "1px solid #334155",
            background: "#1e293b", color: "#94a3b8", fontSize: "13px", cursor: "pointer", fontWeight: 600, transition: "all 0.2s"
          }}>← Prev</button>

          {flipped && (
            <>
              <button onClick={() => markKnown(false)} style={{
                padding: "8px 20px", borderRadius: "10px", border: "1px solid #ef4444",
                background: "rgba(239,68,68,0.12)", color: "#f87171", fontSize: "13px", cursor: "pointer", fontWeight: 600, transition: "all 0.2s"
              }}>✗ Didn't Know</button>
              <button onClick={() => markKnown(true)} style={{
                padding: "8px 20px", borderRadius: "10px", border: "1px solid #22c55e",
                background: "rgba(34,197,94,0.12)", color: "#4ade80", fontSize: "13px", cursor: "pointer", fontWeight: 600, transition: "all 0.2s"
              }}>✓ Got It!</button>
            </>
          )}

          <button onClick={next} style={{
            padding: "8px 18px", borderRadius: "10px", border: "1px solid #334155",
            background: "#1e293b", color: "#94a3b8", fontSize: "13px", cursor: "pointer", fontWeight: 600, transition: "all 0.2s"
          }}>Next →</button>
        </div>

        {/* INSTRUCTIONS FOR WIFE */}
        <div style={{
          background: "rgba(59,130,246,0.06)", border: "1px solid rgba(59,130,246,0.2)",
          borderRadius: "12px", padding: "14px 18px", maxWidth: "600px", margin: "0 auto"
        }}>
          <p style={{ color: "#60a5fa", fontSize: "12px", fontWeight: 700, margin: "0 0 6px", textTransform: "uppercase", letterSpacing: "0.5px" }}>
            💡 How to Use This
          </p>
          <div style={{ color: "#94a3b8", fontSize: "12px", lineHeight: 1.7 }}>
            <p style={{ margin: "0 0 4px" }}>
              <strong style={{ color: "#cbd5e1" }}>1.</strong> Read the <strong style={{ color: "#e2e8f0" }}>question</strong> out loud to him.
            </p>
            <p style={{ margin: "0 0 4px" }}>
              <strong style={{ color: "#cbd5e1" }}>2.</strong> Let him answer — then <strong style={{ color: "#e2e8f0" }}>tap the card</strong> to reveal the answer.
            </p>
            <p style={{ margin: "0 0 4px" }}>
              <strong style={{ color: "#cbd5e1" }}>3.</strong> Click <strong style={{ color: "#4ade80" }}>✓ Got It!</strong> or <strong style={{ color: "#f87171" }}>✗ Didn't Know</strong> to track progress.
            </p>
            <p style={{ margin: "0 0 4px" }}>
              <strong style={{ color: "#cbd5e1" }}>4.</strong> Use <strong style={{ color: "#e2e8f0" }}>category filters</strong> above to focus on specific topics.
            </p>
            <p style={{ margin: 0 }}>
              <strong style={{ color: "#cbd5e1" }}>★</strong> Categories marked with <strong style={{ color: "#f59e0b" }}>★</strong> are his weakest areas — start there!
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
