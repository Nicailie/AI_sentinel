import re
import json
from typing import Dict, List, Tuple
from dataclasses import dataclass

@dataclass
class CyberThreatFlag:
    """Represents a detected cyber threat"""
    type: str
    severity: str
    description: str
    confidence: float
    matched_pattern: str = ""
    mitre_technique: str = ""

class CyberThreatDetector:
    """Analyzes content for cybersecurity threats"""
    
    def __init__(self):
        self._init_exploit_patterns()
        self._init_malware_patterns()
        self._init_attack_keywords()
        
    def _init_exploit_patterns(self):
        """comprehensive and lenient exploit patterns"""
        self.exploit_patterns = {
            'sql_injection': {
                'patterns': [
                    r"or\s+['\"]?1['\"]?\s*=\s*['\"]?1",  # or 1=1
                    r"or\s+['\"][^'\"]+['\"]?\s*=\s*['\"][^'\"]+",  # or 'x'='xz
                    r"union\s+(all\s+)?select",
                    # SQL comments
                    r"--\s*$",  # SQL comment
                    r"/\*.*\*/",  # Multi-line comment
                    # Statement manipulation
                    r";\s*(drop|delete|update|insert)",
                    # Time-based blind
                    r"sleep\s*\(\s*\d+\s*\)",
                    r"benchmark\s*\(",
                    r"pg_sleep",
                    r"waitfor\s+delay",
                    # Stacked queries
                    r";\s*select\s+",
                    # Schema enumeration
                    r"information_schema",
                    r"sysobjects|syscolumns",
                    # Authentication bypass
                    r"admin['\"]?\s*--",
                    r"['\"]?\s*or\s+['\"]?1",
                    # Parenthesis manipulation
                    r"\)\s*or\s*\(",
                    # WHERE clause manipulation
                    r"where\s+.*\s+or\s+",
                    # INSERT manipulation
                    r"insert\s+into\s+\w+.*values",
                    # MySQL specific
                    r"load_file\s*\(",
                    r"into\s+outfile",
                    # MSSQL specific
                    r"exec(\s|\()+xp_",
                    r"sp_executesql",
                ],
                'severity': 'high',
                'description': 'SQL injection pattern detected',
                'mitre': 'T1190 - Exploit Public-Facing Application'
            },
            'command_injection': {
                'patterns': [
                    # Shell commands after separators
                    r"[;&|]\s*(rm|wget|curl|nc|bash|sh|powershell|cmd|cat|ls|whoami|id|uname|chmod|chown)",
                    # Command substitution
                    r"\$\([^)]*\)",
                    r"`[^`]+`",
                    # Piping
                    r"\|\s*(bash|sh|nc|netcat)",
                    # Redirection
                    r">\s*/dev/tcp/",
                    r"2>&1",
                    # Common payload patterns
                    r"wget.*http.*\|",
                    r"curl.*http.*\|",
                    # Encoded commands
                    r"base64.*\|\s*bash",
                    # Python/Perl one-liners
                    r"python.*-c.*socket",
                    r"perl.*-e",
                ],
                'severity': 'high',
                'description': 'Command injection attempt detected',
                'mitre': 'T1059 - Command and Scripting Interpreter'
            },
            'path_traversal': {
                'patterns': [
                    r"\.\./",  # Any traversal
                    r"\.\.\\",
                    r"%2e%2e",  # URL encoded
                    r"/etc/(passwd|shadow)",
                    r"c:\\windows",
                    r"\\\\windows",
                ],
                'severity': 'high',  # Upgraded from medium
                'description': 'Path traversal attempt detected',
                'mitre': 'T1083 - File and Directory Discovery'
            },
            'privilege_escalation': {
                'patterns': [
                    r"\bsudo\b",
                    r"chmod\s+[0-7]{3,4}",
                    r"setuid|seteuid|setgid",
                    r"runas|elevate",
                    r"su\s+(root|-)",
                ],
                'severity': 'high',
                'description': 'Privilege escalation technique detected',
                'mitre': 'T1068 - Exploitation for Privilege Escalation'
            },
            'xss': {
                'patterns': [
                    r"<script",
                    r"</script>",
                    r"javascript:",
                    r"on\w+\s*=",  # Event handlers
                    r"<iframe",
                    r"document\.(cookie|location)",
                    r"\beval\s*\(",
                ],
                'severity': 'high',  # Upgraded from medium
                'description': 'Cross-Site Scripting (XSS) pattern detected',
                'mitre': 'T1189 - Drive-by Compromise'
            },
            'buffer_overflow': {
                'patterns': [
                    r"strcpy|strcat|sprintf|gets\s*\(",
                    r"memcpy.*sizeof",
                    r"A{20,}",
                    r"%s{5,}",
                ],
                'severity': 'high',
                'description': 'Potential buffer overflow vulnerability',
                'mitre': 'T1203 - Exploitation for Client Execution'
            },
        }
        
    def _init_malware_patterns(self):
        """Malware and obfuscation indicators"""
        self.malware_patterns = {
            'obfuscation': {
                'patterns': [
                    r"\beval\s*\(",
                    r"\bexec\s*\(",
                    r"base64_decode|atob|btoa",
                    r"fromCharCode",
                    r"ransomware",
                    r"\\x[0-9a-f]{2}",
                    r"chr\(\d+\)",
                ],
                'severity': 'medium',
                'description': 'Code obfuscation detected',
                'mitre': 'T1027 - Obfuscated Files or Information'
            },
            'reverse_shell': {
                'patterns': [
                    r"socket\s*\(",
                    r"connect\s*\(",
                    r"nc\s+-",
                    r"bash\s+-i",
                    r"/dev/tcp/",
                    r"powershell.*IEX",
                    r"downloadstring",
                ],
                'severity': 'high',
                'description': 'Reverse shell pattern detected',
                'mitre': 'T1071 - Application Layer Protocol'
            },
            'persistence': {
                'patterns': [
                    r"cron|crontab",
                    r"HKEY.*Run",
                    r"AppData.*Start Menu",
                    r"/etc/rc",
                    r"\.bashrc|\.bash_profile",
                ],
                'severity': 'medium',
                'description': 'Persistence mechanism detected',
                'mitre': 'T1053 - Scheduled Task/Job'
            },
            'credential_theft': {
                'patterns': [
                    r"mimikatz",
                    r"lsadump|sam\b",
                    r"secretsdump",
                    r"/etc/shadow",
                    r"HKLM\\SAM",
                    r"password.*dump",
                ],
                'severity': 'high',
                'description': 'Credential theft technique detected',
                'mitre': 'T1003 - OS Credential Dumping'
            },
        }
        
    def _init_attack_keywords(self):
        """Keywords indicating malicious intent"""
        self.attack_keywords = {
            'exploitation': [
                'exploit', 'payload', 'shellcode', 'metasploit',
                'zero-day', '0day', 'vulnerability', 'cve-'
            ],
            'reconnaissance': [
                'port scan', 'nmap', 'enumerate', 'brute force'
            ],
            'evasion': [
                'bypass', 'evade', 'disable defender', 'kill av'
            ]
        }
    
    def analyze(self, text: str) -> Dict:
        """Main analysis function"""
        text_lower = text.lower()
        
        # Run all detection layers
        exploit_flags = self._check_exploits(text, text_lower)
        malware_flags = self._check_malware(text, text_lower)
        keyword_flags = self._check_keywords(text_lower)
        
        all_flags = exploit_flags + malware_flags + keyword_flags
        risk_score = self._calculate_risk_score(all_flags)
        
        return {
            'risk_score': risk_score,
            'risk_level': self._get_risk_level(risk_score),
            'flags': [self._flag_to_dict(f) for f in all_flags],
            'summary': self._generate_summary(all_flags),
            'recommendations': self._get_recommendations(all_flags),
            'mitre_techniques': self._get_mitre_techniques(all_flags)
        }
    
    def _check_exploits(self, text: str, text_lower: str) -> List[CyberThreatFlag]:
        """Detect exploit patterns"""
        flags = []
        
        for category, info in self.exploit_patterns.items():
            matched = False
            for pattern in info['patterns']:
                if re.search(pattern, text_lower, re.IGNORECASE | re.MULTILINE):
                    flags.append(CyberThreatFlag(
                        type='exploit',
                        severity=info['severity'],
                        description=f"{info['description']} ({category})",
                        confidence=0.95,  # Increased confidence
                        matched_pattern=pattern[:50],
                        mitre_technique=info['mitre']
                    ))
                    matched = True
                    break
        
        return flags
    
    def _check_malware(self, text: str, text_lower: str) -> List[CyberThreatFlag]:
        """Detect malware indicators"""
        flags = []
        
        for category, info in self.malware_patterns.items():
            for pattern in info['patterns']:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    flags.append(CyberThreatFlag(
                        type='malware',
                        severity=info['severity'],
                        description=f"{info['description']} ({category})",
                        confidence=0.90,  # Increased
                        matched_pattern=pattern[:50],
                        mitre_technique=info['mitre']
                    ))
                    break
        
        return flags
    
    def _check_keywords(self, text: str) -> List[CyberThreatFlag]:
        """Check for attack-related keywords"""
        flags = []
        
        for category, keywords in self.attack_keywords.items():
            for keyword in keywords:
                if keyword in text:
                    severity = 'high' if category in ['exploitation', 'evasion'] else 'medium'
                    flags.append(CyberThreatFlag(
                        type='intent',
                        severity=severity,
                        description=f"Attack keyword: {category.replace('_', ' ')}",
                        confidence=0.80,
                        matched_pattern=keyword,
                        mitre_technique=""
                    ))
                    break
        
        return flags
    
    def _calculate_risk_score(self, flags: List[CyberThreatFlag]) -> float:
        """CRITICAL FIX: Properly weighted scoring"""
        if not flags:
            return 0.0
        
        # FIXED: Much higher base weights
        severity_weights = {
            'high': 75,      # Single HIGH flag = 70 points (reaches HIGH threshold)
            'medium': 42,    # Single MEDIUM = 40 points (reaches MEDIUM threshold)
            'low': 15
        }
        
        total = sum(severity_weights[f.severity] * f.confidence for f in flags)
        
        # Apply multiplier for multiple flags
        if len(flags) >= 3:
            total *= 1.4
        elif len(flags) >= 2:
            total *= 1.25
    
    # Boost for exploit + malware combination
        has_exploit = any(f.type == 'exploit' for f in flags)
        has_malware = any(f.type == 'malware' for f in flags)
        if has_exploit and has_malware:
            total *= 1.2
        
        return min(100.0, total)
    
    def _get_risk_level(self, score: float) -> str:
        """Risk level thresholds"""
        if score >= 55:
            return 'HIGH'
        elif score >= 28:
            return 'MEDIUM'
        return 'LOW'
    
    def _generate_summary(self, flags: List[CyberThreatFlag]) -> str:
        if not flags:
            return "No cybersecurity threats detected."
        
        counts = {
            'exploit': len([f for f in flags if f.type == 'exploit']),
            'malware': len([f for f in flags if f.type == 'malware']),
            'intent': len([f for f in flags if f.type == 'intent'])
        }
        
        parts = [f"{v} {k}(s)" for k, v in counts.items() if v > 0]
        return f"Detected: {', '.join(parts)}"
    
    def _get_recommendations(self, flags: List[CyberThreatFlag]) -> List[str]:
        recommendations = []
        
        if any(f.severity == 'high' for f in flags):
            recommendations.append("CRITICAL: Flag for security team review")
            recommendations.append("Block execution and quarantine")
        
        if any(f.type == 'exploit' for f in flags):
            recommendations.append("Scan with vulnerability tools")
        
        if any(f.type == 'malware' for f in flags):
            recommendations.append("Run through malware sandbox")
        
        if not recommendations:
            recommendations.append("Content appears safe")
        
        return recommendations
    
    def _get_mitre_techniques(self, flags: List[CyberThreatFlag]) -> List[str]:
        return list(set(f.mitre_technique for f in flags if f.mitre_technique))
    
    def _flag_to_dict(self, flag: CyberThreatFlag) -> Dict:
        return {
            'type': flag.type,
            'severity': flag.severity,
            'description': flag.description,
            'confidence': flag.confidence,
            'matched_pattern': flag.matched_pattern,
            'mitre_technique': flag.mitre_technique
        }