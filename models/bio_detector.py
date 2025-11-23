import re
import json
from typing import List, Dict, Tuple
from dataclasses import dataclass

@dataclass
class ThreatFlag:
    """Representing a detected threat"""
    type: str
    severity: str
    description: str    
    confidence: float
    matched_pattern: str = ""

class BioThreatDetector:
    """Analyzes content for biosecurity threats"""
    
    def __init__(self):
        self._init_sequence_patterns()
        self._init_intent_patterns()
        self._init_pathogen_keywords()

    def _init_sequence_patterns(self):
        """DNA/protein sequence patterns to flag"""
        self.sequence_patterns = {
            'dna_sequence': {
                'pattern': r'[ATGC]{30,}',
                'severity': 'medium',
                'description': 'DNA sequence detected - requires screening'
            },
            'protein_sequence': {
                'pattern': r'[ACDEFGHIKLMNPQRSTVWY]{20,}',
                'severity': 'medium', 
                'description': 'Protein sequence detected - requires verification'
            },
            'restriction_site': {
                'pattern': r'(GAATTC|GGATCC|AAGCTT|CTGCAG)',
                'severity': 'low',
                'description': 'Restriction enzyme site detected'
            }
        }
             
    def _init_intent_patterns(self):
        """FIXED: More comprehensive intent patterns"""
        self.intent_patterns = {
            'weaponization': {
                'keywords': [
                    'weaponize', 'weaponise', 'weaponization', 
                    'bioweapon', 'biological weapon', 'bio weapon',
                    'warfare agent', 'military application'
                ],
                'severity': 'high',
                'description': 'Weaponization intent detected'
            },
            'aerosol_delivery': {
                'keywords': [
                    'aerosolize', 'aerosolization', 'aerosol delivery', 
                    'airborne transmission', 'dispersion', 'atomize',
                    'spray delivery'
                ],
                'severity': 'high',
                'description': 'Aerosol delivery method discussed'
            },
            'gain_of_function': {
                'keywords': [
                    'gain of function', 'gain-of-function', 'GOF',
                    'enhanced virulence', 'increased transmissibility',
                    'enhanced pathogenicity', 'serial passage',
                    'directed evolution', 'mutation enhancement'
                ],
                'severity': 'high',
                'description': 'Gain-of-function research indicators'
            },
            'virulence_factors': {
                'keywords': [
                    'virulence factor', 'pathogenicity island', 
                    'toxin gene', 'immune evasion', 'host invasion',
                    'resistance mechanism'
                ],
                'severity': 'medium',
                'description': 'Virulence mechanism discussed'
            },
            'synthesis_intent': {
                'keywords': [
                    'synthesize pathogen', 'recreate virus', 'resurrect',
                    'de novo synthesis', 'artificial creation',
                    'laboratory creation', 'construct pathogen',
                    'engineer pathogen'
                ],
                'severity': 'high',
                'description': 'Pathogen synthesis intent detected'
            },
            'evasion': {
                'keywords': [
                    'evade detection', 'bypass screening', 'circumvent',
                    'avoid biosecurity', 'escape surveillance',
                    'hide from detection'
                ],
                'severity': 'high',
                'description': 'Security evasion discussed'
            },
            'cultivation': {
                'keywords': [
                    'culture', 'cultivate', 'grow', 'propagate',
                    'ferment', 'incubate', 'replicate'
                ],
                'severity': 'medium',
                'description': 'Pathogen cultivation discussed'
            },
            'toxin_production': {
                'keywords': [
                    'produce toxin', 'extract toxin', 'purify toxin',
                    'concentrate', 'isolate toxin', 'toxin synthesis'
                ],
                'severity': 'high',
                'description': 'Toxin production discussed'
            }
        }
    
    def _init_pathogen_keywords(self):
        """FIXED: Extended pathogen list with variations"""
        self.pathogen_keywords = {
            'select_agents': [
                # Bacteria
                'bacillus anthracis', 'anthrax', 'b. anthracis',
                'yersinia pestis', 'plague', 'y. pestis',
                'francisella tularensis', 'tularemia', 'f. tularensis',
                'burkholderia mallei', 'glanders',
                'burkholderia pseudomallei', 'melioidosis',
                'brucella', 'brucellosis',
                # Viruses
                'variola', 'smallpox', 'variola virus',
                'ebola', 'ebola virus', 'filovirus',
                'marburg', 'marburg virus',
                'lassa', 'lassa fever',
                'crimean-congo', 'cchf',
                # Toxins
                'botulinum', 'botulism', 'botulinum toxin',
                'ricin', 'ricin toxin',
                'saxitoxin', 'staphylococcal enterotoxin',
                't-2 toxin', 'abrin', 'aflatoxin'
            ],
            'pandemic_potential': [
                'h5n1', 'h7n9', 'h1n1', 'avian influenza', 'bird flu',
                'sars-cov', 'mers-cov', 'coronavirus',
                'nipah', 'nipah virus', 'hendra', 'hendra virus',
                'pandemic strain', 'highly pathogenic'
            ],
            'dual_use_organisms': [
                'escherichia coli', 'e. coli', 'e coli',
                'staphylococcus', 's. aureus',
                'streptococcus', 'clostridium'
            ]
        }
        
    def analyze(self, text: str) -> Dict:
        """Analyze the input text for biosecurity threats"""
        text_lower = text.lower()

        # Running all detection layers
        sequence_flags = self._check_sequences(text)
        intent_flags = self._check_intent(text_lower)
        pathogen_flags = self._check_pathogens(text_lower)
        
        # Combine all flags 
        all_flags = sequence_flags + intent_flags + pathogen_flags

        # Calculate overall risk score
        risk_score = self._calculate_risk_score(all_flags)
        
        return {
            'risk_score': risk_score,
            'risk_level': self._get_risk_level(risk_score),
            'flags': [self._flag_to_dict(flag) for flag in all_flags],
            'summary': self._generate_summary(all_flags),
            'recommendations': self._get_recommendations(all_flags)
        }
    
    def _check_sequences(self, text: str) -> List[ThreatFlag]:
        """Detecting biological sequences"""
        flags = []
        
        for name, pattern_info in self.sequence_patterns.items():
            matches = re.finditer(pattern_info['pattern'], text.upper())
            for match in matches:
                sequence = match.group()
                flags.append(ThreatFlag(
                    type='sequence',
                    severity=pattern_info['severity'],
                    description=f"{pattern_info['description']} (length: {len(sequence)})",
                    confidence=0.9,
                    matched_pattern=sequence[:50] + '...' if len(sequence) > 50 else sequence
                ))
        
        return flags    
    
    def _check_intent(self, text: str) -> List[ThreatFlag]:
        """FIXED: More lenient intent detection"""
        flags = []
        
        for category, info in self.intent_patterns.items():
            matched = False
            for keyword in info['keywords']:
                # Case-insensitive search
                if keyword in text:
                    flags.append(ThreatFlag(
                        type='intent',
                        severity=info['severity'],
                        description=info['description'],
                        confidence=0.90,  # Increased confidence
                        matched_pattern=keyword
                    ))
                    matched = True
                    break

        return flags
    


    def _check_pathogens(self, text: str) -> List[ThreatFlag]:
        """FIXED: More comprehensive pathogen detection"""
        flags = []
        
        # Check select agents (highest priority)
        for pathogen in self.pathogen_keywords['select_agents']:
            if pathogen in text:
                flags.append(ThreatFlag(
                    type='pathogen',
                    severity='high',
                    description=f'Select agent detected: {pathogen.title()}',
                    confidence=0.98,  # Very high confidence
                    matched_pattern=pathogen
                ))
                break  # Only flag once per category
        
        # Check pandemic potential pathogens
        if not flags:
            for pathogen in self.pathogen_keywords['pandemic_potential']:
                if pathogen in text:
                    flags.append(ThreatFlag(
                        type='pathogen',
                        severity='medium',
                        description=f'Pandemic-potential pathogen: {pathogen.upper()}',
                        confidence=0.92,
                        matched_pattern=pathogen
                    ))
                    break
        
        if not flags:
            for organism in self.pathogen_keywords['dual_use_organisms']:
                if organism in text:
                    # Only flag if combined with concerning keywords
                    concerning_context = any(word in text for word in [
                        'weaponiz', 'enhance', 'modify', 'engineer', 
                        'toxin', 'virulence', 'pathogen'
                    ])
                    if concerning_context:
                        flags.append(ThreatFlag(
                            type='pathogen',
                            severity='medium',
                            description=f'Dual-use organism in concerning context: {organism}',
                            confidence=0.85,
                            matched_pattern=organism
                        ))
                        break
        
        return flags
    
    def _calculate_risk_score(self, flags: List[ThreatFlag]) -> float:
        """CRITICAL FIX: Properly weighted scoring"""
        if not flags:
            return 0.0
        
        # FIXED: Much higher base weights
        severity_weights = {
            'high': 75,      # Single HIGH flag = 70 points (reaches HIGH threshold)
            'medium': 42,    # Single MEDIUM = 40 points (reaches MEDIUM threshold)
            'low': 15
        }
        
        total_score = sum(
            severity_weights[flag.severity] * flag.confidence 
            for flag in flags
        )
        
        # Apply multiplier for multiple flags
        if len(flags) >= 3:
            total_score *= 1.4
        elif len(flags) >= 2:
            total_score *= 1.25
        has_pathogen = any(f.type == 'pathogen' for f in flags)
        has_intent = any(f.type == 'intent' for f in flags)
        if has_pathogen and has_intent:
            total_score *= 1.3  # Major red flag
        # Cap at 100
        return min(100.0, total_score)
    
    def _get_risk_level(self, score: float) -> str:
        """Risk level thresholds"""
        if score >= 55:
            return 'HIGH'
        elif score >= 28:
            return 'MEDIUM'
        return 'LOW'
    
    def _generate_summary(self, flags: List[ThreatFlag]) -> str:
        """Generate a summary of detected threats"""
        if not flags:
            return "No biosecurity threats detected."
        
        high_flags = [flag for flag in flags if flag.severity == 'high']
        medium_flags = [flag for flag in flags if flag.severity == 'medium']
        low_flags = [flag for flag in flags if flag.severity == 'low']  

        summary_parts = []
        if high_flags:
            summary_parts.append(f"{len(high_flags)} high-severity threat(s)")
        if medium_flags:
            summary_parts.append(f"{len(medium_flags)} medium-severity threat(s)")
        if low_flags:
            summary_parts.append(f"{len(low_flags)} low-severity threat(s)")
        
        return f"Detected: {', '.join(summary_parts)}"
    
    def _get_recommendations(self, flags: List[ThreatFlag]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []

        if any(flag.severity == 'high' for flag in flags):
            recommendations.append("IMMEDIATE ACTION: Flag for human review by biosecurity experts")
            recommendations.append("Do not proceed with synthesis or implementation")
        
        if any(f.type == 'sequence' for f in flags):
            recommendations.append("Screen sequences through Common Mechanism or SecureDNA")
        
        if any(f.type == 'pathogen' for f in flags):
            recommendations.append("Verify legitimate research purpose and institutional oversight")
        
        if any(f.type == 'intent' for f in flags):
            recommendations.append("Review context and researcher credentials")
        
        if not recommendations:
            recommendations.append("Content appears safe for general research purposes")
        
        return recommendations

    def _flag_to_dict(self, flag: ThreatFlag) -> Dict:
        """Convert ThreatFlag to dictionary"""
        return {
            'type': flag.type,
            'severity': flag.severity,
            'description': flag.description,
            'confidence': flag.confidence,
            'matched_pattern': flag.matched_pattern
        }
    
    
        