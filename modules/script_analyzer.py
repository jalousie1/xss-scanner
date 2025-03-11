import re
import logging

class ScriptAnalyzer:
    def __init__(self, verbose=False):
        """Inicializa o analisador de scripts simplificado"""
        self.logger = logging.getLogger('ScriptAnalyzer')
        if not self.logger.handlers:
            level = logging.INFO if verbose else logging.WARNING
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
            handler.setLevel(level)
            self.logger.addHandler(handler)
            self.logger.setLevel(level)
        
        # Funções JavaScript críticas para segurança
        self.dangerous_js_functions = {
            'high_risk': [
                r'eval\s*\(', 
                r'document\.write\s*\(',
                r'innerHTML\s*=',
                r'outerHTML\s*=',
                r'setTimeout\s*\(\s*[\'"`]',
                r'setInterval\s*\(\s*[\'"`]',
                r'location\.href\s*=',
                r'document\.cookie\s*='
            ],
            'medium_risk': [
                r'\.ajax\s*\(',
                r'fetch\s*\(',
                r'XMLHttpRequest',
                r'\.src\s*=',
                r'document\.createElement\s*\('
            ]
        }
        
        # Padrões de obfuscação simplificados
        self.obfuscation_patterns = [
            r'String\.fromCharCode',
            r'atob\s*\(',
            r'\[\s*([\'"`])[^\1]+\1\s*\+\s*([\'"`])[^\2]+\2\s*\]'
        ]
        
    def analyze(self, scripts, html_context=None):
        """Analisa scripts para detectar possíveis vetores de XSS (versão simplificada)"""
        results = {
            'scripts_analyzed': len(scripts),
            'high_risk_scripts': 0,
            'medium_risk_scripts': 0,
            'script_analysis': [],
        }
        
        for i, script in enumerate(scripts):
            # Pular scripts externos ou vazios
            if script.get('type') == 'external' and not script.get('content'):
                continue
                
            content = script.get('content', '')
            if not content:
                continue
                
            # Análise simplificada
            script_analysis = self._analyze_script_simplified(content, i)
            results['script_analysis'].append(script_analysis)
            
            # Contagem de riscos
            if script_analysis['risk_level'] == 'high':
                results['high_risk_scripts'] += 1
            elif script_analysis['risk_level'] == 'medium':
                results['medium_risk_scripts'] += 1
                
        return results
        
    def _analyze_script_simplified(self, script_content, script_id):
        """Versão simplificada da análise de script"""
        result = {
            'id': f"script_{script_id}",
            'risk_level': 'safe',
            'risk_score': 0,
            'dangerous_functions': [],
            'obfuscation_detected': False
        }
        
        # 1. Detectar funções de alto risco
        high_risk_matches = []
        for pattern in self.dangerous_js_functions['high_risk']:
            matches = list(re.finditer(pattern, script_content))
            if matches:
                high_risk_matches.extend(matches)
                result['dangerous_functions'].append({
                    'pattern': pattern,
                    'match': matches[0].group(),
                    'risk': 'high'
                })
                
        # 2. Detectar funções de médio risco apenas se necessário
        if not high_risk_matches:
            for pattern in self.dangerous_js_functions['medium_risk']:
                matches = list(re.finditer(pattern, script_content))
                if matches:
                    result['dangerous_functions'].append({
                        'pattern': pattern,
                        'match': matches[0].group(),
                        'risk': 'medium'
                    })
        
        # 3. Detectar obfuscação básica
        for pattern in self.obfuscation_patterns:
            if re.search(pattern, script_content):
                result['obfuscation_detected'] = True
                break
                
        # Calcular pontuação de risco simplificada
        high_risk_count = len([f for f in result['dangerous_functions'] if f['risk'] == 'high'])
        medium_risk_count = len([f for f in result['dangerous_functions'] if f['risk'] == 'medium'])
        
        risk_score = high_risk_count * 25 + medium_risk_count * 10
        if result['obfuscation_detected']:
            risk_score += 20
            
        result['risk_score'] = min(100, risk_score)
        
        # Determinar nível de risco
        if risk_score >= 70:
            result['risk_level'] = 'high'
        elif risk_score >= 40:
            result['risk_level'] = 'medium'
        elif risk_score >= 10:
            result['risk_level'] = 'low'
            
        return result
