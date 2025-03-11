import os
import logging
import json
from datetime import datetime

# Importar os analisadores
from modules.visual_analyzer import VisualAnalyzer
from modules.html_parser import HTMLParser
from modules.script_analyzer import ScriptAnalyzer

class XSSDetector:
    def __init__(self, verbose=False):
        """
        Inicializa o detector de XSS que integra análises visuais, HTML e de scripts
        
        Args:
            verbose (bool): Se True, exibe logs detalhados
        """
        self.verbose = verbose
        
        # Configurar logging
        level = logging.INFO if verbose else logging.WARNING
        self.logger = logging.getLogger('XSSDetector')
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            handler.setLevel(level)
            self.logger.addHandler(handler)
            self.logger.setLevel(level)
        
        # Inicializar analisadores
        self.visual_analyzer = VisualAnalyzer(verbose=verbose)
        self.html_parser = HTMLParser(verbose=verbose)
        self.script_analyzer = ScriptAnalyzer(verbose=verbose)
        
        self.logger.info("Detector de XSS inicializado")
    
    def analyze(self, page_data):
        """
        Analisa os dados de uma página em busca de vulnerabilidades XSS
        
        Args:
            page_data (dict): Dados da página obtidos pelo web crawler
            
        Returns:
            list: Lista de vulnerabilidades XSS encontradas
        """
        url = page_data['url']
        html = page_data['html']
        scripts = page_data['scripts']
        screenshot_path = page_data['screenshot_path']
        
        self.logger.info(f"Analisando página: {url}")
        vulnerabilities = []
        
        try:
            # 1. Análise visual dos elementos da página
            if screenshot_path and os.path.exists(screenshot_path):
                visual_analysis = self.visual_analyzer.analyze(screenshot_path)
            else:
                visual_analysis = None
                self.logger.warning(f"Screenshot não disponível para {url}")
            
            # 2. Análise do HTML
            html_analysis = self.html_parser.parse(html, url=url)
            
            # 3. Análise de scripts
            try:
                script_analysis = self.script_analyzer.analyze(scripts, html_analysis)
            except Exception as e:
                self.logger.error(f"Erro na análise de scripts: {str(e)}")
                script_analysis = {'script_analysis': [], 'high_risk_scripts': 0}
            
            # 4. Correlacionar resultados para detectar vulnerabilidades
            xss_vulnerabilities = self._correlate_analyses(
                url,
                visual_analysis,
                html_analysis,
                script_analysis,
                screenshot_path
            )
            
            vulnerabilities.extend(xss_vulnerabilities)
            self.logger.info(f"Análise concluída para {url}. Encontradas {len(vulnerabilities)} vulnerabilidades.")
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Erro ao analisar página {url}: {str(e)}")
            return []
    
    def _correlate_analyses(self, url, visual_analysis, html_analysis, script_analysis, screenshot_path):
        """
        Correlaciona os resultados das diferentes análises para identificar vulnerabilidades XSS
        
        Args:
            url (str): URL da página analisada
            visual_analysis (dict): Resultados da análise visual
            html_analysis (dict): Resultados da análise HTML
            script_analysis (dict): Resultados da análise de scripts
            screenshot_path (str): Caminho para o screenshot da página
            
        Returns:
            list: Lista de vulnerabilidades XSS detectadas
        """
        vulnerabilities = []
        
        # Categoria 1: Injeção de XSS em campos de entrada
        input_vulnerabilities = self._find_input_vulnerabilities(
            url, visual_analysis, html_analysis, script_analysis, screenshot_path
        )
        vulnerabilities.extend(input_vulnerabilities)
        
        # Categoria 2: Vulnerabilidades de XSS baseadas em eventos
        event_vulnerabilities = self._find_event_vulnerabilities(
            url, html_analysis, script_analysis, screenshot_path
        )
        vulnerabilities.extend(event_vulnerabilities)
        
        # Categoria 3: Vulnerabilidades de XSS em scripts
        script_vulnerabilities = self._find_script_vulnerabilities(
            url, html_analysis, script_analysis, screenshot_path
        )
        vulnerabilities.extend(script_vulnerabilities)
        
        # Categoria 4: Vulnerabilidades de XSS em URLs
        url_vulnerabilities = self._find_url_vulnerabilities(
            url, html_analysis, script_analysis, screenshot_path
        )
        vulnerabilities.extend(url_vulnerabilities)
        
        return vulnerabilities
    
    def _find_input_vulnerabilities(self, url, visual_analysis, html_analysis, script_analysis, screenshot_path):
        """
        Detecta vulnerabilidades XSS em campos de entrada
        
        Args:
            url (str): URL da página analisada
            visual_analysis (dict): Resultados da análise visual
            html_analysis (dict): Resultados da análise HTML
            script_analysis (dict): Resultados da análise de scripts
            screenshot_path (str): Caminho para o screenshot da página
            
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        vulnerabilities = []
        
        # Se não temos análise visual, usamos apenas a análise HTML
        if not visual_analysis:
            for input_elem in html_analysis['inputs']:
                if input_elem.get('suspicious', False):
                    vulnerabilities.append({
                        'type': 'input_xss',
                        'subtype': 'suspicious_attribute',
                        'url': url,
                        'element_type': input_elem['tag'],
                        'element_id': input_elem.get('id', ''),
                        'element_name': input_elem.get('name', ''),
                        'vulnerability': input_elem.get('xss_vector', 'Atributo suspeito'),
                        'severity': 'Médio',
                        'screenshot': screenshot_path,
                        'evidence': input_elem,
                        'description': f"Campo de entrada com potencial vulnerabilidade XSS: {input_elem.get('xss_vector', 'Atributo suspeito')}",
                        'recommendation': "Implementar validação de entrada e sanitização dos dados do usuário"
                    })
            return vulnerabilities
        
        # Correlacionar campos visuais com elementos HTML para detectar vulnerabilidades mais precisas
        for visual_input in visual_analysis['input_fields']:
            # Tentar encontrar o elemento HTML correspondente
            matching_html_inputs = self._find_matching_html_elements(visual_input, html_analysis['inputs'])
            
            for html_input in matching_html_inputs:
                # Verificar se esse input está sendo usado em scripts perigosos
                input_id = html_input.get('id', '')
                input_name = html_input.get('name', '')
                
                # Procurar uso perigoso deste campo em scripts
                dangerous_usage = False
                script_evidence = None
                
                for script_result in script_analysis['script_analysis']:
                    if 'user_input_handling' in script_result:
                        for input_handling in script_result['user_input_handling']:
                            context = input_handling.get('context', '')
                            if input_id and input_id in context:
                                if input_handling.get('dangerous_usage', False):
                                    dangerous_usage = True
                                    script_evidence = input_handling
                                    break
                            elif input_name and input_name in context:
                                if input_handling.get('dangerous_usage', False):
                                    dangerous_usage = True
                                    script_evidence = input_handling
                                    break
                
                # Se o input é suspeito ou tem uso perigoso, registrar vulnerabilidade
                if html_input.get('suspicious', False) or dangerous_usage:
                    severity = 'Alto' if dangerous_usage else 'Médio'
                    vuln_type = 'input_with_dangerous_usage' if dangerous_usage else 'suspicious_input'
                    
                    vulnerabilities.append({
                        'type': 'input_xss',
                        'subtype': vuln_type,
                        'url': url,
                        'element_type': html_input['tag'],
                        'element_id': html_input.get('id', ''),
                        'element_name': html_input.get('name', ''),
                        'visual_position': {
                            'x': visual_input['x'],
                            'y': visual_input['y'],
                            'width': visual_input['width'],
                            'height': visual_input['height']
                        },
                        'vulnerability': html_input.get('xss_vector', 'Manipulação insegura de entrada') if html_input.get('suspicious', False) else 'Uso perigoso em script',
                        'severity': severity,
                        'screenshot': screenshot_path,
                        'html_evidence': html_input,
                        'script_evidence': script_evidence,
                        'description': f"Campo de entrada com potencial vulnerabilidade XSS. " + 
                                       (f"Encontrado: {html_input.get('xss_vector', '')}" if html_input.get('suspicious', False) else "Entrada usada em contexto perigoso sem sanitização adequada."),
                        'recommendation': "Implementar validação de entrada e sanitização dos dados do usuário. Utilizar funções seguras para manipulação do DOM."
                    })
        
        return vulnerabilities
    
    def _find_event_vulnerabilities(self, url, html_analysis, script_analysis, screenshot_path):
        """
        Detecta vulnerabilidades XSS em manipuladores de eventos
        
        Args:
            url (str): URL da página analisada
            html_analysis (dict): Resultados da análise HTML
            script_analysis (dict): Resultados da análise de scripts
            screenshot_path (str): Caminho para o screenshot da página
            
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        vulnerabilities = []
        
        # Analisar manipuladores de eventos
        for handler in html_analysis['event_handlers']:
            # Todos os manipuladores de eventos são potencialmente perigosos
            # Verificar quais são mais críticos
            
            critical_handlers = False
            critical_reason = ""
            
            # Verificar handlers de maior risco
            for event, code in handler['handlers'].items():
                # Handlers que executam código em mouse/keyboard são mais críticos
                high_risk_events = ['onclick', 'onkeypress', 'onkeyup', 'onkeydown', 'onchange', 'onsubmit', 'onload', 'onerror']
                if event.lower() in high_risk_events:
                    # Verificar se o código contém funções perigosas
                    if any(danger in code.lower() for danger in ['eval(', 'function(', 'document.write', 'innerHTML', 'location']):
                        critical_handlers = True
                        critical_reason = f"Manipulador de evento {event} contém código perigoso: {code[:50]}..."
                        break
            
            severity = 'Alto' if critical_handlers else 'Médio'
            
            vulnerabilities.append({
                'type': 'event_handler_xss',
                'subtype': 'critical_handler' if critical_handlers else 'suspicious_handler',
                'url': url,
                'element_type': handler['tag_name'],
                'element_id': handler.get('id', ''),
                'element_class': handler.get('class', ''),
                'handlers': handler['handlers'],
                'vulnerability': critical_reason if critical_handlers else "Manipulador de evento pode permitir XSS",
                'severity': severity,
                'screenshot': screenshot_path,
                'evidence': handler,
                'description': critical_reason if critical_handlers else "Manipulador de evento que pode permitir a execução de código malicioso",
                'recommendation': "Evitar código JavaScript inline em atributos de eventos. Implementar validação e sanitização."
            })
        
        return vulnerabilities
    
    def _find_script_vulnerabilities(self, url, html_analysis, script_analysis, screenshot_path):
        """
        Detecta vulnerabilidades XSS em scripts
        
        Args:
            url (str): URL da página analisada
            html_analysis (dict): Resultados da análise HTML
            script_analysis (dict): Resultados da análise de scripts
            screenshot_path (str): Caminho para o screenshot da página
            
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        vulnerabilities = []
        
        # Verificar scripts de alto risco
        for script in script_analysis['script_analysis']:
            if script.get('risk_level') == 'high':
                # Scripts de alto risco são considerados vulnerabilidades
                
                # Encontrar os principais problemas no script
                key_issues = []
                
                # Adicionar funções perigosas
                for func in script.get('dangerous_functions', [])[:3]:  # Limitamos a 3 para não sobrecarregar
                    if func['risk'] == 'high':
                        key_issues.append(f"Função perigosa: {func['match']} em contexto: {func['context']}")
                
                # Adicionar manipulações de entrada sem sanitização
                for input_handler in script.get('user_input_handling', [])[:3]:
                    if input_handler.get('dangerous_usage', False) and not input_handler.get('sanitization_detected', False):
                        key_issues.append(f"Manipulação insegura de entrada: {input_handler['source']}")
                
                # Adicionar segmentos suspeitos
                for segment in script.get('suspicious_code_segments', [])[:3]:
                    key_issues.append(f"Código suspeito: {segment['match'] if 'match' in segment else segment['function']}")
                
                # Determinar o tipo específico de vulnerabilidade
                subtype = 'high_risk_script'
                if script.get('obfuscation_detected', False):
                    subtype = 'obfuscated_script'
                elif any('user_input_with_dangerous_function' in str(segment.get('type', '')) for segment in script.get('suspicious_code_segments', [])):
                    subtype = 'unsafe_input_handling'
                
                vulnerabilities.append({
                    'type': 'script_xss',
                    'subtype': subtype,
                    'url': url,
                    'script_id': script['id'],
                    'risk_score': script['risk_score'],
                    'key_issues': key_issues,
                    'vulnerability': "Script contém código que pode permitir ataques XSS",
                    'severity': 'Alto',
                    'screenshot': screenshot_path,
                    'evidence': {
                        'risk_level': script['risk_level'],
                        'risk_score': script['risk_score'],
                        'dangerous_functions_count': len(script.get('dangerous_functions', [])),
                        'user_input_handling_count': len(script.get('user_input_handling', [])),
                        'suspicious_segments_count': len(script.get('suspicious_code_segments', [])),
                        'obfuscated': script.get('obfuscation_detected', False)
                    },
                    'description': f"Script de alto risco com pontuação {script['risk_score']}/100. " + 
                                  f"Contém {len(script.get('dangerous_functions', []))} funções perigosas, " +
                                  f"{len(script.get('user_input_handling', []))} manipulações de entrada de usuário, e " +
                                  f"{len(script.get('suspicious_code_segments', []))} segmentos de código suspeitos.",
                    'recommendation': "Revisar o código JavaScript, implementar sanitização adequada para entradas de usuário, " +
                                     "e evitar funções perigosas como eval(), document.write(), e atribuições diretas a innerHTML."
                })
            
            elif script.get('risk_level') == 'medium' and script.get('risk_score', 0) >= 60:
                # Scripts de médio risco com pontuação alta também são incluídos
                vulnerabilities.append({
                    'type': 'script_xss',
                    'subtype': 'medium_risk_script',
                    'url': url,
                    'script_id': script['id'],
                    'risk_score': script['risk_score'],
                    'vulnerability': "Script contém código potencialmente inseguro",
                    'severity': 'Médio',
                    'screenshot': screenshot_path,
                    'evidence': {
                        'risk_level': script['risk_level'],
                        'risk_score': script['risk_score'],
                        'dangerous_functions_count': len(script.get('dangerous_functions', [])),
                        'user_input_handling_count': len(script.get('user_input_handling', [])),
                    },
                    'description': f"Script de médio risco com pontuação {script['risk_score']}/100 que pode conter vulnerabilidades.",
                    'recommendation': "Revisar o código JavaScript e implementar sanitização adequada para entradas de usuário."
                })
        
        # Verificar inline scripts suspeitos do HTML
        for script in html_analysis['inline_scripts']:
            if script.get('suspicious', False):
                patterns = script.get('suspicious_patterns', [])
                
                vulnerabilities.append({
                    'type': 'inline_script_xss',
                    'subtype': 'suspicious_inline_script',
                    'url': url,
                    'script_id': script['id'],
                    'patterns': patterns[:5],  # Limitamos a 5 padrões
                    'vulnerability': "Script inline contém padrões suspeitos",
                    'severity': 'Médio',
                    'screenshot': screenshot_path,
                    'evidence': script,
                    'description': f"Script inline com {len(patterns)} padrões suspeitos que podem indicar vulnerabilidades XSS.",
                    'recommendation': "Revisar script inline. Considerar mover para arquivo externo e implementar validação adequada."
                })
        
        return vulnerabilities
    
    def _find_url_vulnerabilities(self, url, html_analysis, script_analysis, screenshot_path):
        """
        Detecta vulnerabilidades XSS em URLs e parâmetros
        
        Args:
            url (str): URL da página analisada
            html_analysis (dict): Resultados da análise HTML
            script_analysis (dict): Resultados da análise de scripts
            screenshot_path (str): Caminho para o screenshot da página
            
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        vulnerabilities = []
        
        # Analisar links suspeitos
        for link in html_analysis['links']:
            if link.get('suspicious', False):
                vulnerabilities.append({
                    'type': 'url_xss',
                    'subtype': 'suspicious_link',
                    'url': url,
                    'link_url': link['href'],
                    'link_text': link.get('text', ''),
                    'vulnerability': link.get('xss_vector', 'Link suspeito'),
                    'severity': 'Médio',
                    'screenshot': screenshot_path,
                    'evidence': link,
                    'description': f"Link contém potencial vetor de XSS: {link.get('xss_vector', 'Link suspeito')}",
                    'recommendation': "Validar e sanitizar URLs antes de renderizar links."
                })
                
        # Analisar padrões suspeitos gerais
        for pattern in html_analysis['suspicious_patterns']:
            vulnerabilities.append({
                'type': 'pattern_xss',
                'subtype': 'suspicious_html_pattern',
                'url': url,
                'pattern': pattern['pattern'],
                'match': pattern['match'],
                'context': pattern['context'],
                'vulnerability': f"Padrão de código suspeito encontrado",
                'severity': 'Médio',
                'screenshot': screenshot_path,
                'evidence': pattern,
                'description': f"Padrão de código suspeito que pode indicar vulnerabilidade XSS: {pattern['match']}",
                'recommendation': "Revisar o código HTML e implementar sanitização adequada."
            })
        
        return vulnerabilities
    
    def _find_matching_html_elements(self, visual_element, html_elements):
        """
        Tenta encontrar elementos HTML que correspondam a elementos visuais detectados
        
        Args:
            visual_element (dict): Elemento visual detectado
            html_elements (list): Lista de elementos HTML
            
        Returns:
            list: Elementos HTML correspondentes ao elemento visual
        """
        # Esta é uma simplificação. Em um sistema real, seria necessário
        # um algoritmo mais sofisticado para correlacionar elementos visuais e HTML
        
        matching_elements = []
        
        # Nesta versão simplificada, consideramos todos os inputs de texto
        # como potenciais correspondências para campos de entrada visuais
        if visual_element['type'] == 'text_input':
            for html_elem in html_elements:
                if html_elem['tag'] == 'input' and html_elem.get('type', 'text') in ['text', 'password', 'email', 'search']:
                    matching_elements.append(html_elem)
                elif html_elem['tag'] == 'textarea':
                    matching_elements.append(html_elem)
        else:
            # Para outros tipos de elementos visuais
            for html_elem in html_elements:
                # Nesta simplificação, apenas adicionamos todos os elementos
                matching_elements.append(html_elem)
                
        return matching_elements
    
    def generate_report(self, vulnerabilities, output_path):
        """
        Gera um relatório de vulnerabilidades
        
        Args:
            vulnerabilities (list): Lista de vulnerabilidades encontradas
            output_path (str): Caminho para salvar o relatório
            
        Returns:
            str: Caminho para o relatório gerado
        """
        if not vulnerabilities:
            self.logger.info("Nenhuma vulnerabilidade para reportar")
            return None
            
        # Garantir que o diretório de relatórios existe
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else 'reports', exist_ok=True)
        
        # Simplificar as vulnerabilidades para o relatório
        report_data = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_vulnerabilities': len(vulnerabilities),
            'vulnerabilities_by_type': {},
            'vulnerabilities_by_severity': {},
            'vulnerabilities': []
        }
        
        # Contar por tipo e severidade
        for vuln in vulnerabilities:
            # Contar por tipo
            vuln_type = vuln['type']
            if vuln_type not in report_data['vulnerabilities_by_type']:
                report_data['vulnerabilities_by_type'][vuln_type] = 0
            report_data['vulnerabilities_by_type'][vuln_type] += 1
            
            # Contar por severidade
            severity = vuln['severity']
            if severity not in report_data['vulnerabilities_by_severity']:
                report_data['vulnerabilities_by_severity'][severity] = 0
            report_data['vulnerabilities_by_severity'][severity] += 1
            
            # Adicionar versão simplificada da vulnerabilidade
            report_data['vulnerabilities'].append({
                'type': vuln['type'],
                'subtype': vuln.get('subtype', ''),
                'url': vuln['url'],
                'severity': vuln['severity'],
                'description': vuln['description'],
                'recommendation': vuln['recommendation']
            })
        
        # Salvar o relatório como JSON
        with open(output_path, 'w') as f:
            json.dump(report_data, f, indent=2)
            
        self.logger.info(f"Relatório salvo em: {output_path}")
        
        return output_path
