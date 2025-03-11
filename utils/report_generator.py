import os
import logging
from datetime import datetime
import shutil
from utils.report_templates import ReportTemplates

class ReportGenerator:
    def __init__(self, verbose=False):
        """Inicializa o gerador de relatórios simplificado"""
        self.logger = logging.getLogger('ReportGenerator')
        if not self.logger.handlers:
            level = logging.INFO if verbose else logging.WARNING
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
            handler.setLevel(level)
            self.logger.addHandler(handler)
            self.logger.setLevel(level)
            
        self.templates = ReportTemplates()
    
    def generate(self, vulnerabilities, output_path='xss_report.html'):
        """Versão simplificada do gerador de relatórios"""
        # Criar diretório para o relatório se necessário
        report_dir = os.path.dirname(output_path)
        if report_dir and not os.path.exists(report_dir):
            os.makedirs(report_dir, exist_ok=True)
            
        # Relatório vazio se não houver vulnerabilidades
        if not vulnerabilities:
            self._generate_empty_report(output_path)
            return output_path
        
        try:
            # Deduplica vulnerabilidades
            unique_vulns = self._deduplicate_vulnerabilities(vulnerabilities)
            
            # Preparar dados essenciais
            report_data = self._prepare_report_data(unique_vulns)
            
            # Gerar HTML
            html_content = self.templates.generate_html(report_data)
            
            # Salvar relatório
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            # Copiar screenshots se existirem
            if report_dir:
                self._copy_screenshots_simple(unique_vulns, report_dir)
                
        except Exception as e:
            self.logger.error(f"Erro ao gerar relatório: {str(e)}")
            self._generate_basic_report(vulnerabilities, output_path)
        
        return output_path
    
    def _deduplicate_vulnerabilities(self, vulnerabilities):
        """Elimina vulnerabilidades duplicadas"""
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            key = (vuln.get('url', ''), vuln.get('type', ''), vuln.get('description', ''))
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
                
        return unique_vulns
        
    def _prepare_report_data(self, vulnerabilities):
        """Prepara dados essenciais para o relatório"""
        # Estrutura básica de dados
        report_data = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_vulnerabilities': len(vulnerabilities),
            'urls_analyzed': set(),
            'vulnerabilities_by_type': {},
            'vulnerabilities_by_severity': {},
            'vulnerabilities_by_url': {},
            'vulnerabilities': []
        }
        
        # Processar vulnerabilidades
        for index, vuln in enumerate(vulnerabilities):
            vuln_id = f"vuln_{index+1}"
            vuln_type = vuln.get('type', 'unknown')
            severity = vuln.get('severity', 'Médio')
            url = vuln.get('url', 'Unknown')
            
            # Adicionar URL à lista
            report_data['urls_analyzed'].add(url)
            
            # Estatísticas
            if vuln_type not in report_data['vulnerabilities_by_type']:
                report_data['vulnerabilities_by_type'][vuln_type] = 0
            report_data['vulnerabilities_by_type'][vuln_type] += 1
            
            if severity not in report_data['vulnerabilities_by_severity']:
                report_data['vulnerabilities_by_severity'][severity] = 0
            report_data['vulnerabilities_by_severity'][severity] += 1
            
            # Agrupar por URL
            if url not in report_data['vulnerabilities_by_url']:
                report_data['vulnerabilities_by_url'][url] = []
            report_data['vulnerabilities_by_url'][url].append(vuln)
            
            # Versão limpa da vulnerabilidade
            clean_vuln = {
                'id': vuln_id,
                'type': vuln_type,
                'subtype': vuln.get('subtype', ''),
                'url': url,
                'severity': severity,
                'description': vuln.get('description', 'Sem descrição'),
                'recommendation': vuln.get('recommendation', 'Sem recomendação'),
                'screenshot': vuln.get('screenshot', None)
            }
            
            report_data['vulnerabilities'].append(clean_vuln)
        
        # Converter URLs para lista
        report_data['urls_analyzed'] = list(report_data['urls_analyzed'])
        
        return report_data
    
    def _copy_screenshots_simple(self, vulnerabilities, report_dir):
        """Versão simplificada para copiar screenshots"""
        for vuln in vulnerabilities:
            screenshot_path = vuln.get('screenshot')
            if screenshot_path and os.path.exists(screenshot_path):
                try:
                    destination = os.path.join(report_dir, os.path.basename(screenshot_path))
                    shutil.copy(screenshot_path, destination)
                except:
                    pass
    
    def _generate_empty_report(self, output_path):
        """Gera relatório vazio simplificado"""
        html = self.templates.generate_empty_report()
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
            
    def _generate_basic_report(self, vulnerabilities, output_path):
        """Gera relatório básico em caso de falha"""
        try:
            # HTML básico com vulnerabilidades mínimas
            html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Relatório Básico XSS</title>
                <style>body {{font-family:sans-serif;}} .vuln {{border:1px solid #ccc; padding:10px; margin:5px;}}</style>
            </head>
            <body>
                <h1>Relatório Básico de XSS</h1>
                <p>Data: {datetime.now().strftime("%Y-%m-%d")}</p>
                <p>Total: {len(vulnerabilities)}</p>
            """
            
            # Lista simples de vulnerabilidades
            for vuln in vulnerabilities:
                html += f"""
                <div class="vuln">
                    <h3>{vuln.get('type', 'Desconhecido')} - {vuln.get('severity', 'Médio')}</h3>
                    <p>{vuln.get('description', '')}</p>
                </div>
                """
                
            html += "</body></html>"
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
                
        except Exception as e:
            self.logger.error(f"Erro ao criar relatório básico: {str(e)}")
