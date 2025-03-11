import logging
import os
from datetime import datetime
import re

class ReportTemplates:
    def __init__(self):
        """
        Inicializa a classe de templates para relatórios
        """
        self.logger = logging.getLogger('ReportTemplates')
        
        # Definir cores por severidade para o relatório
        self.severity_colors = {
            'Alto': '#d9534f',  # Vermelho
            'Médio': '#f0ad4e',  # Amarelo/Laranja
            'Baixo': '#5bc0de',  # Azul claro
            'Informativo': '#5cb85c'  # Verde
        }
        
        # Definir ícones por tipo de vulnerabilidade
        self.type_icons = {
            'input_xss': '📝',
            'event_handler_xss': '🔄',
            'script_xss': '📜',
            'inline_script_xss': '📃',
            'url_xss': '🔗',
            'pattern_xss': '🔍'
        }
    
    def generate_html(self, report_data):
        """
        Gera o conteúdo HTML do relatório
        
        Args:
            report_data (dict): Dados organizados para o relatório
            
        Returns:
            str: Conteúdo HTML do relatório
        """
        # Construir o HTML
        html = f"""
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Relatório de Vulnerabilidades XSS</title>
            {self._get_css_styles()}
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>📊 Relatório de Vulnerabilidades XSS</h1>
                    <p>Data e hora: {report_data['timestamp']}</p>
                </header>
                
                {self._generate_summary_section(report_data)}
                
                <h2>Detalhes das Vulnerabilidades</h2>
                {self._generate_vulnerabilities_section(report_data)}
                
                <div id="screenshot-modal" class="screenshot-modal">
                    <span class="close" onclick="closeScreenshotModal()">&times;</span>
                    <img id="screenshot-modal-img" class="screenshot-modal-content">
                </div>
                
                <footer>
                    <p>Relatório gerado automaticamente por Detector de XSS em Elementos Visuais de Websites</p>
                </footer>
            </div>
            
            {self._get_javascript()}
        </body>
        </html>
        """
        
        return html
    
    def generate_empty_report(self):
        """
        Gera um relatório HTML vazio para quando não há vulnerabilidades
        
        Returns:
            str: HTML do relatório vazio
        """
        html = f"""
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Relatório de Vulnerabilidades XSS</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    margin: 0;
                    padding: 0;
                    background-color: #f5f5f5;
                }}
                .container {{
                    max-width: 800px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                header {{
                    background-color: #2c3e50;
                    color: white;
                    padding: 20px;
                    border-radius: 5px 5px 0 0;
                }}
                .content-box {{
                    background-color: white;
                    border-radius: 0 0 5px 5px;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                    padding: 20px;
                    text-align: center;
                }}
                footer {{
                    text-align: center;
                    margin-top: 20px;
                    padding: 10px;
                    font-size: 12px;
                    color: #777;
                }}
                .success-icon {{
                    font-size: 64px;
                    color: #5cb85c;
                    margin: 20px 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>📊 Relatório de Vulnerabilidades XSS</h1>
                    <p>Data e hora: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                </header>
                
                <div class="content-box">
                    <div class="success-icon">✓</div>
                    <h2>Nenhuma vulnerabilidade XSS encontrada!</h2>
                    <p>A análise foi concluída com sucesso e não foram detectadas vulnerabilidades XSS nas páginas examinadas.</p>
                    <p>Este resultado é positivo, mas recomenda-se continuar implementando boas práticas de segurança e realizar análises periódicas.</p>
                </div>
                
                <footer>
                    <p>Relatório gerado automaticamente por Detector de XSS em Elementos Visuais de Websites</p>
                </footer>
            </div>
        </body>
        </html>
        """
        
        return html

    def _get_css_styles(self):
        """
        Retorna os estilos CSS para o relatório
        
        Returns:
            str: Código CSS
        """
        return """
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    margin: 0;
                    padding: 0;
                    background-color: #f5f5f5;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }
                header {
                    background-color: #2c3e50;
                    color: white;
                    padding: 20px;
                    border-radius: 5px 5px 0 0;
                }
                h1, h2, h3 {
                    margin-top: 0;
                }
                .summary-box {
                    background-color: white;
                    border-radius: 5px;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                    padding: 20px;
                    margin-bottom: 20px;
                }
                .chart-container {
                    display: flex;
                    justify-content: space-around;
                    flex-wrap: wrap;
                }
                .chart {
                    width: 45%;
                    min-width: 300px;
                    margin-bottom: 20px;
                }
                .vulnerability-list {
                    background-color: white;
                    border-radius: 5px;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                    margin-bottom: 20px;
                }
                .vulnerability-card {
                    border-left: 4px solid #ddd;
                    margin: 10px;
                    padding: 15px;
                    background-color: #fff;
                    border-radius: 3px;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                }
                .high { border-left-color: #d9534f; }
                .medium { border-left-color: #f0ad4e; }
                .low { border-left-color: #5bc0de; }
                .info { border-left-color: #5cb85c; }
                .severity-badge {
                    display: inline-block;
                    padding: 3px 8px;
                    color: white;
                    border-radius: 3px;
                    font-size: 12px;
                    font-weight: bold;
                    margin-right: 10px;
                }
                .severity-high { background-color: #d9534f; }
                .severity-medium { background-color: #f0ad4e; }
                .severity-low { background-color: #5bc0de; }
                .severity-info { background-color: #5cb85c; }
                .details-button {
                    background-color: #3498db;
                    color: white;
                    border: none;
                    padding: 5px 10px;
                    border-radius: 3px;
                    cursor: pointer;
                    font-size: 12px;
                }
                .details-button:hover {
                    background-color: #2980b9;
                }
                .modal {
                    display: none;
                    position: fixed;
                    z-index: 1;
                    left: 0;
                    top: 0;
                    width: 100%;
                    height: 100%;
                    overflow: auto;
                    background-color: rgba(0,0,0,0.4);
                }
                .modal-content {
                    background-color: #fefefe;
                    margin: 10% auto;
                    padding: 20px;
                    border: 1px solid #888;
                    width: 80%;
                    max-width: 800px;
                    border-radius: 5px;
                }
                .close {
                    color: #aaa;
                    float: right;
                    font-size: 28px;
                    font-weight: bold;
                }
                .close:hover, .close:focus {
                    color: black;
                    text-decoration: none;
                    cursor: pointer;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 20px;
                }
                th, td {
                    padding: 10px;
                    border-bottom: 1px solid #ddd;
                    text-align: left;
                }
                th {
                    background-color: #f2f2f2;
                }
                .screenshot-thumbnail {
                    max-width: 200px;
                    max-height: 150px;
                    cursor: pointer;
                }
                .screenshot-modal {
                    display: none;
                    position: fixed;
                    z-index: 2;
                    left: 0;
                    top: 0;
                    width: 100%;
                    height: 100%;
                    overflow: auto;
                    background-color: rgba(0,0,0,0.9);
                }
                .screenshot-modal-content {
                    margin: auto;
                    display: block;
                    max-width: 80%;
                    max-height: 80%;
                }
                .url-box {
                    background-color: #f9f9f9;
                    padding: 10px;
                    margin-bottom: 20px;
                    border-radius: 3px;
                    border-left: 4px solid #3498db;
                }
                .badge {
                    display: inline-block;
                    background-color: #e7e7e7;
                    padding: 3px 8px;
                    border-radius: 10px;
                    font-size: 12px;
                    margin-right: 5px;
                }
                footer {
                    text-align: center;
                    margin-top: 20px;
                    padding: 10px;
                    font-size: 12px;
                    color: #777;
                }
                .recommendation-box {
                    background-color: #dff0d8;
                    padding: 10px 15px;
                    border-radius: 3px;
                    border-left: 3px solid #5cb85c;
                    margin-top: 10px;
                }
            </style>
        """

    def _get_javascript(self):
        """
        Retorna o código JavaScript para o relatório
        
        Returns:
            str: Código JavaScript
        """
        return """
            <script>
                // Funções para manipular os modais
                function showDetails(vulnId) {
                    var modal = document.getElementById(vulnId + '-modal');
                    if (modal) {
                        modal.style.display = 'block';
                    } else {
                        console.error("Modal not found: " + vulnId + '-modal');
                    }
                }
                
                function closeModal(vulnId) {
                    var modal = document.getElementById(vulnId + '-modal');
                    if (modal) {
                        modal.style.display = 'none';
                    }
                }
                
                function showScreenshot(screenshotPath) {
                    var modal = document.getElementById('screenshot-modal');
                    var modalImg = document.getElementById('screenshot-modal-img');
                    if (modal && modalImg) {
                        modal.style.display = 'block';
                        modalImg.src = screenshotPath;
                    }
                }
                
                function closeScreenshotModal() {
                    var modal = document.getElementById('screenshot-modal');
                    if (modal) {
                        modal.style.display = 'none';
                    }
                }
                
                // Fechar o modal quando o usuário clicar fora dele
                window.onclick = function(event) {
                    if (event.target.classList.contains('modal')) {
                        event.target.style.display = 'none';
                    }
                }
                
                // Adicionar event listener para todos os botões de detalhes
                document.addEventListener('DOMContentLoaded', function() {
                    // Botões de detalhes usando atributos data
                    document.querySelectorAll('.details-button').forEach(function(button) {
                        button.addEventListener('click', function() {
                            var vulnId = this.getAttribute('data-vuln-id');
                            showDetails(vulnId);
                        });
                    });
                    
                    // Botões de fechar usando atributos data
                    document.querySelectorAll('.close').forEach(function(button) {
                        button.addEventListener('click', function() {
                            var vulnId = this.getAttribute('data-close-id');
                            if (vulnId) {
                                closeModal(vulnId);
                            } else {
                                var modal = this.closest('.modal');
                                if (modal) {
                                    modal.style.display = 'none';
                                }
                            }
                        });
                    });
                });
            </script>
        """

    def _generate_summary_section(self, report_data):
        """
        Gera a seção de resumo do relatório
        
        Args:
            report_data (dict): Dados do relatório
            
        Returns:
            str: HTML da seção de resumo
        """
        html = """
            <div class="summary-box">
                <h2>Resumo da Análise</h2>
                <p>
                    <strong>Total de vulnerabilidades encontradas:</strong> {total_vulnerabilities}<br>
                    <strong>URLs analisadas:</strong> {url_count}<br>
                </p>
                
                <div class="chart-container">
                    <div class="chart">
                        <h3>Vulnerabilidades por Severidade</h3>
                        <table>
                            <tr>
                                <th>Severidade</th>
                                <th>Quantidade</th>
                            </tr>
        """.format(
            total_vulnerabilities=report_data['total_vulnerabilities'],
            url_count=len(report_data['urls_analyzed'])
        )
        
        # Adicionar linhas da tabela de severidades
        for severity, count in report_data['vulnerabilities_by_severity'].items():
            severity_class = severity.lower()
            html += f"""
                            <tr>
                                <td><span class="severity-badge severity-{severity_class}">{severity}</span></td>
                                <td>{count}</td>
                            </tr>
            """
            
        html += """
                        </table>
                    </div>
                    
                    <div class="chart">
                        <h3>Vulnerabilidades por Tipo</h3>
                        <table>
                            <tr>
                                <th>Tipo</th>
                                <th>Quantidade</th>
                            </tr>
        """
        
        # Adicionar linhas da tabela de tipos
        for vuln_type, count in report_data['vulnerabilities_by_type'].items():
            icon = self.type_icons.get(vuln_type, '🔴')
            vuln_type_display = vuln_type.replace('_', ' ').title()
            html += f"""
                            <tr>
                                <td>{icon} {vuln_type_display}</td>
                                <td>{count}</td>
                            </tr>
            """
            
        html += """
                        </table>
                    </div>
                </div>
            </div>
        """
        
        return html

    def _generate_vulnerabilities_section(self, report_data):
        """
        Gera a seção de detalhes de vulnerabilidades
        
        Args:
            report_data (dict): Dados do relatório
            
        Returns:
            str: HTML da seção de vulnerabilidades
        """
        html = ""
        
        # Para garantir IDs únicos
        vuln_counter = 0
        
        # Agrupar por URL
        for url, url_vulns in report_data['vulnerabilities_by_url'].items():
            html += f"""
                <div class="url-box">
                    <h3>🌐 {url}</h3>
                    <p>Vulnerabilidades encontradas: {len(url_vulns)}</p>
                </div>
                
                <div class="vulnerability-list">
            """
            
            # Adicionar cada vulnerabilidade para esta URL
            for vuln in url_vulns:
                vuln_counter += 1
                severity = vuln.get('severity', 'Médio').lower()
                
                # Usar o ID da lista de vulnerabilidades limpas, ou gerar um novo ID único
                clean_vuln = next((v for v in report_data['vulnerabilities'] 
                              if v['url'] == url and v.get('description') == vuln.get('description')), None)
                
                if clean_vuln:
                    vuln_id = clean_vuln['id']
                else:
                    vuln_id = f"vuln_auto_{vuln_counter}"
                    
                icon = self.type_icons.get(vuln['type'], '🔴')
                
                html += self._generate_vulnerability_card(vuln, vuln_id, icon, severity, url)
                
            html += """
                </div>
            """
        
        return html

    def _sanitize_html(self, text):
        """
        Sanitiza texto para evitar problemas no HTML
        
        Args:
            text (str): Texto para sanitizar
            
        Returns:
            str: Texto sanitizado
        """
        if not text:
            return ""
        
        # Limitar o tamanho do texto
        if len(text) > 5000:  # Limitar textos muito longos
            text = text[:5000] + "... (texto truncado)"
            
        # Escapar caracteres HTML para evitar quebras
        text = text.replace("&", "&amp;")
        text = text.replace("<", "&lt;")
        text = text.replace(">", "&gt;")
        text = text.replace('"', "&quot;")
        text = text.replace("'", "&#39;")
        
        return text

    def _generate_vulnerability_card(self, vuln, vuln_id, icon, severity, url):
        """
        Gera o HTML de um card de vulnerabilidade
        
        Args:
            vuln (dict): Dados da vulnerabilidade
            vuln_id (str): ID da vulnerabilidade
            icon (str): Ícone da vulnerabilidade
            severity (str): Severidade (em minúsculas)
            url (str): URL da página
            
        Returns:
            str: HTML do card de vulnerabilidade
        """
        # Sanitizar os textos para evitar problemas no HTML
        description = self._sanitize_html(vuln.get('description', 'Sem descrição'))
        recommendation = self._sanitize_html(vuln.get('recommendation', 'Sem recomendação'))
        vulnerability_title = self._sanitize_html(vuln.get('vulnerability', 'Vulnerabilidade XSS'))
        
        html = f"""
            <div class="vulnerability-card {severity}">
                <h4>
                    <span class="severity-badge severity-{severity}">{vuln.get('severity', 'Médio')}</span>
                    {icon} {vulnerability_title}
                </h4>
                <p>{description}</p>
                <div class="recommendation-box">
                    <strong>Recomendação:</strong> {recommendation}
                </div>
                <div style="margin-top: 10px;">
                    <span class="badge">{vuln['type'].replace('_', ' ').title()}</span>
                    {f'<span class="badge">{vuln.get("subtype", "").replace("_", " ").title()}</span>' if vuln.get('subtype') else ''}
                </div>
                <button class="details-button" data-vuln-id="{vuln_id}">Ver Detalhes</button>
            </div>
            
            <div id="{vuln_id}-modal" class="modal">
                {self._generate_vulnerability_detail_modal(vuln, vuln_id, severity, url)}
            </div>
        """
        
        return html

    def _generate_vulnerability_detail_modal(self, vuln, vuln_id, severity, url):
        """
        Gera o HTML do modal de detalhes de uma vulnerabilidade
        
        Args:
            vuln (dict): Dados da vulnerabilidade
            vuln_id (str): ID da vulnerabilidade
            severity (str): Severidade (em minúsculas)
            url (str): URL da página
            
        Returns:
            str: HTML do modal de detalhes
        """
        # Sanitizar os textos
        url_safe = self._sanitize_html(url)
        description = self._sanitize_html(vuln.get('description', 'Sem descrição'))
        recommendation = self._sanitize_html(vuln.get('recommendation', 'Sem recomendação'))
        
        html = f"""
            <div class="modal-content">
                <span class="close" data-close-id="{vuln_id}">&times;</span>
                <h3>Detalhes da Vulnerabilidade</h3>
                <table>
                    <tr>
                        <th>URL</th>
                        <td>{url_safe}</td>
                    </tr>
                    <tr>
                        <th>Tipo</th>
                        <td>{vuln['type'].replace('_', ' ').title()}</td>
                    </tr>
                    <tr>
                        <th>Subtipo</th>
                        <td>{vuln.get('subtype', '').replace('_', ' ').title() or 'N/A'}</td>
                    </tr>
                    <tr>
                        <th>Severidade</th>
                        <td><span class="severity-badge severity-{severity}">{vuln.get('severity', 'Médio')}</span></td>
                    </tr>
                    <tr>
                        <th>Descrição</th>
                        <td>{description}</td>
                    </tr>
                    <tr>
                        <th>Recomendação</th>
                        <td>{recommendation}</td>
                    </tr>
        """
        
        # Adicionar captura de tela se disponível
        if 'screenshot' in vuln and vuln['screenshot']:
            screenshot_path = vuln['screenshot']
            screenshot_filename = os.path.basename(screenshot_path) if screenshot_path else ''
            html += f"""
                    <tr>
                        <th>Captura de Tela</th>
                        <td>
                            <img src="{screenshot_filename}" class="screenshot-thumbnail" onclick="showScreenshot('{screenshot_filename}')">
                        </td>
                    </tr>
            """
        
        # Adicionar evidências específicas conforme o tipo de vulnerabilidade
        if 'evidence' in vuln and vuln['evidence']:
            evidence = vuln['evidence']
            
            if vuln['type'] == 'input_xss':
                html += f"""
                        <tr>
                            <th>Elemento</th>
                            <td>
                                <strong>Tipo:</strong> {vuln.get('element_type', 'Desconhecido')}<br>
                                <strong>ID:</strong> {vuln.get('element_id', 'N/A')}<br>
                                <strong>Nome:</strong> {vuln.get('element_name', 'N/A')}
                            </td>
                        </tr>
                """
                
            elif vuln['type'] in ['script_xss', 'inline_script_xss']:
                if 'key_issues' in vuln:
                    html += """
                        <tr>
                            <th>Problemas Detectados</th>
                            <td>
                                <ul>
                    """
                    for issue in vuln['key_issues']:
                        html += f"<li>{issue}</li>"
                    html += """
                                </ul>
                            </td>
                        </tr>
                    """
                    
            elif vuln['type'] == 'event_handler_xss':
                if isinstance(evidence, dict) and 'handlers' in evidence:
                    html += """
                        <tr>
                            <th>Manipuladores de Eventos</th>
                            <td>
                                <ul>
                    """
                    for event, code in evidence['handlers'].items():
                        html += f"<li><strong>{event}</strong>: {code}</li>"
                    html += """
                                </ul>
                            </td>
                        </tr>
                    """
        
        html += """
                </table>
            </div>
        """
        
        return html
