from bs4 import BeautifulSoup
import re
import logging
import urllib.parse

class HTMLParser:
    def __init__(self, verbose=False):
        """
        Inicializa o analisador HTML para detectar elementos potencialmente vulneráveis a XSS
        
        Args:
            verbose (bool): Se True, exibe logs detalhados
        """
        self.verbose = verbose
        
        # Configurar logging
        level = logging.INFO if verbose else logging.WARNING
        self.logger = logging.getLogger('HTMLParser')
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            handler.setLevel(level)
            self.logger.addHandler(handler)
            self.logger.setLevel(level)
            
        # Padrões de XSS para procurar no HTML
        self.xss_patterns = [
            r'<script[^>]*>.*?</script>',                      # Tags de script
            r'javascript:.*?[\'"\s>]',                         # URLs javascript:
            r'on\w+\s*=\s*(["\']).*?\1',                       # Manipuladores de eventos
            r'data:.*?base64',                                 # Data URIs (potencialmente perigosas)
            r'src\s*=\s*(["\'])[^"\']*?javascript:.*?\1',      # src com javascript:
            r'href\s*=\s*(["\'])[^"\']*?javascript:.*?\1',     # href com javascript:
            r'style\s*=\s*(["\'])[^"\']*?expression\s*\(.*?\1',# CSS expressions
            r'<\w+[^>]*\sformaction\s*=',                      # Atributos formaction
            r'<meta[^>]*\scontent\s*=\s*(["\'])[^"\']*?url\s*=\s*javascript:.*?\1' # Meta refresh com javascript:
        ]
        
        # Eventos que podem ser usados para XSS
        self.event_attributes = [
            'onload', 'onerror', 'onclick', 'onmouseover', 'onmouseout',
            'onkeypress', 'onkeydown', 'onkeyup', 'onchange', 'onfocus',
            'onblur', 'onsubmit', 'onreset', 'ondblclick', 'oncontextmenu',
            'ondrag', 'ondrop', 'onmousedown', 'onmouseup', 'onpaste',
            'oncut', 'oncopy', 'onselect', 'onready', 'onunload'
        ]
        
        self.logger.info("Analisador HTML inicializado")
        
    def parse(self, html, url=None):
        """
        Analisa o HTML para encontrar elementos que podem ser vulneráveis a XSS
        
        Args:
            html (str): Código HTML a ser analisado
            url (str, opcional): URL da página para contexto
            
        Returns:
            dict: Resultados da análise com elementos potencialmente vulneráveis
        """
        self.logger.info("Iniciando análise de HTML")
        
        results = {
            'inputs': [],
            'forms': [],
            'event_handlers': [],
            'inline_scripts': [],
            'suspicious_patterns': [],
            'links': [],
            'base_url': url
        }
        
        try:
            # Criar o parser com BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            
            # Analisar inputs
            results['inputs'] = self._analyze_inputs(soup)
            
            # Analisar formulários
            results['forms'] = self._analyze_forms(soup)
            
            # Analisar manipuladores de eventos
            results['event_handlers'] = self._analyze_event_handlers(soup)
            
            # Analisar scripts inline
            results['inline_scripts'] = self._analyze_inline_scripts(soup)
            
            # Encontrar padrões suspeitos
            results['suspicious_patterns'] = self._find_suspicious_patterns(html)
            
            # Analisar links
            results['links'] = self._analyze_links(soup, url)
            
            # Resumo dos resultados
            self.logger.info(f"Análise HTML concluída. Encontrados: {len(results['inputs'])} inputs, "
                          f"{len(results['forms'])} formulários, {len(results['event_handlers'])} manipuladores de eventos, "
                          f"{len(results['inline_scripts'])} scripts inline, {len(results['suspicious_patterns'])} padrões suspeitos.")
                          
            return results
            
        except Exception as e:
            self.logger.error(f"Erro ao analisar HTML: {str(e)}")
            return results
        
    def _analyze_inputs(self, soup):
        """
        Analisa elementos de entrada (input, textarea, select)
        
        Args:
            soup (BeautifulSoup): Objeto BeautifulSoup do HTML
            
        Returns:
            list: Lista de dicionários com informações sobre os elementos de entrada
        """
        inputs = []
        
        # Analisar tags input
        for tag in soup.find_all('input'):
            input_info = {
                'tag': 'input',
                'type': tag.get('type', 'text'),
                'name': tag.get('name', ''),
                'id': tag.get('id', ''),
                'value': tag.get('value', ''),
                'attributes': {},
                'suspicious': False,
                'parent_form': tag.parent.name == 'form' or tag.find_parent('form') is not None
            }
            
            # Coletar outros atributos
            for attr, value in tag.attrs.items():
                if attr not in ['type', 'name', 'id', 'value']:
                    input_info['attributes'][attr] = value
                
                # Verificar atributos de evento
                if attr in self.event_attributes:
                    input_info['suspicious'] = True
                    input_info['xss_vector'] = f"Event handler: {attr}={value}"
                    
                # Verificar valores de atributos que contêm "javascript:"
                if isinstance(value, str) and 'javascript:' in value.lower():
                    input_info['suspicious'] = True
                    input_info['xss_vector'] = f"JavaScript in attribute: {attr}={value}"
            
            inputs.append(input_info)
            
        # Analisar textareas
        for tag in soup.find_all('textarea'):
            textarea_info = {
                'tag': 'textarea',
                'name': tag.get('name', ''),
                'id': tag.get('id', ''),
                'value': tag.string or '',
                'attributes': {},
                'suspicious': False,
                'parent_form': tag.parent.name == 'form' or tag.find_parent('form') is not None
            }
            
            # Coletar outros atributos
            for attr, value in tag.attrs.items():
                if attr not in ['name', 'id']:
                    textarea_info['attributes'][attr] = value
                
                # Verificar atributos de evento
                if attr in self.event_attributes:
                    textarea_info['suspicious'] = True
                    textarea_info['xss_vector'] = f"Event handler: {attr}={value}"
            
            inputs.append(textarea_info)
            
        # Analisar selects
        for tag in soup.find_all('select'):
            select_info = {
                'tag': 'select',
                'name': tag.get('name', ''),
                'id': tag.get('id', ''),
                'options': [],
                'attributes': {},
                'suspicious': False,
                'parent_form': tag.parent.name == 'form' or tag.find_parent('form') is not None
            }
            
            # Coletar opções
            for option in tag.find_all('option'):
                option_info = {
                    'value': option.get('value', ''),
                    'text': option.string or '',
                    'selected': option.get('selected') is not None
                }
                select_info['options'].append(option_info)
                
                # Verificar valores suspeitos nas opções
                if 'javascript:' in option_info['value'].lower():
                    select_info['suspicious'] = True
                    select_info['xss_vector'] = f"JavaScript in option value: {option_info['value']}"
            
            # Coletar outros atributos
            for attr, value in tag.attrs.items():
                if attr not in ['name', 'id']:
                    select_info['attributes'][attr] = value
                
                # Verificar atributos de evento
                if attr in self.event_attributes:
                    select_info['suspicious'] = True
                    select_info['xss_vector'] = f"Event handler: {attr}={value}"
            
            inputs.append(select_info)
            
        return inputs
        
    def _analyze_forms(self, soup):
        """
        Analisa elementos de formulário (form)
        
        Args:
            soup (BeautifulSoup): Objeto BeautifulSoup do HTML
            
        Returns:
            list: Lista de dicionários com informações sobre os formulários
        """
        forms = []
        
        for tag in soup.find_all('form'):
            form_info = {
                'action': tag.get('action', ''),
                'method': tag.get('method', 'get').upper(),
                'id': tag.get('id', ''),
                'name': tag.get('name', ''),
                'attributes': {},
                'inputs': [],
                'submit_buttons': [],
                'suspicious': False
            }
            
            # Verificar ações suspeitas
            action = form_info['action'].lower()
            if 'javascript:' in action:
                form_info['suspicious'] = True
                form_info['xss_vector'] = f"JavaScript in action: {action}"
                
            # Coletar inputs do formulário
            for input_tag in tag.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.name if input_tag.name in ['textarea', 'select'] else input_tag.get('type', 'text')
                
                # Identificar botões de submit
                if input_tag.name == 'input' and input_type in ['submit', 'image', 'button']:
                    form_info['submit_buttons'].append({
                        'type': input_type,
                        'value': input_tag.get('value', ''),
                        'name': input_tag.get('name', ''),
                        'id': input_tag.get('id', '')
                    })
                else:
                    input_info = {
                        'type': input_type,
                        'name': input_tag.get('name', ''),
                        'id': input_tag.get('id', ''),
                        'value': input_tag.get('value', '') if input_tag.name != 'textarea' else (input_tag.string or '')
                    }
                    form_info['inputs'].append(input_info)
            
            # Também verificar botões definidos como <button>
            for button_tag in tag.find_all('button'):
                form_info['submit_buttons'].append({
                    'type': button_tag.get('type', 'submit'),
                    'value': button_tag.string or '',
                    'name': button_tag.get('name', ''),
                    'id': button_tag.get('id', '')
                })
            
            # Coletar outros atributos
            for attr, value in tag.attrs.items():
                if attr not in ['action', 'method', 'id', 'name']:
                    form_info['attributes'][attr] = value
                
                # Verificar atributos de evento
                if attr in self.event_attributes:
                    form_info['suspicious'] = True
                    form_info['xss_vector'] = f"Event handler: {attr}={value}"
            
            forms.append(form_info)
            
        return forms
        
    def _analyze_event_handlers(self, soup):
        """
        Localiza manipuladores de eventos em elementos HTML
        
        Args:
            soup (BeautifulSoup): Objeto BeautifulSoup do HTML
            
        Returns:
            list: Lista de dicionários com informações sobre os manipuladores de eventos
        """
        event_handlers = []
        
        for tag in soup.find_all():
            handlers = {}
            tag_info = None
            
            for attr in tag.attrs:
                if attr.lower() in self.event_attributes:
                    if tag_info is None:
                        tag_info = {
                            'tag_name': tag.name,
                            'id': tag.get('id', ''),
                            'class': ' '.join(tag.get('class', [])),
                            'handlers': {},
                            'content_preview': (tag.string or '')[:50] if tag.string else '',
                            'source_line': None  # BeautifulSoup não fornece número da linha facilmente
                        }
                    
                    handlers[attr] = tag[attr]
            
            if handlers:
                tag_info['handlers'] = handlers
                event_handlers.append(tag_info)
        
        return event_handlers
        
    def _analyze_inline_scripts(self, soup):
        """
        Analisa scripts embutidos no HTML
        
        Args:
            soup (BeautifulSoup): Objeto BeautifulSoup do HTML
            
        Returns:
            list: Lista de dicionários com informações sobre os scripts inline
        """
        inline_scripts = []
        
        for i, tag in enumerate(soup.find_all('script')):
            # Ignorar scripts com src (não são inline)
            if tag.has_attr('src'):
                continue
                
            script_content = tag.string or ''
            
            script_info = {
                'id': f"inline_script_{i}",
                'content': script_content,
                'attributes': {},
                'suspicious': False,
                'suspicious_patterns': []
            }
            
            # Coletar atributos do script
            for attr, value in tag.attrs.items():
                if attr != 'src':
                    script_info['attributes'][attr] = value
                    
                    # Verificar atributos de evento (incomum em tags script, mas possível)
                    if attr in self.event_attributes:
                        script_info['suspicious'] = True
                        script_info['suspicious_patterns'].append(f"Event handler in script tag: {attr}={value}")
            
            # Procurar padrões suspeitos no conteúdo
            suspicious_patterns = self._find_suspicious_js_patterns(script_content)
            if suspicious_patterns:
                script_info['suspicious'] = True
                script_info['suspicious_patterns'].extend(suspicious_patterns)
            
            inline_scripts.append(script_info)
        
        return inline_scripts
        
    def _find_suspicious_patterns(self, html):
        """
        Procura padrões suspeitos no HTML original
        
        Args:
            html (str): Código HTML completo
            
        Returns:
            list: Lista de padrões suspeitos encontrados
        """
        suspicious = []
        
        # Verificar cada padrão de XSS
        for pattern in self.xss_patterns:
            matches = re.finditer(pattern, html, re.IGNORECASE | re.DOTALL)
            for match in matches:
                suspicious.append({
                    'pattern': pattern,
                    'match': match.group(0)[:100] + ('...' if len(match.group(0)) > 100 else ''),
                    'position': match.span(),
                    'context': self._get_context(html, match.span()[0], 30)
                })
        
        return suspicious
        
    def _find_suspicious_js_patterns(self, js_content):
        """
        Procura padrões suspeitos em código JavaScript
        
        Args:
            js_content (str): Conteúdo JavaScript
            
        Returns:
            list: Lista de padrões suspeitos encontrados
        """
        suspicious = []
        
        # Funções JavaScript comumente usadas em XSS
        js_danger_patterns = [
            (r'document\.write\s*\(', 'document.write()'),
            (r'eval\s*\(', 'eval()'),
            (r'setTimeout\s*\(', 'setTimeout()'),
            (r'setInterval\s*\(', 'setInterval()'),
            (r'new\s+Function\s*\(', 'new Function()'),
            (r'innerHTML\s*=', 'innerHTML assignment'),
            (r'outerHTML\s*=', 'outerHTML assignment'),
            (r'document\.cookie', 'Cookie access/manipulation'),
            (r'document\.domain\s*=', 'document.domain assignment'),
            (r'document\.location\s*=', 'document.location assignment'),
            (r'window\.location\s*=', 'window.location assignment'),
            (r'location\.href\s*=', 'location.href assignment'),
            (r'location\.replace\s*\(', 'location.replace()'),
            (r'parent\.', 'Parent frame access'),
            (r'top\.', 'Top frame access'),
            (r'fromCharCode', 'String.fromCharCode (possible obfuscation)'),
            (r'decodeURI\(', 'decodeURI (possible obfuscation)'),
            (r'atob\(', 'atob (possible obfuscation)'),
            (r'execScript\(', 'execScript (possible dangerous execution)')
        ]
        
        for pattern, description in js_danger_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                suspicious.append(f"Suspicious JS pattern ({description}): {match.group(0)}")
        
        return suspicious
        
    def _analyze_links(self, soup, base_url=None):
        """
        Analisa links na página para identificar potenciais vetores de XSS
        
        Args:
            soup (BeautifulSoup): Objeto BeautifulSoup do HTML
            base_url (str, opcional): URL base para resolver URLs relativas
            
        Returns:
            list: Lista de dicionários com informações sobre links suspeitos
        """
        links = []
        
        for tag in soup.find_all('a', href=True):
            href = tag['href']
            link_info = {
                'href': href,
                'text': tag.get_text(strip=True)[:50],
                'suspicious': False
            }
            
            # Verificar se é um link javascript:
            if href.lower().startswith('javascript:'):
                link_info['suspicious'] = True
                link_info['xss_vector'] = f"JavaScript URI: {href[:100]}"
            
            # Verificar se há parâmetros na URL que podem ser usados para XSS
            elif '?' in href and not href.lower().startswith(('http:', 'https:', 'ftp:')):
                # URL relativa
                link_info['has_parameters'] = True
                
            elif '?' in href:
                # URL absoluta com parâmetros
                try:
                    parsed_url = urllib.parse.urlparse(href)
                    query_params = urllib.parse.parse_qs(parsed_url.query)
                    link_info['parameters'] = {k: v[0] if v else '' for k, v in query_params.items()}
                    link_info['has_parameters'] = True
                    
                    # Verificar valores de parâmetros suspeitos
                    for param, value in link_info['parameters'].items():
                        if any(p in value.lower() for p in ['<script', 'javascript:', 'onerror=', 'onload=']):
                            link_info['suspicious'] = True
                            link_info['xss_vector'] = f"Suspicious parameter: {param}={value[:100]}"
                except:
                    pass
            
            # Verificar atributos de evento no link
            for attr in tag.attrs:
                if attr.lower() in self.event_attributes:
                    link_info['suspicious'] = True
                    link_info['xss_vector'] = f"Event handler in link: {attr}={tag[attr]}"
            
            if link_info['suspicious'] or ('has_parameters' in link_info and link_info['has_parameters']):
                links.append(link_info)
        
        return links
    
    def _get_context(self, text, position, context_size=30):
        """
        Obtém o contexto em torno de uma posição no texto
        
        Args:
            text (str): Texto completo
            position (int): Posição no texto
            context_size (int): Tamanho do contexto antes e depois
        
        Returns:
            str: Texto com contexto
        """
        start = max(0, position - context_size)
        end = min(len(text), position + context_size)
        
        prefix = "..." if start > 0 else ""
        suffix = "..." if end < len(text) else ""
        
        return f"{prefix}{text[start:position]}<HERE>{text[position:end]}{suffix}"
