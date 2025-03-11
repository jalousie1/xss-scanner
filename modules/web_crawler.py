from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time
import os
import logging
import platform
import geckodriver_autoinstaller
import re

class WebCrawler:
    def __init__(self, verbose=False, save_screenshots=True, chrome_path=None, use_firefox=False):
        """
        Inicializa o crawler web
        
        Args:
            verbose (bool): Se True, exibe logs detalhados
            save_screenshots (bool): Se True, salva screenshots das páginas
            chrome_path (str): Caminho para o executável do Chrome (opcional)
            use_firefox (bool): Se True, usa Firefox em vez de Chrome
        """
        self.verbose = verbose
        self.save_screenshots = save_screenshots
        self.chrome_path = chrome_path
        self.use_firefox = use_firefox
        self.driver = None
        self.visited_urls = set()
        
        # Configurar logging simplificado
        self.logger = logging.getLogger('WebCrawler')
        if not self.logger.handlers:
            level = logging.INFO if verbose else logging.WARNING
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
            handler.setLevel(level)
            self.logger.addHandler(handler)
            self.logger.setLevel(level)
    
    def _init_driver(self):
        """Inicializa o driver do Selenium"""
        try:
            if self.use_firefox:
                return self._init_firefox_driver()
            else:
                return self._init_chrome_driver()
        except Exception as e:
            self.logger.error(f"Erro ao inicializar Chrome: {e}")
            if not self.use_firefox:
                self.logger.info("Tentando Firefox como fallback")
                self.use_firefox = True
                return self._init_firefox_driver()
    
    def _init_chrome_driver(self):
        """Inicializa o Chrome de forma simplificada"""
        options = ChromeOptions()
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        
        # Detectar Chrome apenas se necessário
        if self.chrome_path and os.path.exists(self.chrome_path):
            options.binary_location = self.chrome_path
        
        service = ChromeService(ChromeDriverManager().install())
        self.driver = webdriver.Chrome(service=service, options=options)
        self.driver.set_page_load_timeout(30)
        return self.driver
    
    def _init_firefox_driver(self):
        """Inicializa o Firefox de forma simplificada"""
        geckodriver_autoinstaller.install()
        options = FirefoxOptions()
        options.add_argument("--headless")
        
        self.driver = webdriver.Firefox(options=options)
        self.driver.set_page_load_timeout(30)
        return self.driver
    
    def _close_driver(self):
        """Fecha o driver do Selenium"""
        if self.driver:
            if self.verbose:
                self.logger.info("Fechando o driver...")
            self.driver.quit()
            self.driver = None
    
    def _get_page_data(self, url):
        """Versão simplificada que foca nos dados essenciais da página"""
        if not self.driver:
            self._init_driver()
            
        try:
            self.logger.info(f"Acessando URL: {url}")
            self.driver.get(url)
            time.sleep(2)  # Tempo reduzido
            
            # Screenshot simplificado
            screenshot_path = None
            if self.save_screenshots:
                try:
                    screenshots_dir = "screenshots"
                    os.makedirs(screenshots_dir, exist_ok=True)
                    filename = f"{hash(url) % 100000}.png"
                    screenshot_path = os.path.join(screenshots_dir, filename)
                    self.driver.save_screenshot(screenshot_path)
                except Exception as e:
                    self.logger.warning(f"Erro ao salvar screenshot: {str(e)}")
                    screenshot_path = None
            
            # Dados essenciais
            html = self.driver.page_source
            scripts = self._extract_scripts()
            links = self._extract_links(html, url)
            
            return {
                'url': url,
                'html': html,
                'scripts': scripts,
                'links': links,
                'screenshot_path': screenshot_path,
                'timestamp': time.time()
            }
            
        except Exception as e:
            self.logger.error(f"Erro ao acessar {url}: {str(e)}")
            return None
    
    def _extract_scripts(self):
        """Extrai scripts de forma simplificada"""
        scripts = []
        script_elements = self.driver.find_elements("tag name", "script")
        for script in script_elements:
            try:
                if script.get_attribute("src"):
                    scripts.append({"type": "external", "src": script.get_attribute("src")})
                else:
                    content = script.get_attribute('innerHTML')
                    if content:
                        scripts.append({"type": "inline", "content": content})
            except:
                pass
        return scripts
                
    def _extract_links(self, html, base_url):
        """Extrai links de forma simplificada"""
        links = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for a in soup.find_all('a', href=True):
                href = a['href']
                absolute_url = urljoin(base_url, href)
                links.append(absolute_url)
        except:
            pass
        return links
    
    def crawl(self, start_url, depth=2):
        """
        Rastreia site até uma profundidade específica
        
        Args:
            start_url (str): URL inicial
            depth (int): Profundidade máxima de rastreamento
            
        Returns:
            list: Lista de dicionários com dados das páginas visitadas
        """
        self.logger.info(f"Iniciando rastreamento a partir de {start_url} com profundidade {depth}")
        self._init_driver()
        self.visited_urls.clear()
        pages_data = []
        
        try:
            self._crawl_recursive(start_url, depth, pages_data)
        finally:
            self._close_driver()
            
        self.logger.info(f"Rastreamento concluído. {len(pages_data)} páginas visitadas.")
        return pages_data
    
    def _crawl_recursive(self, url, depth, pages_data):
        """
        Método recursivo para rastreamento de páginas
        
        Args:
            url (str): URL atual
            depth (int): Profundidade restante
            pages_data (list): Lista para armazenar dados das páginas
        """
        # Verifica se já visitou a URL ou se atingiu a profundidade máxima
        if depth <= 0 or url in self.visited_urls:
            return
        
        # Marca URL como visitada para evitar loops
        self.visited_urls.add(url)
        
        # Obtém dados da página atual
        page_data = self._get_page_data(url)
        if not page_data:
            return
            
        # Adiciona à lista de resultados
        pages_data.append(page_data)
        
        # Mostra progresso se verbose
        if self.verbose:
            self.logger.info(f"Profundidade {depth}: {url} - Encontrados {len(page_data['links'])} links")
        
        # Filtra links do mesmo domínio
        same_domain_links = []
        base_domain = urlparse(url).netloc
        
        for link in page_data['links']:
            parsed_link = urlparse(link)
            if parsed_link.netloc == base_domain and link not in self.visited_urls:
                same_domain_links.append(link)
        
        # Limita o número de links por página para evitar explosão
        max_links_per_page = 10
        if len(same_domain_links) > max_links_per_page:
            if self.verbose:
                self.logger.info(f"Limitando a {max_links_per_page} links de {len(same_domain_links)} encontrados")
            same_domain_links = same_domain_links[:max_links_per_page]
        
        # Visita recursivamente os links encontrados
        for link in same_domain_links:
            self._crawl_recursive(link, depth - 1, pages_data)
