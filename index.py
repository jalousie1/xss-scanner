import argparse
import os
import sys
import time

def setup_project_structure():
    """Configura a estrutura de diretórios do projeto"""
    dirs = ['modules', 'utils', 'reports', 'screenshots']
    for dir_name in dirs:
        os.makedirs(dir_name, exist_ok=True)
    print("[+] Estrutura de diretórios criada com sucesso")

def main():
    """Função principal do detector de XSS"""
    # Configurar o parser de argumentos
    parser = argparse.ArgumentParser(description='Detector de XSS em Elementos Visuais de Websites')
    parser.add_argument('--url', required=True, help='URL do site a ser analisado')
    parser.add_argument('--depth', type=int, default=2, help='Profundidade de rastreamento')
    parser.add_argument('--output', default='xss_report.html', help='Arquivo de saída para relatório')
    parser.add_argument('--screenshots', action='store_true', help='Salvar screenshots das páginas')
    parser.add_argument('--verbose', action='store_true', help='Mostrar informações detalhadas')
    # Novos argumentos para resolver o problema do Chrome
    parser.add_argument('--chrome-path', help='Caminho para o executável do Chrome')
    parser.add_argument('--use-firefox', action='store_true', help='Usar Firefox em vez de Chrome')
    
    args = parser.parse_args()
    
    # Verificar se os módulos necessários foram criados
    required_modules = [
        'modules/web_crawler.py',
        'modules/visual_analyzer.py',
        'modules/html_parser.py',
        'modules/script_analyzer.py',
        'modules/xss_detector.py',
        'utils/report_generator.py'
    ]
    
    missing_modules = [module for module in required_modules if not os.path.exists(module)]
    
    if missing_modules:
        print("[!] Alguns módulos necessários não foram encontrados:")
        for module in missing_modules:
            print(f"  - {module}")
        print("[!] Por favor, crie todos os módulos necessários antes de executar o detector.")
        sys.exit(1)
    
    print(f"[*] Iniciando análise de XSS para: {args.url}")
    print(f"[*] Profundidade de rastreamento: {args.depth}")
    
    try:
        # Importar os módulos necessários
        from modules.web_crawler import WebCrawler
        from modules.xss_detector import XSSDetector
        from utils.report_generator import ReportGenerator
        
        # Iniciar o crawler (com as novas opções)
        crawler = WebCrawler(
            verbose=args.verbose, 
            save_screenshots=args.screenshots,
            chrome_path=args.chrome_path,
            use_firefox=args.use_firefox
        )
        
        print("[*] Iniciando rastreamento do website...")
        pages_data = crawler.crawl(args.url, depth=args.depth)
        print(f"[+] Rastreamento concluído: {len(pages_data)} páginas encontradas")
        
        # Analisar cada página em busca de vulnerabilidades
        detector = XSSDetector(verbose=args.verbose)
        results = []
        
        print("[*] Iniciando análise de vulnerabilidades...")
        for page_data in pages_data:
            if args.verbose:
                print(f"[*] Analisando: {page_data['url']}")
            vulnerabilities = detector.analyze(page_data)
            if vulnerabilities:
                results.extend(vulnerabilities)
        
        # Gerar relatório
        report_generator = ReportGenerator()
        if results:
            print(f"[!] Encontradas {len(results)} potenciais vulnerabilidades XSS")
            report_path = report_generator.generate(results, args.output)
            print(f"[+] Relatório salvo em: {report_path}")
        else:
            print("[+] Nenhuma vulnerabilidade XSS encontrada")
            report_path = report_generator.generate([], args.output)
            print(f"[+] Relatório vazio salvo em: {report_path}")
            
    except ImportError as e:
        print(f"[!] Erro ao importar módulos: {str(e)}")
        print("[!] Certifique-se de que todas as dependências estão instaladas:")
        print("    pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Erro durante a execução: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    setup_project_structure()
    main()
