import cv2
import numpy as np
import os
import logging

class VisualAnalyzer:
    def __init__(self, verbose=False):
        """Inicializa o analisador visual simplificado"""
        self.verbose = verbose
        self.logger = logging.getLogger('VisualAnalyzer')
        if not self.logger.handlers:
            level = logging.INFO if verbose else logging.WARNING
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
            handler.setLevel(level)
            self.logger.addHandler(handler)
            self.logger.setLevel(level)
            
    def analyze(self, screenshot_path):
        """Analisa uma captura de tela para identificar elementos de interesse"""
        if not os.path.exists(screenshot_path):
            self.logger.error(f"Screenshot não encontrado: {screenshot_path}")
            return None
            
        try:
            # Carregar imagem e fazer análise básica
            image = cv2.imread(screenshot_path)
            if image is None:
                return None
                
            # Dimensões básicas
            height, width = image.shape[:2]
            
            # Detectar apenas os elementos essenciais
            input_fields = self._detect_input_fields(image)
            
            # Resultados simplificados
            results = {
                'input_fields': input_fields,
                'image_dimensions': {'width': width, 'height': height}
            }
            
            return results
            
        except Exception as e:
            self.logger.error(f"Erro na análise visual: {str(e)}")
            return None
            
    def _detect_input_fields(self, image):
        """Versão simplificada que detecta apenas campos de entrada essenciais"""
        input_fields = []
        
        # Converter para escala de cinza
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        blurred = cv2.GaussianBlur(gray, (5, 5), 0)
        edges = cv2.Canny(blurred, 50, 150)
        
        # Encontrar contornos e filtrar os mais prováveis de serem campos de entrada
        contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        
        for i, contour in enumerate(contours):
            # Análise simplificada de retângulos que podem ser campos de entrada
            x, y, w, h = cv2.boundingRect(contour)
            aspect_ratio = float(w) / h if h > 0 else 0
            
            # Filtros básicos para identificar campos de entrada
            if 2.5 < aspect_ratio < 10.0 and w > 100 and 20 < h < 60:
                roi = gray[y:y+h, x:x+w]
                std_dev = np.std(roi)
                
                if std_dev < 40:
                    input_fields.append({
                        'id': f'input_{i}',
                        'x': int(x),
                        'y': int(y),
                        'width': int(w),
                        'height': int(h),
                        'type': 'text_input' if aspect_ratio > 5 else 'input_field'
                    })
        
        return input_fields
