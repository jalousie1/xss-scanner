# css scanner

A tool for detecting Cross-Site Scripting (XSS) vulnerabilities in websites using visual and code analysis.

## About

XSSVision combines multiple analysis techniques to identify XSS vulnerabilities:

- Visual analysis of UI elements using OpenCV
- HTML code analysis for suspicious patterns
- JavaScript risk assessment
- HTML report generation

## Quick Start

```bash
python index.py --url https://example.com
```

## Parameters

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `--url` | Target website URL | Yes | - |
| `--depth` | Crawling depth | No | 2 |
| `--output` | Report output path | No | xss_report.html |
| `--screenshots` | Save page screenshots | No | False |
| `--verbose` | Show detailed information | No | False |
| `--chrome-path` | Chrome executable path | No | Auto-detect |
| `--use-firefox` | Use Firefox instead of Chrome | No | False |

## Examples

Basic scan:
```bash
python index.py --url https://example.com
```

Deeper scan:
```bash
python index.py --url https://example.com --depth 3
```

Custom report with screenshots:
```bash
python index.py --url https://example.com --output reports/my_report.html --screenshots
```

## Detected Vulnerabilities

XSSVision detects various XSS vulnerabilities:

- Input fields with XSS vectors
- Event handlers with suspicious code
- Risky JavaScript code
- URLs containing XSS attack vectors
- Suspicious HTML patterns

## Notes

- Uses headless browsers for JavaScript rendering
- Recommended depth is 2-3 (higher values may take longer)
- Reports may contain false positives requiring manual verification
- For ethical security testing only - use only on websites you have permission to test

