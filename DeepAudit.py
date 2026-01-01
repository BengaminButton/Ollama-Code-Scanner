import sys
import argparse
import json
import requests
import os

# --- КОНФИГУРАЦИЯ ---
OLLAMA_API = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "qwen2.5-coder" # Или dolphin-llama3

# Эвристика: ~150 строк кода обычно влезают в 4k-8k контекст с запасом на промпт.
# Если модель 32 тыщи контекста - можно ставить больше.
CHUNK_SIZE = 150

# Перекрытие строк, чтобы не потерять контекст на стыке чанков
OVERLAP_LINES = 20

def banner():
    print("--- Local LLM SAST Scanner v1.0 ---")

def parse_args():
    parser = argparse.ArgumentParser(description="AI Code Vulnerability Scanner")
    parser.add_argument("file", help="Path to source file")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Ollama model (default: {DEFAULT_MODEL})")
    parser.add_argument("--timeout", type=int, default=120, help="API request timeout in seconds")
    parser.add_argument("--output", help="Save report to JSON file")
    return parser.parse_args()

def prepare_code_chunks(file_path):
    """Читает файл и разбивает его на чанки с перекрытием и нумерацией"""
    try:
        # Фолбэк кодировок для легаси-кода
        content = ""
        lines = []
        for encoding in ['utf-8', 'latin-1', 'cp1251']:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    lines = f.readlines()
                break
            except UnicodeDecodeError:
                continue
        
        if not lines:
            print("[!] Failed to read file or file is empty.")
            sys.exit(1)

        chunks = []
        total_lines = len(lines)
        
        # Реализация Sliding Window
        step = CHUNK_SIZE - OVERLAP_LINES
        if step < 1: step = 1
        
        for i in range(0, total_lines, step):
            chunk_lines = lines[i : i + CHUNK_SIZE]
            if not chunk_lines: break
            
            chunk_content = ""
            start_line = i + 1
            
            # Вшиваем номера строк прямо в контент
            for idx, line in enumerate(chunk_lines):
                chunk_content += f"{start_line + idx}: {line}"
            
            end_line = start_line + len(chunk_lines) - 1
            
            chunks.append({
                "content": chunk_content,
                "lines_range": f"{start_line}-{end_line}"
            })
            
            # Если дошли до конца файла
            if end_line == total_lines:
                break
                
        return chunks
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        sys.exit(1)

def analyze_chunk(chunk, model, timeout):
    """Отправляет чанк в LLM с форсированием JSON"""
    prompt = f"""
    You are a Senior Security Engineer doing a code audit.
    Analyze the provided code chunk for security vulnerabilities (SQLi, XSS, RCE, IDOR, Logic Bugs, Secrets).
    INSTRUCTIONS:
    1. Respond ONLY in valid JSON format.
    2. Do NOT explain logic if no bugs found.
    3. Use the provided line numbers in 'line' field.
    4. Ignore minor code style issues.

    JSON SCHEMA:
    {{
        "vulnerabilities": [
            {{
                "type": "Vulnerability Type",
                "severity": "High/Medium/Low",
                "line": "Line Number",
                "details": "Short explanation",
                "fix": "Suggested fix"
            }}
        ]
    }}

    CODE CHUNK:
    {chunk['content']}
    """
    
    data = {
        "model": model,
        "prompt": prompt,
        "format": "json",  # Киллер-фича Ollama для строгого JSON
        "stream": False
    }
    
    try:
        response = requests.post(OLLAMA_API, json=data, timeout=timeout)
        response.raise_for_status()
        return response.json().get('response', '')
    except requests.exceptions.RequestException:
        return None

def main():
    banner()
    args = parse_args()
    
    if not os.path.isfile(args.file):
        print(f"[!] File not found: {args.file}")
        sys.exit(1)
        
    print(f"[*] Target: {args.file}")
    print(f"[*] Model: {args.model}")
    
    chunks = prepare_code_chunks(args.file)
    print(f"[*] Split into {len(chunks)} chunks (Overlap: {OVERLAP_LINES} lines). Starting analysis...\n")
    
    all_vulns = []
    
    for i, chunk in enumerate(chunks):
        print(f" -> Analyzing chunk {i+1}/{len(chunks)} (Lines: {chunk['lines_range']})...", end="\r")
        result_raw = analyze_chunk(chunk, args.model, args.timeout)
        
        if result_raw:
            try:
                result_json = json.loads(result_raw)
                if "vulnerabilities" in result_json and result_json["vulnerabilities"]:
                    for vuln in result_json["vulnerabilities"]:
                        # Дедупликация (так как у нас есть перекрытие чанков)
                        if vuln not in all_vulns:
                            all_vulns.append(vuln)
            except json.JSONDecodeError:
                pass # Бывает, что модель все равно плюет мусор, игнорируем

    print("\n\n" + "="*60)
    print(f"SCAN COMPLETE. Found {len(all_vulns)} unique issues.")
    print("="*60 + "\n")
    
    # Вывод в консоль
    if all_vulns:
        for v in all_vulns:
            print(f"[TYPE] {v.get('type', 'Unknown')}")
            print(f"[SEVERITY] {v.get('severity', 'Unknown')}")
            print(f"[LINE] {v.get('line', '?')}")
            print(f"[DETAILS] {v.get('details', 'No details')}")
            print("-" * 30)
            
    # Сохранение в файл
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump({"target": args.file, "vulnerabilities": all_vulns}, f, indent=4)
            print(f"[*] Report saved to {args.output}")
        except Exception as e:
            print(f"[!] Failed to save report: {e}")

if __name__ == "__main__":
    main()