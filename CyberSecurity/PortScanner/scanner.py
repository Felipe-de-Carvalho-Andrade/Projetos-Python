import socket
import errno
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# --- CONFIGURAÇÕES GERAIS ---
TARGET = "scanme.nmap.org"  # Alvo do escaneamento
MAX_THREADS = 100           # Limite de threads simultâneas
TIMEOUT = 2.0               # Tempo máximo de espera por resposta (segundos)

# --- ENGENHARIA DE IDENTIFICAÇÃO (FINGERPRINTING) ---
# Regras para identificar serviços baseadas em strings contidas no banner
RULES = [
    {"match": "SSH-", "service": "ssh"},
    {"match": "FTP", "service": "ftp"},
    {"match": "220 ", "service": "ftp"},
    {"match": "HTTP/", "service": "http"},
    {"match": "SMTP", "service": "smtp"},
    {"match": "ESMTP", "service": "smtp"}
]

# Dicionário para inferência de serviço baseada na porta (fallback)
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 143: "imap",
    443: "https", 3306: "mysql", 3389: "rdp", 8080: "http-proxy"
}

# Portas candidatas a probing HTTP ativo
HTTP_PORTS = {80, 443, 8000, 8080, 8443, 8888}

# --- FUNÇÕES DE COMUNICAÇÃO DE REDE ---
def get_socket(timeout):
    """Inicializa e configura um socket TCP padrão"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    return s

def probe_http(host, port, timeout):
    """Tenta identificar serviços web enviando uma requisição HTTP básica"""
    try:
        with get_socket(timeout) as s:
            s.connect((host, port))
            request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            s.sendall(request.encode())
            data = s.recv(1024).decode(errors='ignore')
            if data:
                # Retorna o protocolo e a primeira linha da resposta (status)
                return "http", data.split('\n')[0].strip()
    except Exception:
        pass
    return None, None

# --- PROCESSAMENTO DE DADOS E ANÁLISE ---
def parse_ssh_banner(banner: str):
    """Extrai o nome do software e a versão de uma string de banner SSH"""
    output = {"software": "unknown", "version": None}
    parts = banner.split("-")
    if len(parts) > 2:
        software_part = parts[2].split("_")
        if len(software_part) >= 2:
            output["software"] = software_part[0]
            output["version"] = software_part[1].split(" ")[0].strip()
    return output

def analyze_banner(banner: str, result_dict: dict):
    """Compara o banner recebido com as regras para identificar o serviço"""
    banner_upper = banner.upper()
    
    for rule in RULES:
        if rule["match"] in banner_upper or rule["match"] in banner:
            result_dict["service"] = rule["service"]
            
            # Tratamento especial para SSH (extração de versão)
            if rule["service"] == "ssh":
                parsed = parse_ssh_banner(banner)
                result_dict["software"] = parsed["software"]
                result_dict["version"] = parsed["version"]
            
            return True 
            
    return False

# --- SCANNER ---
def scan(host, port, timeout):
    """
    Fluxo principal de escaneamento de uma porta:
    1. Conexão -> 2. Captura de Banner -> 3. Probing HTTP -> 4. Fallback por Porta
    """
    # Estrutura base para armazenar os dados
    output = {
        "port": port, "state": "closed", "service": "unknown",
        "software": "unknown", "version": None, "banner": "", "notes": ""
    }

    try:
        # Etapa 1: Verifica se a porta está aberta
        with get_socket(timeout) as s:
            result = s.connect_ex((host, port))

        if result == 0:
            output["state"] = "open"

            # Etapa 2: Captura Passiva de Banner (espera o serviço enviar dados)
            try:
                with get_socket(timeout) as s_banner:
                    s_banner.connect((host, port))
                    data = s_banner.recv(1024)
                    if data:
                        output["banner"] = data.decode(errors='ignore').strip()
            except Exception:
                pass

            # Etapa 3: Fingerprinting do banner coletado
            if output["banner"]:
                analyze_banner(output["banner"], output)

            # Etapa 4: Probing Ativo (caso o serviço seja desconhecido ou porta seja HTTP)
            if output["service"] == "unknown" or port in HTTP_PORTS:
                svc, info = probe_http(host, port, timeout)
                if svc:
                    output["service"] = svc
                    output["notes"] = info

            # Etapa 5: Fallback (se tudo falhar, assume serviço padrão da porta)
            if output["service"] == "unknown":
                if port in COMMON_PORTS:
                    output["service"] = f"{COMMON_PORTS[port]} (provável)"

        # Tratamento de estados de rede (Filtered/Firewall)
        elif result in (errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH):
            output["state"] = "filtered"

    except Exception as e:
        output["state"] = "error"
        output["notes"] = str(e)

    return output

# --- CONFIGURAÇÃO DA SAÍDA DE DADOS ---
def print_pro_header():
    """Imprime o cabeçalho estilizado no terminal."""
    print(f"\n{'='*85}")
    print(f" PORT-SCAN | Alvo: {TARGET}")
    print(f" Threads: {MAX_THREADS} | Timeout: {TIMEOUT}s | Início: {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*85}\n")
    print(f"{'PORTA':<10} | {'ESTADO':<10} | {'SERVIÇO':<16} | {'DETALHES/VERSÃO'}")
    print(f"{'-'*10:<10} | {'-'*10:<10} | {'-'*16:<16} | {'-'*40}")

def print_result_row(res: dict):
    """Formata e exibe os dados de uma porta aberta de forma tabular."""
    port_col = f"{res['port']}/tcp"
    state_col = res['state'].upper()
    service_col = res['service'].upper()
    
    # Lógica de prioridade de exibição: Versão > Notas > Banner
    if res['version']:
        detail_col = f"{res['software']} {res['version']}"
    elif res['notes']:
        detail_col = res['notes']
    elif res['banner']:
        clean_banner = res['banner'].replace('\r', '').replace('\n', ' ')
        detail_col = (clean_banner[:37] + '...') if len(clean_banner) > 40 else clean_banner
    else:
        detail_col = "-"
        
    print(f"{port_col:<10} | {state_col:<10} | {service_col:<16} | {detail_col}")

if __name__ == "__main__":
    start_time = datetime.now()
    print_pro_header()

    open_ports_count = 0

    # Uso do ThreadPoolExecutor para gerenciar a concorrência de forma eficiente
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        # Mapeia o scan para o range de portas (1 a 1024)
        futures = [
            executor.submit(scan, TARGET, port, TIMEOUT)
            for port in range(1, 1025)
        ]

        # Processa e exibe os resultados assim que cada thread finaliza
        for future in as_completed(futures):
            try:
                resultado = future.result()
                
                # Exibe no terminal apenas o que estiver aberto
                if resultado["state"] == "open":
                    print_result_row(resultado)
                    open_ports_count += 1
            except Exception:
                pass

    # Rodapé com estatísticas finais
    duration = datetime.now() - start_time
    print(f"\n{'='*85}")
    print(f" Scan finalizado em {duration.total_seconds():.2f} segundos.")
    print(f" Total de portas abertas: {open_ports_count}")
    print(f"{'='*85}")