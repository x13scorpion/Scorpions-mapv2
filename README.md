#!/usr/bin/env python3
"""
Scorpions Map - Framework de Varredura e Auditoria de Rede
Wrapper em Python sobre nmap, traceroute, dig e curl.

AVISO: use apenas em redes/sistemas que você tem autorização para testar.
"""

import argparse
import os
import subprocess
import sys
import time
import shutil

# Configurações de Cores para Interface
C_GREEN = "\033[1;32m"
C_RED = "\033[1;31m"
C_YELLOW = "\033[1;33m"
C_BLUE = "\033[1;34m"
C_CYAN = "\033[1;36m"
C_RESET = "\033[0m"


class ScorpionsMap:
    def __init__(self):
        self.target = ""
        self.mode = ""  # 'ip' ou 'url'
        self.report_lines = []  # guarda saída para o relatório final

    # ---------------------------------------------------------------
    # Utilitários de interface
    # ---------------------------------------------------------------
    def banner(self):
        os.system('clear')
        print(f"{C_YELLOW}")
        if shutil.which("figlet"):
            os.system('figlet Scorpions Map')
        else:
            print("=== SCORPIONS MAP ===")
        print(f"{C_CYAN}==========================================================")
        print(f"{C_RED}[!] Framework de Varredura e Auditoria de Rede v2.0")
        print(f"{C_CYAN}=========================================================={C_RESET}")
        print(f"{C_YELLOW}Status: Engine Ready | Modo: Aguardando Alvo{C_RESET}\n")

    def log(self, message, level="INFO"):
        levels = {
            "INFO": f"{C_BLUE}[*]{C_RESET}",
            "SUCCESS": f"{C_GREEN}[+]{C_RESET}",
            "WARNING": f"{C_YELLOW}[!]{C_RESET}",
            "ERROR": f"{C_RED}[X]{C_RESET}",
        }
        print(f"{levels.get(level, '[ ]')} {message}")

    def check_dependencies(self, tools):
        """Verifica se os binários necessários existem antes de tentar usá-los."""
        missing = [t for t in tools if not shutil.which(t)]
        if missing:
            self.log(f"Ferramentas ausentes: {', '.join(missing)}. Instale-as para usar todos os recursos.", "WARNING")
        return missing

    def run_command(self, command, capture_for_report=True):
        """Executa comandos de sistema e captura saída em tempo real."""
        try:
            process = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True
            )
            for line in process.stdout:
                line = line.rstrip()
                print(line)
                if capture_for_report:
                    self.report_lines.append(line)
            process.wait()
        except Exception as e:
            self.log(f"Erro ao executar comando: {e}", "ERROR")

    # ---------------------------------------------------------------
    # Descoberta de hosts na rede
    # ---------------------------------------------------------------
    def discover_hosts(self, subnet):
        """Descobre hosts ativos em uma sub-rede (ex: 192.168.1.0/24)."""
        self.log(f"Descobrindo hosts ativos em {subnet}...", "INFO")
        # -sn: ping scan (sem port scan), apenas descoberta de hosts vivos
        self.run_command(f"nmap -sn {subnet}")

    # ---------------------------------------------------------------
    # Scan principal de portas / serviços / SO / vulnerabilidades
    # ---------------------------------------------------------------
    def scan_network(self, target, aggressive=False, udp=False, ipv6=False):
        """
        Módulo Principal de Varredura (Nmap Engine)
        Cobre: port scan, detecção de serviço/versão, SO, MAC/fabricante,
        scripts NSE padrão e, opcionalmente, scripts de vulnerabilidade.
        """
        self.log(f"Iniciando varredura completa em: {target}", "INFO")

        flags = "-6 " if ipv6 else ""
        # -sV: versão de serviço | -O: SO | -sC: scripts NSE padrão
        # -T4: velocidade | -Pn: ignora ping (contorna firewalls que bloqueiam ICMP)
        cmd = f"nmap {flags}-sV -O -sC -T4 -Pn {target}"

        if aggressive:
            self.log("MODO AGRESSIVO: varredura de vulnerabilidades com NSE...", "WARNING")
            cmd = f"nmap {flags}-sV -sC --script vuln -T4 -Pn {target}"

        if udp:
            self.log("Incluindo varredura de portas UDP (mais lenta)...", "INFO")
            cmd += " -sU"

        self.log(f"Executando: {cmd}", "INFO")
        self.run_command(cmd)

    def scan_dns_recon(self, target):
        """Reconhecimento de infraestrutura: traceroute, DNS e portas UDP rápidas."""
        self.log(f"Iniciando reconhecimento de infraestrutura para {target}...", "INFO")

        print(f"\n{C_CYAN}--- [1] Rota de Rede (Traceroute) ---{C_RESET}")
        self.run_command(f"traceroute {target}")

        print(f"\n{C_CYAN}--- [2] Resolução de DNS e Host ---{C_RESET}")
        self.run_command(f"dig {target} ANY")

        print(f"\n{C_CYAN}--- [3] Verificação rápida de portas UDP ---{C_RESET}")
        self.run_command(f"nmap -sU -F {target}")

    def scan_url_web(self, url):
        """Módulo especializado para alvos HTTP/HTTPS."""
        self.log(f"Alvo Web detectado: {url}", "INFO")

        print(f"\n{C_CYAN}--- [1] Headers de Segurança HTTP ---{C_RESET}")
        self.run_command(
            f"curl -I -s {url} | grep -iE "
            f"'server|x-powered-by|strict-transport-security|content-security-policy'"
        )

        print(f"\n{C_CYAN}--- [2] Portas Web Comuns ---{C_RESET}")
        self.run_command(f"nmap -p 80,443,8080,8443 -sV {url}")

    # ---------------------------------------------------------------
    # Relatórios
    # ---------------------------------------------------------------
    def save_report(self, target, fmt="txt"):
        """Exporta resultados para .txt (log completo) ou .xml (saída nativa do nmap)."""
        safe_name = target.replace('.', '_').replace('/', '_').replace(':', '_')

        if fmt == "xml":
            filename = f"report_{safe_name}.xml"
            self.log(f"Gerando relatório XML nativo do nmap em {filename}...", "INFO")
            self.run_command(f"nmap -sV -O -oX {filename} {target}", capture_for_report=False)
            self.log(f"Relatório XML salvo: {filename}", "SUCCESS")
        else:
            filename = f"report_{safe_name}.txt"
            self.log(f"Salvando relatório em {filename}...", "INFO")
            with open(filename, "w") as f:
                f.write(f"Relatório de Varredura Scorpions Map\n")
                f.write(f"Alvo: {target}\n")
                f.write(f"Data: {time.ctime()}\n")
                f.write("=" * 60 + "\n\n")
                f.write("\n".join(self.report_lines))
            self.log(f"Relatório salvo: {filename}", "SUCCESS")


def main():
    parser = argparse.ArgumentParser(
        description="Scorpions Map - Framework de Varredura e Auditoria de Rede"
    )
    parser.add_argument("-u", "--url", help="Alvo por URL (HTTP/HTTPS)")
    parser.add_argument("-i", "--ip", help="Alvo por endereço IP ou domínio")
    parser.add_argument("-d", "--discover", help="Descobrir hosts ativos em uma sub-rede (ex: 192.168.1.0/24)")
    parser.add_argument("-a", "--aggressive", action="store_true", help="Varredura agressiva (NSE vuln)")
    parser.add_argument("--udp", action="store_true", help="Incluir varredura de portas UDP")
    parser.add_argument("-6", "--ipv6", action="store_true", help="Varredura via IPv6")
    parser.add_argument("-s", "--save", action="store_true", help="Salvar relatório em .txt")
    parser.add_argument("--xml", action="store_true", help="Salvar relatório em .xml (formato nativo do nmap)")

    args = parser.parse_args()
    scanner = ScorpionsMap()
    scanner.banner()

    scanner.check_dependencies(["nmap", "curl", "dig", "traceroute"])

    if args.discover:
        scanner.discover_hosts(args.discover)
        if args.save:
            scanner.save_report(args.discover)
        sys.exit()

    if args.url:
        scanner.mode = "url"
        scanner.target = args.url
        scanner.scan_url_web(args.url)
        if args.aggressive:
            scanner.scan_network(args.url, aggressive=True, udp=args.udp, ipv6=args.ipv6)

    elif args.ip:
        scanner.mode = "ip"
        scanner.target = args.ip
        scanner.scan_dns_recon(args.ip)
        scanner.scan_network(args.ip, aggressive=args.aggressive, udp=args.udp, ipv6=args.ipv6)

    else:
        print(f"{C_RED}[!] Erro: selecione um alvo com -u (URL), -i (IP) ou -d (descoberta de rede){C_RESET}")
        print(f"{C_YELLOW}Exemplos:{C_RESET}")
        print("  python3 scorpions_map.py -i 192.168.1.1")
        print("  python3 scorpions_map.py -u https://alvo.com -a")
        print("  python3 scorpions_map.py -d 192.168.1.0/24")
        print("  python3 scorpions_map.py -i alvo.com -a --udp -s --xml")
        sys.exit()

    target = args.ip if args.ip else args.url
    if args.save:
        scanner.save_report(target)
    if args.xml:
        scanner.save_report(target, fmt="xml")

    print(f"\n{C_GREEN}==========================================================")
    print(f"{C_GREEN}   VARREDURA FINALIZADA PELO SCORPIONS MAP{C_RESET}")
    print(f"{C_GREEN}=========================================================={C_RESET}")


if __name__ == "__main__":
    main()
# Scorpions-mapv2
