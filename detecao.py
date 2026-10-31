import asyncio
import sys
import pyshark

# Configuração do loop de eventos assíncrono para suprimir erros residuais de fechamento do tshark
def suprimir_erros_asyncio(loop, context):
    exception = context.get("exception")
    if isinstance(exception, (EOFError, BrokenPipeError, ConnectionResetError)):
        return  # Suprime exceções normais decorrentes do encerramento abrupto do pipe do tshark
    loop.default_exception_handler(context)

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
loop.set_exception_handler(suprimir_erros_asyncio)

LIMITE_DE_PORTAS = 15

captura = pyshark.LiveCapture(interface="wlo1", 
                              bpf_filter="tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0")

#criando um dicionario para salvar todas as tentativas de conexao que um endereco
# ip tentar realizar
registro_conexoes = {}  

# evita multiplos alertas para o mesmo endereco IP
ips_alertados = set()

try:
    for pacote in captura.sniff_continuously():
        try:
        # aqui ele esta lendo o endereco IP que está tentando se conectar 
            ip_origem = pacote.ip.src 

        # aqui esta a porta que o endereco IP esta tentando se conectar
            porta_destino = int(pacote.tcp.dstport)

        # verificando se o ip_origem ja esta no dicionario registro_conexoes
            if ip_origem not in registro_conexoes:
                registro_conexoes[ip_origem]=set()

        #adicionando a porta de destino que o ip de origem esta tentando se conectar
            registro_conexoes[ip_origem].add(porta_destino)
            total = len(registro_conexoes[ip_origem])
            if total >= LIMITE_DE_PORTAS and ip_origem not in ips_alertados:
                print(f"\nALERTA! Possível Port Scan detectado vindo do endereço IP {ip_origem}")
                print(f"\n Número de portas contatadas: {total}")
                ips_alertados.add(ip_origem)

        except AttributeError:
            continue

except KeyboardInterrupt:
    print("\nMonitoramento encerrado!")

finally:
    try:
        captura.close()
    except Exception:
        pass
    print("\nScript finalizado")
    sys.exit(0)
