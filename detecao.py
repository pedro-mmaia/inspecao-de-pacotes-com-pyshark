import pyshark

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

