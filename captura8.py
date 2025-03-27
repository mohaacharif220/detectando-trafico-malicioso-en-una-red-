def procesar_paquetes(packets):
    print("Procesando paquetes capturados...")
    data = []
    conteo_por_ip = {}

    for packet in packets:
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            protocol = packet[scapy.IP].proto
            sport = packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else 0
            dport = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else 0
            timestamp = packet.time

            if src_ip not in conteo_por_ip:
                conteo_por_ip[src_ip] = {'puertos': set(), 'icmp': 0, 'destinos_icmp': set(), 'timestamps': []}

            if protocol == 1:  # ICMP (ping)
                conteo_por_ip[src_ip]['icmp'] += 1
                conteo_por_ip[src_ip]['destinos_icmp'].add(dst_ip)
            elif protocol == 6:  # TCP
                conteo_por_ip[src_ip]['puertos'].add(dport)

            conteo_por_ip[src_ip]['timestamps'].append(timestamp)
            data.append([src_ip, dst_ip, protocol, sport, dport])

    # Determinar etiquetas basadas en la actividad
    processed_data = []
    for entry in data:
        src_ip = entry[0]
        protocol = entry[2]

        label = 0  # Tráfico normal por defecto

        # Detección de ICMP flood o escaneo ICMP
        if protocol == 1:
            num_icmp = conteo_por_ip[src_ip]['icmp']
            num_destinos_icmp = len(conteo_por_ip[src_ip]['destinos_icmp'])
            if num_icmp > 10 and num_destinos_icmp > 5:
                label = 1  # Actividad ICMP sospechosa

        # Detección de escaneo de puertos TCP
        elif protocol == 6:
            num_puertos = len(conteo_por_ip[src_ip]['puertos'])
            if num_puertos > 10:
                label = 1  # Escaneo de puertos

        processed_data.append(entry + [label])

    df = pd.DataFrame(processed_data, columns=["Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Label"])
    return df
