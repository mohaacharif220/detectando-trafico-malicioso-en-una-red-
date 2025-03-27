import scapy.all as scapy
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# 1. Captura de paquetes en la interfaz 'enp0s8'
def capturar_paquetes():
    print("Capturando paquetes en la interfaz enp0s8...")
    packets = scapy.sniff(iface="enp0s8", count=100)
    scapy.wrpcap("trafico.pcap", packets)
    return packets

# 2. Procesar los paquetes capturados y detectar escaneos de puertos
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

            if src_ip not in conteo_por_ip:
                conteo_por_ip[src_ip] = {'puertos': set(), 'icmp': 0}

            if protocol == 1:  # ICMP (ping)
                conteo_por_ip[src_ip]['icmp'] += 1
            elif protocol == 6:  # TCP
                conteo_por_ip[src_ip]['puertos'].add(dport)

            data.append([src_ip, dst_ip, protocol, sport, dport])

    # Determinar etiquetas basadas en la actividad
    processed_data = []
    for entry in data:
        src_ip = entry[0]
        protocol = entry[2]
        dport = entry[4]

        if protocol == 1 and conteo_por_ip[src_ip]['icmp'] > 10:
            label = 1  # ICMP flood
        elif protocol == 6 and len(conteo_por_ip[src_ip]['puertos']) > 10:
            label = 1  # Escaneo de puertos
        else:
            label = 0  # Tráfico normal

        processed_data.append(entry + [label])

    df = pd.DataFrame(processed_data, columns=["Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Label"])
    return df

# 3. Visualización de actividad sospechosa
def visualizar_protocolos(df):
    print("Visualizando distribución de protocolos...")
    df["Protocol"].value_counts().plot(kind="bar")
    plt.title("Distribución de Protocolos en el Tráfico")
    plt.xlabel("Protocolo")
    plt.ylabel("Cantidad")
    plt.show()

    print("Visualizando IPs sospechosas...")
    ip_sospechosas = df[df["Label"] == 1]["Source IP"].value_counts()
    if not ip_sospechosas.empty:
        ip_sospechosas.plot(kind="bar", color="red")
        plt.title("IPs sospechosas de actividades maliciosas")
        plt.xlabel("IP de origen")
        plt.ylabel("Cantidad de paquetes")
        plt.show()
    else:
        print("No se detectaron IPs sospechosas.")

# 4. Preparación de los datos para Machine Learning
def preparar_datos(df):
    df['Source IP'] = df['Source IP'].apply(lambda x: int(x.split('.')[3]))
    df['Destination IP'] = df['Destination IP'].apply(lambda x: int(x.split('.')[3]))
    X = df[['Source IP', 'Destination IP', 'Protocol', 'Source Port', 'Destination Port']]
    y = df['Label']
    return X, y

# 5. Entrenamiento del modelo de Machine Learning
def entrenar_modelo(X, y):
    print("Entrenando el modelo de Machine Learning...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = RandomForestClassifier()
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f'Precisión del modelo: {accuracy}')
    return clf

# 6. Realizar una predicción sobre un nuevo paquete
def predecir_trafico(clf):
    nuevos_paquetes = pd.DataFrame([[192, 168, 1, 12345, 80]], columns=['Source IP', 'Destination IP', 'Protocol', 'Source Port', 'Destination Port'])
    prediccion = clf.predict(nuevos_paquetes)
    print(f'Predicción para el nuevo paquete: {"Malicioso" if prediccion[0] == 1 else "Normal"}')

# Función principal
def main():
    paquetes = capturar_paquetes()
    df = procesar_paquetes(paquetes)
    visualizar_protocolos(df)
    X, y = preparar_datos(df)
    clf = entrenar_modelo(X, y)
    predecir_trafico(clf)

if __name__ == "__main__":
    main()
