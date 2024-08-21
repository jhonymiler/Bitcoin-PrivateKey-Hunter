from multiprocessing.managers import BaseManager
from queue import Queue
import logging
import socket
import fcntl
import struct

# Configuração do logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("server.log"),
        logging.StreamHandler()
    ]
)

task_queue = Queue()
result_queue = Queue()
found_flag = Queue()

class QueueManager(BaseManager):
    pass

QueueManager.register('get_task_queue', callable=lambda: task_queue)
QueueManager.register('get_result_queue', callable=lambda: result_queue)
QueueManager.register('get_found_flag', callable=lambda: found_flag)

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15].encode('utf-8'))
    )[20:24])

def start_server(port=50000, authkey=b'abc'):
    try:
        ip_address = get_ip_address('eth0')  # Substitua 'eth0' pela interface correta
    except IOError:
        ip_address = '127.0.0.1'  # Fallback para loopback se a interface não for encontrada
    
    manager = QueueManager(address=(ip_address, port), authkey=authkey)
    server = manager.get_server()
    logging.info(f"Servidor iniciado no IP {ip_address} na porta {port}, aguardando clientes...")
    server.serve_forever()

if __name__ == '__main__':
    min_range = int("40000", 16)
    max_range = int("7FFFF", 16)
    num_blocks = 100
    chunk_size = (max_range - min_range) // num_blocks
    
    for i in range(num_blocks):
        start = min_range + i * chunk_size
        end = start + chunk_size
        task_queue.put((start, end))
    
    start_server()
