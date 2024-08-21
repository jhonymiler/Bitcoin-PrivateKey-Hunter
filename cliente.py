import queue
from multiprocessing.managers import BaseManager  # Adicione essa linha
from ecdsa import SECP256k1, ellipticcurve
import hashlib
import base58
import logging
from multiprocessing import Process, Manager

# Configuração do logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("client.log"),
        logging.StreamHandler()
    ]
)

# Configuração da curva SECP256k1
curve = SECP256k1.curve
G = SECP256k1.generator

def calculate_y(x, p):
    y_squared = (pow(x, 3, p) + 7) % p
    y = pow(y_squared, (p + 1) // 4, p)
    if pow(y, 2, p) == y_squared:
        return y, p - y
    else:
        raise ValueError("O ponto não está na curva.")

x_pub = 0x85663c8b2f90659e1ccab201694f4f8ec24b3749cfe5030c7c3646a709408e19
y_pub1, y_pub2 = calculate_y(x_pub, curve.p())
y_pub = min(y_pub1, y_pub2)

def generate_wif(private_key_hex):
    private_key = bytes.fromhex(private_key_hex)
    extended_key = b'\x80' + private_key
    hashed_key = hashlib.sha256(extended_key).digest()
    hashed_key = hashlib.sha256(hashed_key).digest()
    wif = base58.b58encode(extended_key + hashed_key[:4])
    return wif.decode()

def verify_private_key(private_key, x_pub, y_pub):
    Q = private_key * G
    return Q.x() == x_pub and (Q.y() == y_pub or Q.y() == curve.p() - y_pub)

class QueueManager(BaseManager):  
    pass

QueueManager.register('get_task_queue')
QueueManager.register('get_result_queue')
QueueManager.register('get_found_flag')

def worker_process(start, end, found_flag, result_queue, client_name):
    logging.info(f"Processo processando bloco de {start} até {end}")
    for k in range(start, end):
        if not found_flag.empty():
            found_by = found_flag.get()
            logging.info(f"Processo interrompido, chave já encontrada por {found_by}")
            return

        private_key = k

        if verify_private_key(private_key, x_pub, y_pub):
            wif = generate_wif(f'{private_key:064x}')
            logging.info(f"Chave privada encontrada por {client_name}: {hex(private_key)}")
            
            # Notifica todos os clientes que a chave foi encontrada
            found_flag.put(client_name)
            result_queue.put((private_key, wif))

            with open('keys.txt', 'a') as f:
                f.write(f"Private key: {hex(private_key)}, WIF: {wif}\n")
            return

def client_work(server_ip, client_name, port=50000, authkey=b'abc', num_processes=4):
    manager = QueueManager(address=(server_ip, port), authkey=authkey)
    manager.connect()

    task_queue = manager.get_task_queue()
    result_queue = manager.get_result_queue()
    found_flag = manager.get_found_flag()

    logging.info(f"{client_name} conectado ao servidor, aguardando tarefas...")

    while not task_queue.empty():
        try:
            start, end = task_queue.get(timeout=1)
            logging.info(f"Dividindo o bloco de {start} até {end} em {num_processes} processos")

            # Divida o intervalo em subintervalos para multiprocessing
            interval_size = (end - start) // num_processes
            processes = []

            for i in range(num_processes):
                sub_start = start + i * interval_size
                sub_end = sub_start + interval_size if i < num_processes - 1 else end
                process = Process(target=worker_process, args=(sub_start, sub_end, found_flag, result_queue, client_name))
                process.start()
                processes.append(process)

            for process in processes:
                process.join()

        except queue.Empty:
            logging.info("Nenhuma tarefa restante.")
            break

if __name__ == '__main__':
    server_ip = '172.30.135.213'
    client_name = input("Digite seu nome: ")
    client_work(server_ip, client_name)
