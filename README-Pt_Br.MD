# Bitcoin-PrivateKey-Hunter

Sistema distribuído em Python para encontrar chaves privadas de carteiras Bitcoin. Utiliza multiprocessing para dividir e processar blocos de chaves em paralelo, permitindo buscas eficientes em redes distribuídas.

## Requisitos

- Python 3.7+
- WSL (Windows Subsystem for Linux) se estiver executando no Windows.

## Instalação

1. Clone o repositório ou baixe os arquivos.

2. Instale as dependências listadas em `requirements.txt`:

    ```bash
    pip install -r requirements.txt
    ```

## Configuração

### Servidor

1. O servidor precisa ser configurado para escutar em um IP válido na rede. O arquivo `server.py` já está configurado para detectar automaticamente o IP da interface de rede `eth0`. Certifique-se de que o nome da interface (`eth0`) corresponde à interface correta em seu sistema.

2. Para iniciar o servidor, execute:

    ```bash
    python server.py
    ```

   O servidor dividirá o intervalo de chaves em 100 blocos e começará a escutar as conexões dos clientes na porta `50000`.

### Cliente

1. O cliente se conectará ao servidor e processará os blocos de chaves em paralelo usando 12 threads (por padrão).

2. Para iniciar o cliente, execute:

    ```bash
    python client.py
    ```

3. O cliente solicitará que você insira seu nome. Este nome será usado para notificar todos os outros clientes caso a chave correta seja encontrada.

## Como Funciona

- **Servidor**: O servidor distribui blocos de chaves para os clientes e escuta a porta `50000` para conexões.
- **Cliente**: Cada cliente se conecta ao servidor, recebe blocos de chaves e processa esses blocos em paralelo usando threads. Quando uma chave correspondente é encontrada, todos os outros clientes são notificados e o processamento para.
- **Multiprocessing**: O cliente divide o bloco de chaves em subintervalos e processa cada subintervalo em um processo separado.

## Estrutura dos Arquivos

- `server.py`: Código do servidor.
- `client.py`: Código do cliente.
- `requirements.txt`: Lista de dependências necessárias para o projeto.
- `README.md`: Este arquivo, contendo as instruções para configurar e executar o projeto.

## Contribuição

Se você deseja contribuir com este projeto, sinta-se à vontade para abrir um pull request ou reportar issues.

## Licença

Este projeto está sob a licença MIT. Veja o arquivo LICENSE para mais detalhes.
