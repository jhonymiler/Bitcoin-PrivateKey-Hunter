# Bitcoin-PrivateKey-Hunter

Distributed system in Python for finding private keys of Bitcoin wallets. It uses multiprocessing and multithreading to divide and process key blocks in parallel, enabling efficient searches in distributed networks.

## Requirements

- Python 3.7+
- WSL (Windows Subsystem for Linux) if running on Windows.

## Installation

1. Clone the repository or download the files.

2. Install the dependencies listed in `requirements.txt`:

    ```bash
    pip install -r requirements.txt
    ```

## Configuration

### Server

1. The server needs to be configured to listen on a valid IP address on the network. The `server.py` file is already configured to automatically detect the IP of the `eth0` network interface. Make sure that the interface name (`eth0`) matches the correct interface on your system.

2. To start the server, run:

    ```bash
    python server.py
    ```

   The server will divide the key range into 100 blocks and start listening for client connections on port `50000`.

### Client

1. The client will connect to the server and process the key blocks in parallel using 12 threads (by default).

2. To start the client, run:

    ```bash
    python client.py
    ```

3. The client will ask you to enter your name. This name will be used to notify all other clients if the correct key is found.

## How It Works

- **Server**: The server distributes key blocks to clients and listens on port `50000` for connections.
- **Client**: Each client connects to the server, receives key blocks, and processes these blocks in parallel using threads. When a matching key is found, all other clients are notified, and processing stops.
- **Multithreading**: The client divides the key block into subranges and processes each subrange in a separate thread.

## File Structure

- `server.py`: Server code.
- `client.py`: Client code.
- `requirements.txt`: List of dependencies needed for the project.
- `README.md`: This file, containing instructions for setting up and running the project.

## Contribution

If you wish to contribute to this project, feel free to open a pull request or report issues.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
