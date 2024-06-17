# Packet Sniffer

## Benefits of a Packet Sniffer in Cyber Security

Packet sniffing is a crucial technique in network security, used to monitor and analyze network traffic. By capturing packets, security professionals can detect anomalies, troubleshoot network issues, and identify potential security breaches. A packet sniffer can help in understanding the flow of data across the network, ensuring that sensitive information is not being transmitted insecurely, and verifying the proper functioning of network protocols.

## Installation

1. **Download the Source Code:**
    - Clone the repository to your local machine using the following command:
        ```sh
        git clone https://github.com/your-username/packet-sniffer.git
        ```

2. **Install Dependencies:**
    - Ensure you have [pip](https://pypi.org/project/pip/) and [Python](https://www.python.org/downloads/) installed on your machine.
    - Install the required Python modules `colorama` and `scapy` using the following command:
        ```sh
        pip3 install colorama scapy
        ```

## Running the Script

1. **Help Screen:**
    - To view the help screen of the script, execute the following command in your terminal:
        ```sh
        python3 packet_sniffer.py --help
        ```

2. **Run the Script:**
    - Execute the following command in your terminal to run the packet sniffer on a specific network interface:
        ```sh
        python3 packet_sniffer.py -i <interface>
        ```

    - Replace `<interface>` with the network interface you want to sniff (e.g., `eth0` or `wlan0`).

### Examples

- To sniff packets on the network interface `eth0`:
    ```sh
    python3 packet_sniffer.py -i eth0
    ```

- To sniff packets on the network interface `wlan0`:
    ```sh
    python3 packet_sniffer.py -i wlan0
    ```
