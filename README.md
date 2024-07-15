# PRODIGY_CS_05_packet_sniffer

# Packet Sniffer Application

Packet Sniffer Application is a Python-based GUI tool for sniffing and logging network packets using Scapy and Tkinter.

## Features

- Start and stop packet sniffing.
- Display captured packet information in a scrollable table.
- Save captured packet data to a text file.
- Error logging with timestamped messages.

## Requirements

- Python 3.x
- Required Python packages:
  - `tkinter`
  - `scapy`
  
  Install required packages using pip:

  ```
  pip install scapy tk
  ```

## Usage

1. Clone the repository:

   ```
   git clone https://github.com/matalha786/PRODIGY_CS_05_packet_snifferr
   ```

2. Run the application:

   ```
   python packet_sniffer.py
   ```

3. Interface Overview:
   - Click **Start Sniffing** to begin capturing packets.
   - Click **Stop Sniffing** to stop packet capture.
   - Click **Save Data** to save captured packet information to a text file.

## How It Works

The application utilizes Scapy for packet sniffing and Tkinter for the graphical user interface (GUI). It spawns separate threads for packet capture and GUI updates to maintain responsiveness.



## License

This project is licensed under the GPL License - see the LICENSE file for details.
