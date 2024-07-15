import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scapy.all import sniff, IP
from threading import Thread, Event
import queue
import datetime
import os

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        
        # Create a resizable window
        self.root.geometry("800x600")
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)
        
        self.sniffing = False
        self.sniffer_thread = None
        self.packet_queue = queue.Queue()  # Queue for packet data
        self.stop_sniffing_event = Event()  # Event to signal stop sniffing
        
        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.grid(row=0, column=0, pady=10, padx=10, sticky=tk.W)
        
        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_button.grid(row=0, column=1, pady=10, padx=10, sticky=tk.E)
        self.stop_button.config(state=tk.DISABLED)
        
        self.save_button = tk.Button(root, text="Save Data", command=self.save_sniffed_data)
        self.save_button.grid(row=0, column=2, pady=10, padx=10, sticky=tk.E)
        self.save_button.config(state=tk.DISABLED)
        
        # Create a Treeview widget
        self.tree = ttk.Treeview(root, columns=("Source", "Destination", "Protocol", "Payload"), show="headings")
        self.tree.heading("Source", text="Source IP")
        self.tree.heading("Destination", text="Destination IP")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Payload", text="Payload")
        
        # Configure column widths and weights for resizing
        self.tree.column("Source", width=150, anchor=tk.CENTER)
        self.tree.column("Destination", width=150, anchor=tk.CENTER)
        self.tree.column("Protocol", width=100, anchor=tk.CENTER)
        self.tree.column("Payload", width=400, anchor=tk.CENTER)
        
        self.tree.grid(row=1, column=0, columnspan=3, padx=10, pady=10, sticky=tk.NSEW)
        
        # Add vertical scrollbar
        self.scrollbar = ttk.Scrollbar(root, orient="vertical", command=self.tree.yview)
        self.scrollbar.grid(row=1, column=3, sticky=tk.NS)
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        # Configure resizing behavior
        root.grid_columnconfigure(0, weight=1)
        root.grid_rowconfigure(1, weight=1)

        # Initialize logging if enabled
        self.enable_logging = False  # Set this to True if you want to enable logging
        if self.enable_logging:
            self.setup_logging()

    def setup_logging(self):
        if self.enable_logging:
            self.log_file = open("log.txt", "a")
            self.log("Packet Sniffer started.")

    def log(self, message):
        # Only log important messages if logging is enabled
        if self.enable_logging and ("started" in message.lower() or "stopped" in message.lower() or "error" in message.lower()):
            timestamped_message = f"[{self.get_timestamp()}] {message}\n"
            self.log_file.write(timestamped_message)
            self.log_file.flush()  # Ensure logs are immediately written to file

    def get_timestamp(self):
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def packet_callback(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto
            payload = str(packet[IP].payload)
            
            # Put packet data into the queue for GUI update
            self.packet_queue.put((ip_src, ip_dst, protocol, payload))

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.save_button.config(state=tk.DISABLED)  # Disable save button while sniffing
            self.log("Packet sniffing started.")

            # Start packet sniffing in a separate thread
            self.sniffer_thread = Thread(target=self.sniff_packets)
            self.sniffer_thread.start()
            
            # Start a separate thread to update GUI from queue
            self.update_gui_thread = Thread(target=self.update_gui_from_queue)
            self.update_gui_thread.start()

    def sniff_packets(self):
        try:
            sniff(prn=self.packet_callback, stop_filter=lambda x: self.stop_sniffing_event.is_set())
        except Exception as e:
            self.log(f"Error in packet sniffing: {str(e)}")

    def update_gui_from_queue(self):
        while self.sniffing or not self.packet_queue.empty():
            try:
                ip_src, ip_dst, protocol, payload = self.packet_queue.get(timeout=1)
                self.tree.insert("", tk.END, values=(ip_src, ip_dst, protocol, payload))
                self.tree.yview_moveto(1.0)  # Move scrollbar to the bottom
            except queue.Empty:
                continue

    def stop_sniffing(self):
        if self.sniffing:
            self.sniffing = False
            self.stop_sniffing_event.set()  # Set the event to stop sniffing
            
            if self.sniffer_thread:
                self.sniffer_thread.join(timeout=2)  # Allow 2 seconds for the thread to finish
            
            # Stop the update GUI thread
            if self.update_gui_thread:
                self.update_gui_thread.join()

            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.save_button.config(state=tk.NORMAL)  # Enable save button after sniffing stops
            self.log("Packet sniffing stopped.")
            
            if self.enable_logging:
                self.log_file.close()

    def save_sniffed_data(self):
        # Prompt user to select save location
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        
        if file_path:
            # Determine the appropriate file name to avoid overwriting existing files
            save_file_path = self.generate_unique_filename(file_path)
            
            try:
                with open(save_file_path, "w") as f:
                    f.write("Source, Destination, Protocol, Payload\n")
                    for child in self.tree.get_children():
                        values = self.tree.item(child)["values"]
                        f.write(f"{values[0]}, {values[1]}, {values[2]}, {values[3]}\n")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save data: {str(e)}")
                return
            
            messagebox.showinfo("Saved", f"Sniffed data saved successfully to:\n{save_file_path}")

    def generate_unique_filename(self, file_path):
        base_dir = os.path.dirname(file_path)
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        ext = os.path.splitext(file_path)[1]
        
        index = 1
        while os.path.exists(file_path):
            file_path = os.path.join(base_dir, f"{base_name}({index}){ext}")
            index += 1
        
        return file_path

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
