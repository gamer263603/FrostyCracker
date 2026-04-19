#!/usr/bin/env python3
"""
Aircrack-ng GUI Tool
A graphical interface for wireless network auditing tools
Requires: PyQt5, aircrack-ng suite installed on system
"""

import sys
import os
import subprocess
import threading
import re
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QTextEdit, QLabel, 
                             QComboBox, QLineEdit, QFileDialog, QGroupBox,
                             QProgressBar, QTabWidget, QTableWidget, QTableWidgetItem,
                             QHeaderView, QMessageBox, QCheckBox, QSpinBox,
                             QGridLayout, QAbstractItemView)
from PyQt5.QtCore import QTimer, Qt, pyqtSignal, QObject
from PyQt5.QtGui import QFont, QColor, QTextCursor

class CommandExecutor(QObject):
    """Handles command execution in separate thread"""
    output_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(int)
    
    def __init__(self):
        super().__init__()
        self.process = None
        
    def execute_command(self, command, sudo=False):
        """Execute a command and emit output"""
        def run():
            try:
                if sudo:
                    cmd = ['sudo'] + command.split()
                else:
                    cmd = command.split()
                
                self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                               stderr=subprocess.STDOUT, 
                                               text=True, bufsize=1)
                
                for line in iter(self.process.stdout.readline, ''):
                    if line:
                        self.output_signal.emit(line.strip())
                
                self.process.wait()
                self.finished_signal.emit(self.process.returncode)
                
            except Exception as e:
                self.output_signal.emit(f"Error: {str(e)}")
                self.finished_signal.emit(1)
        
        thread = threading.Thread(target=run)
        thread.daemon = True
        thread.start()
    
    def stop(self):
        """Stop the running process"""
        if self.process:
            self.process.terminate()

class AircrackGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.executor = CommandExecutor()
        self.executor.output_signal.connect(self.append_output)
        self.executor.finished_signal.connect(self.command_finished)
        
        self.init_ui()
        self.check_dependencies()
        
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Aircrack-ng GUI Tool")
        self.setGeometry(100, 100, 1300, 900)
        
        # Set dark theme style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2b2b2b;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #555;
                border-radius: 5px;
                margin-top: 1ex;
                padding-top: 10px;
                color: #00ff00;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QPushButton {
                background-color: #4CAF50;
                border: none;
                color: white;
                padding: 8px 16px;
                text-align: center;
                text-decoration: none;
                font-size: 14px;
                margin: 4px 2px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
            QTextEdit {
                background-color: #1e1e1e;
                color: #00ff00;
                font-family: monospace;
                border: 1px solid #555;
            }
            QLineEdit, QComboBox {
                padding: 5px;
                background-color: #3c3c3c;
                color: white;
                border: 1px solid #555;
                border-radius: 3px;
            }
            QTableWidget {
                background-color: #1e1e1e;
                color: white;
                gridline-color: #555;
                alternate-background-color: #2a2a2a;
                selection-background-color: #4CAF50;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QHeaderView::section {
                background-color: #3c3c3c;
                color: #00ff00;
                padding: 8px;
                border: 1px solid #555;
                font-weight: bold;
            }
            QLabel {
                color: white;
            }
            QTabWidget::pane {
                border: 1px solid #555;
                background-color: #2b2b2b;
            }
            QTabBar::tab {
                background-color: #3c3c3c;
                color: white;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #4CAF50;
            }
            QTabBar::tab:hover {
                background-color: #45a049;
            }
        """)
        
        # Central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        tabs = QTabWidget()
        main_layout.addWidget(tabs)
        
        # Create tabs
        self.create_monitor_tab(tabs)
        self.create_capture_tab(tabs)
        self.create_crack_tab(tabs)
        self.create_deauth_tab(tabs)
        self.create_output_tab(tabs)
        
        # Status bar
        self.statusBar().showMessage("Ready")
        self.statusBar().setStyleSheet("color: #00ff00;")
        
    def create_monitor_tab(self, tabs):
        """Create monitor mode management tab"""
        monitor_widget = QWidget()
        layout = QVBoxLayout(monitor_widget)
        
        # Interface selection
        interface_group = QGroupBox("Network Interface")
        interface_layout = QHBoxLayout()
        
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.get_wireless_interfaces())
        self.interface_combo.setMinimumWidth(200)
        refresh_btn = QPushButton("🔄 Refresh Interfaces")
        refresh_btn.clicked.connect(self.refresh_interfaces)
        
        interface_layout.addWidget(QLabel("Wireless Interface:"))
        interface_layout.addWidget(self.interface_combo)
        interface_layout.addWidget(refresh_btn)
        interface_group.setLayout(interface_layout)
        layout.addWidget(interface_group)
        
        # Monitor mode controls
        monitor_group = QGroupBox("Monitor Mode Controls")
        monitor_layout = QHBoxLayout()
        
        enable_monitor_btn = QPushButton("📡 Enable Monitor Mode")
        enable_monitor_btn.clicked.connect(self.enable_monitor_mode)
        disable_monitor_btn = QPushButton("❌ Disable Monitor Mode")
        disable_monitor_btn.clicked.connect(self.disable_monitor_mode)
        
        monitor_layout.addWidget(enable_monitor_btn)
        monitor_layout.addWidget(disable_monitor_btn)
        monitor_group.setLayout(monitor_layout)
        layout.addWidget(monitor_group)
        
        # Kill processes button
        kill_btn = QPushButton("🔫 Kill Conflicting Processes")
        kill_btn.clicked.connect(self.kill_conflicting_processes)
        layout.addWidget(kill_btn)
        
        # Info label
        info_label = QLabel("ℹ️ Note: Run 'sudo airmon-ng check kill' first to kill conflicting processes")
        info_label.setStyleSheet("color: #ffaa00; font-size: 11px;")
        layout.addWidget(info_label)
        
        layout.addStretch()
        tabs.addTab(monitor_widget, "📡 Monitor Mode")
        
    def create_capture_tab(self, tabs):
        """Create packet capture tab"""
        capture_widget = QWidget()
        layout = QVBoxLayout(capture_widget)
        
        # Capture settings
        settings_group = QGroupBox("Capture Settings")
        settings_layout = QGridLayout()
        
        settings_layout.addWidget(QLabel("Interface:"), 0, 0)
        self.capture_interface = QComboBox()
        self.capture_interface.setMinimumWidth(200)
        settings_layout.addWidget(self.capture_interface, 0, 1)
        
        settings_layout.addWidget(QLabel("Channel:"), 1, 0)
        self.channel_spin = QSpinBox()
        self.channel_spin.setRange(1, 14)
        self.channel_spin.setValue(6)
        settings_layout.addWidget(self.channel_spin, 1, 1)
        
        settings_layout.addWidget(QLabel("Output File:"), 2, 0)
        self.capture_file = QLineEdit()
        self.capture_file.setText("capture-01.cap")
        self.capture_file.setMinimumWidth(300)
        settings_layout.addWidget(self.capture_file, 2, 1)
        
        browse_btn = QPushButton("📁 Browse")
        browse_btn.clicked.connect(self.browse_capture_file)
        settings_layout.addWidget(browse_btn, 2, 2)
        
        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)
        
        # BSSID filtering
        filter_group = QGroupBox("Filter by BSSID (Optional)")
        filter_layout = QHBoxLayout()
        self.bssid_filter = QLineEdit()
        self.bssid_filter.setPlaceholderText("00:11:22:33:44:55")
        self.bssid_filter.setMinimumWidth(300)
        filter_layout.addWidget(self.bssid_filter)
        filter_group.setLayout(filter_layout)
        layout.addWidget(filter_group)
        
        # Capture controls
        capture_controls = QHBoxLayout()
        self.start_capture_btn = QPushButton("▶️ Start Capture")
        self.start_capture_btn.clicked.connect(self.start_capture)
        self.stop_capture_btn = QPushButton("⏹️ Stop Capture")
        self.stop_capture_btn.clicked.connect(self.stop_capture)
        self.stop_capture_btn.setEnabled(False)
        
        capture_controls.addWidget(self.start_capture_btn)
        capture_controls.addWidget(self.stop_capture_btn)
        layout.addLayout(capture_controls)
        
        # Scan networks button
        scan_btn = QPushButton("🔍 Scan Networks")
        scan_btn.clicked.connect(self.scan_networks)
        layout.addWidget(scan_btn)
        
        # Networks table with improved settings
        self.networks_table = QTableWidget()
        self.networks_table.setColumnCount(5)
        self.networks_table.setHorizontalHeaderLabels(["BSSID", "Channel", "Encryption", "ESSID", "Signal"])
        self.networks_table.setAlternatingRowColors(True)
        self.networks_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.networks_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.networks_table.horizontalHeader().setStretchLastSection(True)
        self.networks_table.setMinimumHeight(300)
        
        # Set column widths
        self.networks_table.setColumnWidth(0, 180)  # BSSID
        self.networks_table.setColumnWidth(1, 80)   # Channel
        self.networks_table.setColumnWidth(2, 150)  # Encryption
        self.networks_table.setColumnWidth(3, 250)  # ESSID
        self.networks_table.setColumnWidth(4, 80)   # Signal
        
        layout.addWidget(self.networks_table)
        
        tabs.addTab(capture_widget, "📡 Capture Packets")
        
    def create_crack_tab(self, tabs):
        """Create WEP/WPA cracking tab"""
        crack_widget = QWidget()
        layout = QVBoxLayout(crack_widget)
        
        # File selection
        file_group = QGroupBox("Capture File")
        file_layout = QHBoxLayout()
        
        self.crack_file = QLineEdit()
        self.crack_file.setPlaceholderText("Select .cap file...")
        browse_cap_btn = QPushButton("📁 Browse")
        browse_cap_btn.clicked.connect(self.browse_cap_file)
        
        file_layout.addWidget(self.crack_file)
        file_layout.addWidget(browse_cap_btn)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Wordlist selection (for WPA)
        wordlist_group = QGroupBox("Wordlist (for WPA/WPA2)")
        wordlist_layout = QHBoxLayout()
        
        self.wordlist_file = QLineEdit()
        self.wordlist_file.setPlaceholderText("Select wordlist file...")
        browse_wordlist_btn = QPushButton("📁 Browse")
        browse_wordlist_btn.clicked.connect(self.browse_wordlist)
        
        wordlist_layout.addWidget(self.wordlist_file)
        wordlist_layout.addWidget(browse_wordlist_btn)
        wordlist_group.setLayout(wordlist_layout)
        layout.addWidget(wordlist_group)
        
        # Crack buttons
        crack_buttons = QHBoxLayout()
        crack_wep_btn = QPushButton("🔓 Crack WEP")
        crack_wep_btn.clicked.connect(self.crack_wep)
        crack_wpa_btn = QPushButton("🔑 Crack WPA/WPA2")
        crack_wpa_btn.clicked.connect(self.crack_wpa)
        
        crack_buttons.addWidget(crack_wep_btn)
        crack_buttons.addWidget(crack_wpa_btn)
        layout.addLayout(crack_buttons)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        layout.addStretch()
        tabs.addTab(crack_widget, "🔑 Crack Password")
        
    def create_deauth_tab(self, tabs):
        """Create deauthentication attack tab"""
        deauth_widget = QWidget()
        layout = QVBoxLayout(deauth_widget)
        
        # Warning label
        warning_label = QLabel("⚠️ WARNING: This should only be used on your own networks! ⚠️")
        warning_label.setStyleSheet("color: #ff0000; font-weight: bold; font-size: 14px;")
        layout.addWidget(warning_label)
        
        # Target settings
        target_group = QGroupBox("Target Information")
        target_layout = QGridLayout()
        
        target_layout.addWidget(QLabel("Interface (Monitor Mode):"), 0, 0)
        self.deauth_interface = QComboBox()
        self.deauth_interface.setMinimumWidth(200)
        target_layout.addWidget(self.deauth_interface, 0, 1)
        
        target_layout.addWidget(QLabel("Target BSSID:"), 1, 0)
        self.target_bssid = QLineEdit()
        self.target_bssid.setPlaceholderText("00:11:22:33:44:55")
        self.target_bssid.setMinimumWidth(200)
        target_layout.addWidget(self.target_bssid, 1, 1)
        
        target_layout.addWidget(QLabel("Client Station (optional):"), 2, 0)
        self.client_station = QLineEdit()
        self.client_station.setPlaceholderText("FF:FF:FF:FF:FF:FF for broadcast")
        target_layout.addWidget(self.client_station, 2, 1)
        
        target_layout.addWidget(QLabel("Number of packets:"), 3, 0)
        self.packet_count = QSpinBox()
        self.packet_count.setRange(0, 10000)
        self.packet_count.setValue(10)
        target_layout.addWidget(self.packet_count, 3, 1)
        
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)
        
        # Attack button
        deauth_btn = QPushButton("⚠️ Send Deauthentication Packets ⚠️")
        deauth_btn.clicked.connect(self.send_deauth)
        deauth_btn.setStyleSheet("background-color: #f44336; font-weight: bold;")
        layout.addWidget(deauth_btn)
        
        layout.addStretch()
        tabs.addTab(deauth_widget, "⚠️ Deauth Attack")
        
    def create_output_tab(self, tabs):
        """Create output/console tab"""
        output_widget = QWidget()
        layout = QVBoxLayout(output_widget)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Monospace", 10))
        layout.addWidget(self.output_text)
        
        # Control buttons
        button_layout = QHBoxLayout()
        clear_btn = QPushButton("🗑️ Clear Output")
        clear_btn.clicked.connect(self.clear_output)
        save_btn = QPushButton("💾 Save Output")
        save_btn.clicked.connect(self.save_output)
        
        button_layout.addWidget(clear_btn)
        button_layout.addWidget(save_btn)
        layout.addLayout(button_layout)
        
        tabs.addTab(output_widget, "📝 Output")
        
    def get_wireless_interfaces(self):
        """Get list of wireless interfaces"""
        try:
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            interfaces = []
            for line in result.stdout.split('\n'):
                if 'IEEE 802.11' in line:
                    interface = line.split()[0]
                    interfaces.append(interface)
            return interfaces if interfaces else ['wlan0', 'wlan1']
        except:
            return ['wlan0', 'wlan1']
    
    def refresh_interfaces(self):
        """Refresh the interface lists"""
        interfaces = self.get_wireless_interfaces()
        self.interface_combo.clear()
        self.capture_interface.clear()
        self.deauth_interface.clear()
        self.interface_combo.addItems(interfaces)
        self.capture_interface.addItems(interfaces)
        self.deauth_interface.addItems(interfaces)
        self.append_output(f"Refreshed interfaces: {', '.join(interfaces)}")
        
    def check_dependencies(self):
        """Check if required tools are installed"""
        required_tools = ['airmon-ng', 'airodump-ng', 'aireplay-ng', 'aircrack-ng']
        missing = []
        
        for tool in required_tools:
            try:
                subprocess.run([tool, '--help'], capture_output=True)
            except FileNotFoundError:
                missing.append(tool)
        
        if missing:
            self.append_output(f"⚠️ Warning: Missing tools: {', '.join(missing)}")
            self.append_output("Please install aircrack-ng suite: sudo apt-get install aircrack-ng")
        else:
            self.append_output("✅ All dependencies are installed")
    
    def enable_monitor_mode(self):
        """Enable monitor mode on selected interface"""
        interface = self.interface_combo.currentText()
        if interface:
            self.append_output(f"📡 Enabling monitor mode on {interface}...")
            self.executor.execute_command(f"sudo airmon-ng start {interface}", sudo=False)
    
    def disable_monitor_mode(self):
        """Disable monitor mode"""
        interface = self.interface_combo.currentText()
        if interface:
            self.append_output(f"📡 Disabling monitor mode on {interface}...")
            self.executor.execute_command(f"sudo airmon-ng stop {interface}mon", sudo=False)
    
    def kill_conflicting_processes(self):
        """Kill processes that might interfere"""
        self.append_output("🔫 Killing conflicting processes...")
        self.executor.execute_command("sudo airmon-ng check kill", sudo=False)
    
    def browse_capture_file(self):
        """Browse for capture output file"""
        filename, _ = QFileDialog.getSaveFileName(self, "Save Capture File", "", "Capture Files (*.cap)")
        if filename:
            self.capture_file.setText(filename)
    
    def browse_cap_file(self):
        """Browse for .cap file to crack"""
        filename, _ = QFileDialog.getOpenFileName(self, "Open Capture File", "", "Capture Files (*.cap)")
        if filename:
            self.crack_file.setText(filename)
    
    def browse_wordlist(self):
        """Browse for wordlist file"""
        filename, _ = QFileDialog.getOpenFileName(self, "Select Wordlist", "", "Wordlist Files (*.txt *.lst)")
        if filename:
            self.wordlist_file.setText(filename)
    
    def start_capture(self):
        """Start packet capture"""
        interface = self.capture_interface.currentText()
        output_file = self.capture_file.text()
        channel = self.channel_spin.value()
        bssid = self.bssid_filter.text()
        
        if not interface or not output_file:
            QMessageBox.warning(self, "Warning", "Please select interface and output file")
            return
        
        # Build command
        cmd = f"sudo airodump-ng -w {output_file} --channel {channel} {interface}"
        if bssid:
            cmd += f" --bssid {bssid}"
        
        self.append_output(f"▶️ Starting capture: {cmd}")
        self.executor.execute_command(cmd, sudo=False)
        self.start_capture_btn.setEnabled(False)
        self.stop_capture_btn.setEnabled(True)
    
    def stop_capture(self):
        """Stop packet capture"""
        self.append_output("⏹️ Stopping capture...")
        self.executor.stop()
        self.start_capture_btn.setEnabled(True)
        self.stop_capture_btn.setEnabled(False)
    
    def scan_networks(self):
        """Scan for nearby networks"""
        interface = self.capture_interface.currentText()
        if not interface:
            QMessageBox.warning(self, "Warning", "Please select an interface")
            return
        
        self.append_output("🔍 Scanning for networks... (This will run for 30 seconds)")
        self.networks_table.setRowCount(0)  # Clear existing networks
        
        # Use a temporary file
        temp_file = f"/tmp/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Run scan in background and parse when done
        def run_scan():
            # Run airodump-ng for 30 seconds
            cmd = f"sudo timeout 30 airodump-ng -w {temp_file} --output-format csv {interface}"
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            process.wait()
            
            # Parse the CSV file after scan completes
            csv_file = f"{temp_file}-01.csv"
            self.parse_networks(csv_file)
            
            # Clean up temp files
            try:
                if os.path.exists(csv_file):
                    os.remove(csv_file)
                if os.path.exists(f"{temp_file}-01.kismet.csv"):
                    os.remove(f"{temp_file}-01.kismet.csv")
                if os.path.exists(f"{temp_file}-01.kismet.netxml"):
                    os.remove(f"{temp_file}-01.kismet.netxml")
            except:
                pass
        
        # Run scan in separate thread
        scan_thread = threading.Thread(target=run_scan)
        scan_thread.daemon = True
        scan_thread.start()
    
    def parse_networks(self, csv_file):
        """Parse airodump CSV output and display networks clearly"""
        try:
            if not os.path.exists(csv_file):
                self.append_output("❌ Scan completed but no data found. Make sure the interface is in monitor mode.")
                return
            
            with open(csv_file, 'r') as f:
                content = f.read()
            
            # Clear existing rows
            self.networks_table.setRowCount(0)
            
            # Parse CSV properly
            lines = content.split('\n')
            network_count = 0
            
            for line in lines:
                # Skip empty lines and header lines
                if not line.strip() or line.startswith('BSSID') or line.startswith('Station'):
                    continue
                
                # Split by comma but handle quoted fields
                parts = []
                in_quote = False
                current_part = []
                
                for char in line:
                    if char == '"':
                        in_quote = not in_quote
                    elif char == ',' and not in_quote:
                        parts.append(''.join(current_part).strip())
                        current_part = []
                    else:
                        current_part.append(char)
                parts.append(''.join(current_part).strip())
                
                # Network entries have at least 15 fields
                if len(parts) >= 15 and parts[0] and parts[0] != "BSSID":
                    bssid = parts[0]
                    # Skip if it's not a valid MAC address
                    if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', bssid):
                        continue
                    
                    # Extract network information
                    channel = parts[3] if len(parts) > 3 else "?"
                    encryption = parts[5] if len(parts) > 5 else "?"
                    cipher = parts[6] if len(parts) > 6 else ""
                    auth = parts[7] if len(parts) > 7 else ""
                    power = parts[8] if len(parts) > 8 else "0"
                    essid = parts[13] if len(parts) > 13 else ""
                    
                    # Clean up encryption info
                    if encryption == "OPN":
                        encryption_text = "Open"
                    elif encryption == "WEP":
                        encryption_text = "WEP"
                    elif "WPA2" in encryption:
                        encryption_text = f"WPA2 {cipher}"
                    elif "WPA" in encryption:
                        encryption_text = f"WPA {cipher}"
                    else:
                        encryption_text = encryption if encryption else "Unknown"
                    
                    # Add to table
                    row = self.networks_table.rowCount()
                    self.networks_table.insertRow(row)
                    
                    # Create items with better visibility
                    bssid_item = QTableWidgetItem(bssid)
                    channel_item = QTableWidgetItem(str(channel))
                    encryption_item = QTableWidgetItem(encryption_text)
                    essid_item = QTableWidgetItem(essid if essid else "<Hidden Network>")
                    
                    # Format signal strength
                    try:
                        power_val = int(power)
                        if power_val > -50:
                            signal_text = f"{power_val} dBm 📶📶📶"
                            signal_color = QColor(0, 255, 0)  # Green - strong
                        elif power_val > -70:
                            signal_text = f"{power_val} dBm 📶📶"
                            signal_color = QColor(255, 255, 0)  # Yellow - medium
                        else:
                            signal_text = f"{power_val} dBm 📶"
                            signal_color = QColor(255, 0, 0)  # Red - weak
                    except:
                        signal_text = "N/A"
                        signal_color = QColor(128, 128, 128)
                    
                    power_item = QTableWidgetItem(signal_text)
                    power_item.setForeground(signal_color)
                    
                    # Set items
                    self.networks_table.setItem(row, 0, bssid_item)
                    self.networks_table.setItem(row, 1, channel_item)
                    self.networks_table.setItem(row, 2, encryption_item)
                    self.networks_table.setItem(row, 3, essid_item)
                    self.networks_table.setItem(row, 4, power_item)
                    
                    network_count += 1
            
            self.append_output(f"✅ Found {network_count} networks")
            
            # Auto-fit columns
            self.networks_table.resizeColumnsToContents()
            
            if network_count == 0:
                self.append_output("💡 Tip: Make sure your interface is in monitor mode and you're within range of networks")
            
        except Exception as e:
            self.append_output(f"❌ Error parsing networks: {str(e)}")
    
    def crack_wep(self):
        """Crack WEP key"""
        cap_file = self.crack_file.text()
        if not cap_file or not os.path.exists(cap_file):
            QMessageBox.warning(self, "Warning", "Please select a valid .cap file")
            return
        
        self.append_output(f"🔓 Cracking WEP key from {cap_file}...")
        self.executor.execute_command(f"aircrack-ng {cap_file}", sudo=False)
    
    def crack_wpa(self):
        """Crack WPA/WPA2 key"""
        cap_file = self.crack_file.text()
        wordlist = self.wordlist_file.text()
        
        if not cap_file or not os.path.exists(cap_file):
            QMessageBox.warning(self, "Warning", "Please select a valid .cap file")
            return
        
        if not wordlist or not os.path.exists(wordlist):
            QMessageBox.warning(self, "Warning", "Please select a valid wordlist file")
            return
        
        self.append_output(f"🔑 Cracking WPA/WPA2 key from {cap_file} using {wordlist}...")
        self.executor.execute_command(f"aircrack-ng -w {wordlist} {cap_file}", sudo=False)
    
    def send_deauth(self):
        """Send deauthentication packets"""
        interface = self.deauth_interface.currentText()
        bssid = self.target_bssid.text()
        client = self.client_station.text() if self.client_station.text() else "-0"
        count = self.packet_count.value()
        
        if not interface or not bssid:
            QMessageBox.warning(self, "Warning", "Please select interface and target BSSID")
            return
        
        # Confirm dangerous action
        reply = QMessageBox.warning(self, "⚠️ WARNING ⚠️", 
                                   "This will send deauthentication packets which can disconnect clients!\n"
                                   "Only use this on networks you own or have permission to test.\n\n"
                                   "Do you want to continue?",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.No:
            return
        
        # Build deauth command correctly
        if client == "-0":
            cmd = f"sudo aireplay-ng -0 {count} -a {bssid} {interface}"
        else:
            cmd = f"sudo aireplay-ng -0 {count} -a {bssid} -c {client} {interface}"
        
        self.append_output(f"⚠️ Sending deauth packets: {cmd}")
        self.executor.execute_command(cmd, sudo=False)
    
    def append_output(self, text):
        """Append text to output console"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.output_text.append(f"[{timestamp}] {text}")
        # Auto-scroll to bottom
        self.output_text.moveCursor(QTextCursor.End)
    
    def clear_output(self):
        """Clear output console"""
        self.output_text.clear()
        self.append_output("Output cleared")
    
    def save_output(self):
        """Save output to file"""
        filename, _ = QFileDialog.getSaveFileName(self, "Save Output", "", "Text Files (*.txt)")
        if filename:
            with open(filename, 'w') as f:
                f.write(self.output_text.toPlainText())
            self.append_output(f"💾 Output saved to {filename}")
    
    def command_finished(self, returncode):
        """Handle command completion"""
        self.append_output(f"✅ Command finished with return code: {returncode}")
        self.start_capture_btn.setEnabled(True)
        self.stop_capture_btn.setEnabled(False)
        self.statusBar().showMessage("Ready")
    
    def closeEvent(self, event):
        """Handle application close"""
        reply = QMessageBox.question(self, 'Exit', 
                                   'Are you sure you want to exit?',
                                   QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = AircrackGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
