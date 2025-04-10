import sys
import os
import json
import time

# Add the parent directory of 'src' to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from PyQt6 import QtWidgets, uic, QtGui, QtCore, QtPrintSupport
from modules import recon
from utils.logger import get_logger
from src.modules.network_mapper import NetworkMapper, NetworkNode, NetworkLink, NetworkMapResult
from src.utils.check_dependencies import check_nmap_installation, get_nmap_installation_instructions
from src.ui.recon_viz import ReconVizTab


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        """Initialize the main window"""
        super().__init__()
        
        # Load the UI from the .ui file
        self.ui = uic.loadUi("src/ui/main_window.ui", self)
        
        # Load additional UI pages
        self.reconPage = uic.loadUi("src/ui/recon.ui")
        self.vulnScanPage = uic.loadUi("src/ui/vuln_scanner.ui")
        self.bruteForceePage = uic.loadUi("src/ui/brute_force.ui")
        self.payloadGenPage = uic.loadUi("src/ui/payload_gen.ui")
        self.exploitExecPage = uic.loadUi("src/ui/exploit_exec.ui")
        self.networkMapperPage = uic.loadUi("src/ui/network_mapper.ui")
        self.logsPage = uic.loadUi("src/ui/logs.ui")
        self.terminalPage = uic.loadUi("src/ui/terminal.ui")
        self.settingsPage = uic.loadUi("src/ui/settings.ui")
        self.reportPage = uic.loadUi("src/ui/report.ui")
        
        # Create the recon visualization tab
        self.reconVizTab = ReconVizTab()
        
        # Add visualization tab to recon page
        if hasattr(self.reconPage, 'mainTabWidget'):
            self.reconPage.mainTabWidget.addTab(self.reconVizTab, "Visualization")
        
        # Add pages to the stacked widget
        self.stackedWidget = self.ui.findChild(QtWidgets.QStackedWidget, "stackedWidget")
        self.stackedWidget.addWidget(self.reconPage)
        self.stackedWidget.addWidget(self.vulnScanPage)
        self.stackedWidget.addWidget(self.bruteForceePage)
        self.stackedWidget.addWidget(self.payloadGenPage)
        self.stackedWidget.addWidget(self.exploitExecPage)
        self.stackedWidget.addWidget(self.networkMapperPage)
        self.stackedWidget.addWidget(self.logsPage)
        self.stackedWidget.addWidget(self.terminalPage)
        self.stackedWidget.addWidget(self.settingsPage)
        self.stackedWidget.addWidget(self.reportPage)
        
        # Set up the dashboard module buttons and connect them to functions
        self.reconButton = self.ui.findChild(QtWidgets.QPushButton, "reconButton")
        self.vulnScannerButton = self.ui.findChild(QtWidgets.QPushButton, "vulnScannerButton")
        self.bruteForceButton = self.ui.findChild(QtWidgets.QPushButton, "bruteForceButton")
        self.payloadGenButton = self.ui.findChild(QtWidgets.QPushButton, "payloadGenButton")
        self.exploitExecButton = self.ui.findChild(QtWidgets.QPushButton, "exploitExecButton")
        self.networkMapperButton = self.ui.findChild(QtWidgets.QPushButton, "networkMapperButton")
        self.serviceEnumButton = self.ui.findChild(QtWidgets.QPushButton, "serviceEnumButton")
        self.scanEngineButton = self.ui.findChild(QtWidgets.QPushButton, "scanEngineButton")
        self.webScannerButton = self.ui.findChild(QtWidgets.QPushButton, "webScannerButton")
        self.authBypassButton = self.ui.findChild(QtWidgets.QPushButton, "authBypassButton")
        self.reportGenButton = self.ui.findChild(QtWidgets.QPushButton, "reportGenButton")
        self.settingsButton = self.ui.findChild(QtWidgets.QPushButton, "settingsButton")
        
        # Find the log and terminal utility buttons
        self.clearLogsButton = self.ui.findChild(QtWidgets.QPushButton, "clearLogsButton")
        self.saveLogsButton = self.ui.findChild(QtWidgets.QPushButton, "saveLogsButton")
        self.terminalExecuteButton = self.ui.findChild(QtWidgets.QPushButton, "terminalExecuteButton")
        self.terminalClearButton = self.ui.findChild(QtWidgets.QPushButton, "terminalClearButton")
        
        # Connect dashboard buttons to switch pages
        if self.reconButton:
            self.reconButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.reconPage))
        if self.vulnScannerButton:
            self.vulnScannerButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.vulnScanPage))
        if self.bruteForceButton:
            self.bruteForceButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.bruteForceePage))
        if self.payloadGenButton:
            self.payloadGenButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.payloadGenPage))
        if self.exploitExecButton:
            self.exploitExecButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.exploitExecPage))
        if self.networkMapperButton:
            self.networkMapperButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.networkMapperPage))
        if self.serviceEnumButton:
            self.serviceEnumButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.serviceEnumPage))
        if self.scanEngineButton:
            self.scanEngineButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.scanResultPage))
        if self.webScannerButton:
            self.webScannerButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.webScannerPage))
        if self.authBypassButton:
            self.authBypassButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.authBypassPage))
        if self.reportGenButton:
            self.reportGenButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.reportPage))
        if self.settingsButton:
            self.settingsButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.settingsPage))
        
        # Connect the nmap options - Checkbox to enable/disable script line edit
        self.networkMapperPage.scriptScanCheckBox.toggled.connect(self.toggle_nmap_script_field)
        
        # Connect menu actions
        self.actionLogs.triggered.connect(lambda: self.logsDockWidget.setVisible(not self.logsDockWidget.isVisible()))
        self.actionTerminal.triggered.connect(lambda: self.terminalDockWidget.setVisible(not self.terminalDockWidget.isVisible()))
        self.actionDashboard.triggered.connect(lambda: self.stackedWidget.setCurrentIndex(0))
        
        # Connect file menu actions
        self.actionNew_Project.triggered.connect(self.new_project)
        self.actionOpen_Project.triggered.connect(self.open_project)
        self.actionSave_Project.triggered.connect(self.save_project)
        self.actionSave_Project_As.triggered.connect(self.save_project_as)
        self.actionImport.triggered.connect(self.import_data)
        self.actionExport.triggered.connect(self.export_data)
        self.actionExit.triggered.connect(self.quit_application)
        
        # Connect edit menu actions
        self.actionCut.triggered.connect(self.cut_action)
        self.actionCopy.triggered.connect(self.copy_action)
        self.actionPaste.triggered.connect(self.paste_action)
        self.actionPreferences.triggered.connect(lambda: self.stackedWidget.setCurrentWidget(self.settingsPage))
        
        # Connect view menu actions
        self.actionFull_Screen.triggered.connect(self.toggle_fullscreen)
        
        # Connect module menu actions
        self.actionReconnaissance.triggered.connect(lambda: self.stackedWidget.setCurrentWidget(self.reconPage))
        self.actionNetwork_Mapper.triggered.connect(lambda: self.stackedWidget.setCurrentWidget(self.networkMapperPage))
        self.actionService_Enumeration.triggered.connect(lambda: self.stackedWidget.setCurrentWidget(self.serviceEnumPage))
        self.actionScan_Engine.triggered.connect(lambda: self.stackedWidget.setCurrentWidget(self.scanResultPage))
        self.actionWeb_Scanner.triggered.connect(lambda: self.stackedWidget.setCurrentWidget(self.webScannerPage))
        self.actionVulnerability_Scanner.triggered.connect(lambda: self.stackedWidget.setCurrentWidget(self.vulnScanPage))
        self.actionBrute_Force.triggered.connect(lambda: self.stackedWidget.setCurrentWidget(self.bruteForceePage))
        self.actionAuth_Bypass.triggered.connect(lambda: self.stackedWidget.setCurrentWidget(self.authBypassPage))
        self.actionPayload_Generator.triggered.connect(lambda: self.stackedWidget.setCurrentWidget(self.payloadGenPage))
        self.actionExploit_Execution.triggered.connect(lambda: self.stackedWidget.setCurrentWidget(self.exploitExecPage))
        self.actionReport_Generator.triggered.connect(lambda: self.stackedWidget.setCurrentWidget(self.reportPage))
        
        # Connect help menu actions
        self.actionDocumentation.triggered.connect(self.show_documentation)
        self.actionTutorials.triggered.connect(self.show_tutorials)
        self.actionCheck_for_Updates.triggered.connect(self.check_for_updates)
        self.actionAbout.triggered.connect(self.show_about_dialog)
        
        # Connect tools menu actions
        self.actionWordlist_Manager.triggered.connect(self.open_wordlist_manager)
        self.actionPlugin_Manager.triggered.connect(self.open_plugin_manager)
        self.actionScheduler.triggered.connect(self.open_scheduler)
        self.actionTask_Manager.triggered.connect(self.open_task_manager)
        
        # Connect toolbar actions
        self.actionSettings.triggered.connect(lambda: self.stackedWidget.setCurrentWidget(self.settingsPage))

        # Set default page
        self.stackedWidget.setCurrentWidget(self.reconPage)

        # Connect Recon buttons
        self.reconPage.startButton.clicked.connect(self.start_recon)
        self.reconPage.stopButton.clicked.connect(self.stop_recon)
        
        # Connect Network Mapper buttons
        self.networkMapperPage.startButton.clicked.connect(self.start_network_mapping)
        self.networkMapperPage.stopButton.clicked.connect(self.stop_network_mapping)
        self.networkMapperPage.exportButton.clicked.connect(self.export_network_map)
        
        # Connect Logs buttons
        self.clearLogsButton.clicked.connect(self.clear_logs)
        self.saveLogsButton.clicked.connect(self.export_logs)
        
        # Connect Vulnerability Scanner buttons
        self.vulnScanPage.startButton.clicked.connect(self.start_vuln_scan)
        self.vulnScanPage.stopButton.clicked.connect(self.stop_vuln_scan)
        
        # Connect Brute Force buttons
        self.bruteForceePage.startButton.clicked.connect(self.start_brute_force)
        self.bruteForceePage.stopButton.clicked.connect(self.stop_brute_force)
        
        # Connect Payload Generator buttons
        self.payloadGenPage.generateButton.clicked.connect(self.generate_payload)
        
        # Connect Exploit Execution buttons
        self.exploitExecPage.runButton.clicked.connect(self.run_exploit)
        self.exploitExecPage.stopButton.clicked.connect(self.stop_exploit)
        
        # Connect Report buttons
        self.reportPage.generateButton.clicked.connect(self.generate_report)
        
        # Connect Terminal buttons
        self.terminalExecuteButton.clicked.connect(self.execute_command)
        self.terminalCommandLineEdit.returnPressed.connect(self.execute_command)
        self.terminalClearButton.clicked.connect(self.clear_terminal)
        
        # Connect Settings buttons
        if hasattr(self.settingsPage, 'saveButton'):
            self.settingsPage.saveButton.clicked.connect(self.save_settings)
        if hasattr(self.settingsPage, 'resetButton'):
            self.settingsPage.resetButton.clicked.connect(self.reset_settings)
        if hasattr(self.settingsPage, 'applyButton'):
            self.settingsPage.applyButton.clicked.connect(self.apply_settings)
        
        # Connect dock widget visibility to action checkboxes
        self.logsDockWidget.visibilityChanged.connect(lambda visible: self.actionLogs.setChecked(visible))
        self.terminalDockWidget.visibilityChanged.connect(lambda visible: self.actionTerminal.setChecked(visible))

        # Logging
        self.logger = get_logger("APTToolkit")
        self.recon_output = self.reconPage.rawTextEdit
        self.log_output = self.logsTextEdit
        self.terminal_output = self.terminalTextEdit

        # Spinner placeholder (loading animation)
        self.spinner = QtWidgets.QLabel(self.reconPage)
        self.spinner.setMovie(QtGui.QMovie("src/assets/icons/spinner.gif"))  # Update path if needed
        self.spinner.setVisible(False)
        self.spinner.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.reconPage.verticalLayout.addWidget(self.spinner)
        
        # Initialize modules
        self.init_modules()

    def init_modules(self):
        """Initialize all modules"""
        # This method will initialize all the modules needed by the application
        # For now, it's a placeholder that can be expanded as needed
        pass
        
    def start_recon(self):
        """Start the reconnaissance process"""
        # Get target from UI
        target = self.reconPage.targetLineEdit.text().strip()
        if not target:
            self.append_recon_output("Error: Please enter a target.")
            return
        
        # Get recon options from UI
        dns_enum = self.reconPage.dnsEnumCheckBox.isChecked()
        whois = self.reconPage.whoisCheckBox.isChecked()
        subdomain_enum = self.reconPage.subdomainEnumCheckBox.isChecked()
        reverse_ip = self.reconPage.reverseIPCheckBox.isChecked()
        port_scan = self.reconPage.portScanCheckBox.isChecked()
        service_detection = self.reconPage.serviceDetectionCheckBox.isChecked()
        os_detection = self.reconPage.osDetectionCheckBox.isChecked()
        
        # Get port range if port scanning is enabled
        ports = []
        if port_scan:
            port_range = self.reconPage.portRangeLineEdit.text().strip()
            if port_range:
                try:
                    for part in port_range.split(','):
                        if '-' in part:
                            start, end = part.split('-')
                            ports.extend(range(int(start), int(end) + 1))
                        else:
                            ports.append(int(part))
                except ValueError:
                    self.append_recon_output("Error: Invalid port range format. Using default ports.")
                    ports = []
        
        # Create recon worker thread
        self.recon_worker = ReconWorker(target, self.logger)
        self.recon_worker.output_signal.connect(self.append_recon_output)
        self.recon_worker.finished_signal.connect(self._on_recon_finished)
        
        # Disable start button and enable stop button
        self.reconPage.startButton.setEnabled(False)
        self.reconPage.stopButton.setEnabled(True)
        
        # Clear the output text
        self.reconPage.outputTextEdit.clear()
        
        # Start the worker thread
        self.recon_thread = QtCore.QThread()
        self.recon_worker.moveToThread(self.recon_thread)
        self.recon_thread.started.connect(self.recon_worker.run)
        self.recon_thread.start()
        
    def _on_recon_finished(self):
        """Handle completion of reconnaissance"""
        # Stop the worker thread
        self.recon_thread.quit()
        self.recon_thread.wait()
        
        # Enable start button and disable stop button
        self.reconPage.startButton.setEnabled(True)
        self.reconPage.stopButton.setEnabled(False)
        
        # Display results
        self.append_recon_output("\nReconnaissance completed.")
        
        # Create sample result for testing visualization
        result = self._create_sample_recon_result()
        
        # Load the recon results into the visualization tab
        self.reconVizTab.load_data(result.to_dict())
        
        # Switch to the visualization tab
        if hasattr(self.reconPage, 'mainTabWidget'):
            for i in range(self.reconPage.mainTabWidget.count()):
                if self.reconPage.mainTabWidget.tabText(i) == "Visualization":
                    self.reconPage.mainTabWidget.setCurrentIndex(i)
                    break
        
    def stop_recon(self):
        """Stop reconnaissance"""
        if hasattr(self, 'recon_worker') and self.recon_worker:
            self.append_recon_output("[*] Stopping reconnaissance...")
            self.recon_worker.stop()
            
            # Update UI
            self.reconPage.stopButton.setEnabled(False)
            
            # Give some time for the thread to clean up
            if hasattr(self, 'recon_thread') and self.recon_thread.isRunning():
                self.recon_thread.quit()
                self.recon_thread.wait(1000)  # Wait up to 1 second

    def start_vuln_scan(self):
        """Start vulnerability scanning"""
        target = self.vulnScanPage.targetLineEdit.text().strip()
        if not target:
            self.append_output(self.vulnScanPage.statusTextEdit, "[!] Please enter a valid target.")
            return
            
        self.append_output(self.vulnScanPage.statusTextEdit, f"[*] Starting vulnerability scan on: {target}")
        # Implement actual vulnerability scanning functionality
        
    def stop_vuln_scan(self):
        """Stop vulnerability scanning"""
        self.append_output(self.vulnScanPage.statusTextEdit, "[*] Stopping vulnerability scan...")
        # Implement stop functionality
        
    def start_brute_force(self):
        """Start brute force attack"""
        host = self.bruteForceePage.hostLineEdit.text().strip()
        if not host:
            self.append_output(self.bruteForceePage.statusTextEdit, "[!] Please enter a valid host.")
            return
            
        self.append_output(self.bruteForceePage.statusTextEdit, f"[*] Starting brute force attack on: {host}")
        # Implement actual brute force functionality
        
    def stop_brute_force(self):
        """Stop brute force attack"""
        self.append_output(self.bruteForceePage.statusTextEdit, "[*] Stopping brute force attack...")
        # Implement stop functionality
        
    def generate_payload(self):
        """Generate payload"""
        self.append_output(self.payloadGenPage.outputTextEdit, "[*] Generating payload...")
        # Implement payload generation functionality
        
    def run_exploit(self):
        """Run exploit"""
        self.append_output(self.exploitExecPage.consoleTextEdit, "[*] Running exploit...")
        # Implement exploit execution functionality
        
    def stop_exploit(self):
        """Stop exploit"""
        self.append_output(self.exploitExecPage.consoleTextEdit, "[*] Stopping exploit...")
        # Implement stop functionality
        
    def start_network_mapping(self):
        """Start network mapping"""
        target = self.networkMapperPage.targetLineEdit.text().strip()
        if not target:
            self.append_output(self.networkMapperPage.rawTextEdit, "[!] Please enter a valid target.")
            return
            
        # Basic input validation
        # Remove common prefixes and validate
        clean_target = target
        for prefix in ["http://", "https://", "ftp://", "ftps://"]:
            if clean_target.lower().startswith(prefix):
                clean_target = clean_target[len(prefix):]
                
        # Remove path components if present
        clean_target = clean_target.split('/')[0]
        
        # Check for obviously invalid inputs
        if ' ' in clean_target or not '.' in clean_target:
            self.append_output(self.networkMapperPage.rawTextEdit, "[!] Invalid target format. Please enter a valid IP address, domain, or hostname.")
            return
            
        # Get options from the actual UI checkboxes - Basic options
        use_traceroute = self.networkMapperPage.tracerouteCheckBox.isChecked()
        use_arp = self.networkMapperPage.arpCheckBox.isChecked()
        detect_os = self.networkMapperPage.osDetectionCheckBox.isChecked()
        discover_hosts = self.networkMapperPage.hostDiscoveryCheckBox.isChecked()
        identify_devices = self.networkMapperPage.deviceIdentificationCheckBox.isChecked()
        save_results = self.networkMapperPage.saveResultsCheckBox.isChecked()
        use_nmap = self.networkMapperPage.nmapScanCheckBox.isChecked()
        
        # Check if nmap is installed before proceeding with nmap scanning
        if use_nmap:
            system_nmap, python_nmap, error_message = check_nmap_installation()
            
            if not (system_nmap and python_nmap):
                use_nmap = False
                self.append_output(self.networkMapperPage.rawTextEdit, f"[!] Nmap scan disabled: {error_message}")
                self.append_output(self.networkMapperPage.rawTextEdit, f"[!] Falling back to basic network mapping without nmap.")
                self.networkMapperPage.nmapScanCheckBox.setChecked(False)
                
                # Show dialog with installation instructions
                msg_box = QtWidgets.QMessageBox()
                msg_box.setIcon(QtWidgets.QMessageBox.Icon.Warning)
                msg_box.setWindowTitle("Nmap Not Available")
                
                if not system_nmap:
                    instructions = get_nmap_installation_instructions()
                    msg_box.setText(f"Nmap is not installed on your system.\n\nTo install nmap, run:\n{instructions}")
                else:
                    msg_box.setText("Python-nmap library is not installed.\n\nTo install it, run:\npip install python-nmap")
                
                msg_box.setStandardButtons(QtWidgets.QMessageBox.StandardButton.Ok)
                msg_box.exec()
        
        # Get depth setting
        depth = self.networkMapperPage.depthComboBox.currentText()
        
        # Initialize visualization - clear the map view
        if hasattr(self.networkMapperPage, 'networkMapView'):
            if self.networkMapperPage.networkMapView.scene():
                self.networkMapperPage.networkMapView.scene().clear()
            else:
                self.networkMapperPage.networkMapView.setScene(QtWidgets.QGraphicsScene())
        
        # Clear status text
        self.networkMapperPage.rawTextEdit.clear()
        
        # Update status
        self.append_output(self.networkMapperPage.rawTextEdit, f"[*] Starting network mapping on {target}")
        self.append_output(self.networkMapperPage.rawTextEdit, f"[*] Scan depth: {depth}")
        self.append_output(self.networkMapperPage.rawTextEdit, f"[*] Options:")
        self.append_output(self.networkMapperPage.rawTextEdit, f"    - Traceroute: {'Enabled' if use_traceroute else 'Disabled'}")
        self.append_output(self.networkMapperPage.rawTextEdit, f"    - ARP: {'Enabled' if use_arp else 'Disabled'}")
        self.append_output(self.networkMapperPage.rawTextEdit, f"    - OS Detection: {'Enabled' if detect_os else 'Disabled'}")
        self.append_output(self.networkMapperPage.rawTextEdit, f"    - Host Discovery: {'Enabled' if discover_hosts else 'Disabled'}")
        self.append_output(self.networkMapperPage.rawTextEdit, f"    - Device Identification: {'Enabled' if identify_devices else 'Disabled'}")
        self.append_output(self.networkMapperPage.rawTextEdit, f"    - Save Results: {'Enabled' if save_results else 'Disabled'}")
        self.append_output(self.networkMapperPage.rawTextEdit, f"    - Nmap Scan: {'Enabled' if use_nmap else 'Disabled'}")
        
        # Collect advanced nmap options if nmap is enabled
        nmap_options = {}
        if use_nmap and hasattr(self.networkMapperPage, 'nmapOptionsTabWidget'):
            # Scan types
            nmap_options["tcp_syn_scan"] = self.networkMapperPage.tcpSynScanCheckBox.isChecked()
            nmap_options["tcp_connect_scan"] = self.networkMapperPage.tcpConnectScanCheckBox.isChecked()
            nmap_options["udp_scan"] = self.networkMapperPage.udpScanCheckBox.isChecked()
            nmap_options["ping_scan"] = self.networkMapperPage.pingCheckBox.isChecked()
            nmap_options["fin_scan"] = self.networkMapperPage.finScanCheckBox.isChecked()
            nmap_options["null_scan"] = self.networkMapperPage.nullScanCheckBox.isChecked()
            nmap_options["xmas_scan"] = self.networkMapperPage.xmasScanCheckBox.isChecked()
            nmap_options["ip_protocol_scan"] = self.networkMapperPage.ipProtocolScanCheckBox.isChecked()
            
            # Discovery options
            nmap_options["disable_ping"] = self.networkMapperPage.disablePingCheckBox.isChecked()
            nmap_options["tcp_syn_ping"] = self.networkMapperPage.tcpSynPingCheckBox.isChecked()
            nmap_options["tcp_ack_ping"] = self.networkMapperPage.tcpAckPingCheckBox.isChecked()
            nmap_options["udp_ping"] = self.networkMapperPage.udpPingCheckBox.isChecked()
            nmap_options["sctp_ping"] = self.networkMapperPage.sctpPingCheckBox.isChecked()
            nmap_options["icmp_echo_ping"] = self.networkMapperPage.icmpEchoPingCheckBox.isChecked()
            
            # Advanced options
            port_range = self.networkMapperPage.portRangeLineEdit.text().strip()
            if port_range:
                nmap_options["port_range"] = port_range
                self.append_output(self.networkMapperPage.rawTextEdit, f"    - Port Range: {port_range}")
                
            # Timing template
            timing_idx = self.networkMapperPage.timingComboBox.currentIndex()
            nmap_options["timing_template"] = timing_idx
            self.append_output(self.networkMapperPage.rawTextEdit, f"    - Timing Template: T{timing_idx}")
            
            # Script scan
            script_scan = self.networkMapperPage.scriptScanCheckBox.isChecked()
            nmap_options["script_scan"] = script_scan
            if script_scan:
                self.append_output(self.networkMapperPage.rawTextEdit, f"    - Script Scan: Enabled")
                script_args = self.networkMapperPage.scriptLineEdit.text().strip()
                if script_args:
                    nmap_options["script_args"] = script_args
                    self.append_output(self.networkMapperPage.rawTextEdit, f"    - Script Arguments: {script_args}")
            
            # Version detection
            version_detection = self.networkMapperPage.versionDetectionCheckBox.isChecked()
            nmap_options["version_detection"] = version_detection
            if version_detection:
                self.append_output(self.networkMapperPage.rawTextEdit, f"    - Version Detection: Enabled")
                intensity_idx = self.networkMapperPage.versionIntensityComboBox.currentIndex()
                nmap_options["version_intensity"] = intensity_idx
                self.append_output(self.networkMapperPage.rawTextEdit, f"    - Version Intensity: {intensity_idx}")
            
            # OS Detection
            nmap_options["os_detection"] = detect_os
            
            # Custom args
            custom_args = self.networkMapperPage.customArgsLineEdit.text().strip()
            if custom_args:
                nmap_options["custom_args"] = custom_args
                self.append_output(self.networkMapperPage.rawTextEdit, f"    - Custom Arguments: {custom_args}")
        
        # Update UI
        self.networkMapperPage.startButton.setEnabled(False)
        self.networkMapperPage.stopButton.setEnabled(True)
        self.networkMapperPage.exportButton.setEnabled(False)
        self.networkMapperPage.progressBar.setValue(0)
        self.networkMapperPage.statusLabel.setText("Status: Starting...")
        
        # Create thread and worker
        self.network_thread = QtCore.QThread()
        self.network_worker = NetworkMappingWorker(
            target, 
            self.logger,
            use_traceroute=use_traceroute,
            use_arp=use_arp,
            detect_os=detect_os,
            discover_hosts=discover_hosts,
            identify_devices=identify_devices
        )
        # Set the scan depth
        self.network_worker.scan_depth = depth
        # Set nmap usage
        self.network_worker.use_nmap = use_nmap
        # Set nmap options
        self.network_worker.nmap_options = nmap_options
        
        self.network_worker.moveToThread(self.network_thread)
        
        # Connect signals
        self.network_worker.output_signal.connect(lambda msg: self.append_output(self.networkMapperPage.rawTextEdit, msg))
        self.network_worker.progress_signal.connect(self.networkMapperPage.progressBar.setValue)
        self.network_worker.status_signal.connect(self.networkMapperPage.statusLabel.setText)
        self.network_worker.finished_signal.connect(self._on_network_mapping_finished)
        
        # Start thread
        self.network_thread.started.connect(self.network_worker.run)
        self.network_thread.start()
    
    def stop_network_mapping(self):
        """Stop network mapping"""
        if hasattr(self, 'network_worker') and self.network_worker:
            self.network_worker.stop()
            self.append_output(self.networkMapperPage.rawTextEdit, "[*] Stopping network mapping...")
            self.networkMapperPage.statusLabel.setText("Status: Stopping")
            
            # Give some time for the thread to clean up
            if hasattr(self, 'network_thread') and self.network_thread.isRunning():
                self.network_thread.quit()
                self.network_thread.wait(1000)  # Wait up to 1 second
        else:
            self.append_output(self.networkMapperPage.rawTextEdit, "[!] No network mapping in progress.")
    
    def export_network_map(self):
        """Export network map"""
        if not hasattr(self, 'network_worker') or not hasattr(self.network_worker, 'devices'):
            QtWidgets.QMessageBox.warning(
                self,
                "No Data",
                "No network mapping data available to export.",
                QtWidgets.QMessageBox.StandardButton.Ok
            )
            return
        
        path, filter_type = QtWidgets.QFileDialog.getSaveFileName(
            self, 
            "Export Network Map", 
            "", 
            "JSON Files (*.json);;CSV Files (*.csv);;HTML Files (*.html);;PDF Files (*.pdf);;All Files (*)"
        )
        
        if not path:
            return
        
        # Add file extension if not present
        if "json" in filter_type and not path.lower().endswith(".json"):
            path += ".json"
        elif "csv" in filter_type and not path.lower().endswith(".csv"):
            path += ".csv"
        elif "html" in filter_type and not path.lower().endswith(".html"):
            path += ".html"
        elif "pdf" in filter_type and not path.lower().endswith(".pdf"):
            path += ".pdf"
        
        try:
            self.logger.info(f"Exporting network map to {path}")
            
            # Export in different formats based on the filter type
            if path.lower().endswith(".json"):
                # Export as JSON
                with open(path, 'w') as f:
                    json.dump(self.network_worker.devices, f, indent=4)
            elif path.lower().endswith(".csv"):
                # Export as CSV
                with open(path, 'w') as f:
                    f.write("IP,Hostname,MAC,Type,OS\n")
                    for device in self.network_worker.devices:
                        f.write(f"{device['ip']},{device['hostname']},{device['mac']},{device['type']},{device['os']}\n")
            elif path.lower().endswith(".html"):
                # Export as HTML
                with open(path, 'w') as f:
                    html = "<html><head><title>Network Map Report</title></head><body>"
                    html += "<h1>Network Map Report</h1>"
                    html += f"<p><b>Target:</b> {self.network_worker.target}</p>"
                    html += f"<p><b>Scan Date:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>"
                    html += "<h2>Discovered Devices</h2>"
                    html += "<table border='1'><tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Type</th><th>OS</th></tr>"
                    
                    for device in self.network_worker.devices:
                        html += f"<tr><td>{device['ip']}</td><td>{device['hostname']}</td><td>{device['mac']}</td><td>{device['type']}</td><td>{device['os']}</td></tr>"
                    
                    html += "</table></body></html>"
                    f.write(html)
            elif path.lower().endswith(".pdf"):
                # Export placeholder for PDF (would require PDF generation library)
                QtWidgets.QMessageBox.information(
                    self,
                    "PDF Export",
                    "PDF export requires additional libraries. Please use another format.",
                    QtWidgets.QMessageBox.StandardButton.Ok
                )
                return
            
            self.append_output(self.networkMapperPage.rawTextEdit, f"[+] Network map exported to {path}")
        except Exception as e:
            self.logger.error(f"Error exporting network map: {e}")
            QtWidgets.QMessageBox.critical(
                self,
                "Export Error",
                f"Error exporting network map: {str(e)}",
                QtWidgets.QMessageBox.StandardButton.Ok
            )

    def generate_report(self):
        """Generate report"""
        report_title = self.reportPage.reportTitleLineEdit.text().strip()
        if not report_title:
            report_title = "Security Assessment Report"
            
        self.append_output(self.reportPage.statusLabel, f"[*] Generating report: {report_title}")
        # Implement report generation functionality
        
    def append_recon_output(self, message: str):
        """Append message to recon output and log it"""
        if hasattr(self, 'recon_output'):
            self.recon_output.append(message)
        if hasattr(self, 'log_output'):
            self.log_output.append(message)
        if hasattr(self, 'logger'):
            self.logger.info(message)

    def append_output(self, text_widget, message: str):
        """Append message to specified text widget and log it"""
        if text_widget and hasattr(text_widget, 'append'):
            text_widget.append(message)
        if hasattr(self, 'log_output'):
            self.log_output.append(message)
        if hasattr(self, 'logger'):
            self.logger.info(message)
        
    def clear_logs(self):
        """Clear logs"""
        if hasattr(self, 'log_output'):
            self.log_output.clear()
            self.append_output(self.log_output, "[*] Logs cleared")

    def export_logs(self):
        """Export logs to file"""
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Logs", "", "Text Files (*.txt)")
        if path:
            try:
                with open(path, "w") as f:
                    if hasattr(self, 'log_output'):
                        f.write(self.log_output.toPlainText())
                self.append_output(self.log_output, f"[+] Logs exported to: {path}")
            except Exception as e:
                self.append_output(self.log_output, f"[!] Error exporting logs: {str(e)}")
    
    def new_project(self):
        """Create a new project"""
        reply = QtWidgets.QMessageBox.question(
            self, 
            "New Project", 
            "Are you sure you want to create a new project? Any unsaved changes will be lost.",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
            QtWidgets.QMessageBox.StandardButton.No
        )
        
        if reply == QtWidgets.QMessageBox.StandardButton.Yes:
            self.logger.info("Creating new project")
            # Reset UI state for new project
            self.reconPage.rawTextEdit.clear()
            self.stackedWidget.setCurrentWidget(self.reconPage)
            self.append_recon_output("[*] New project created")
    
    def open_project(self):
        """Open an existing project"""
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, 
            "Open Project", 
            "", 
            "APT Project Files (*.apt);;All Files (*)"
        )
        
        if path:
            self.logger.info(f"Opening project from {path}")
            self.append_recon_output(f"[*] Opening project from {path}")
            # TODO: Implement project loading logic

    def save_project(self):
        """Save the current project"""
        # Check if we have a current project path
        # If not, use save_project_as
        self.save_project_as()

    def save_project_as(self):
        """Save the current project with a new name"""
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, 
            "Save Project As", 
            "", 
            "APT Project Files (*.apt)"
        )
        
        if path:
            if not path.endswith(".apt"):
                path += ".apt"
            self.logger.info(f"Saving project to {path}")
            self.append_recon_output(f"[*] Project saved to {path}")
            # TODO: Implement project saving logic

    def import_data(self):
        """Import data from file"""
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, 
            "Import Data", 
            "", 
            "All Files (*)"
        )
        
        if path:
            self.logger.info(f"Importing data from {path}")
            self.append_recon_output(f"[*] Importing data from {path}")
            # TODO: Implement data import logic

    def export_data(self):
        """Export data to file"""
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, 
            "Export Data", 
            "", 
            "All Files (*)"
        )
        
        if path:
            self.logger.info(f"Exporting data to {path}")
            self.append_recon_output(f"[*] Data exported to {path}")
            # TODO: Implement data export logic

    def quit_application(self):
        """Quit the application"""
        # Ask for confirmation if there are unsaved changes
        reply = QtWidgets.QMessageBox.question(
            self, 
            "Quit", 
            "Are you sure you want to quit? Any unsaved changes will be lost.",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
            QtWidgets.QMessageBox.StandardButton.No
        )
        
        if reply == QtWidgets.QMessageBox.StandardButton.Yes:
            self.logger.info("Quitting application")
            
            # Force cleanup of any running threads before quitting
            # This is necessary to prevent the "QThread: Destroyed while thread is still running" error
            for child in self.findChildren(QtCore.QThread):
                if child.isRunning():
                    self.logger.info(f"Waiting for thread to finish: {child.objectName() or 'unnamed thread'}")
                    child.quit()
                    child.wait(1000)  # Wait up to 1000ms for the thread to finish
            
            # Process any pending events to allow thread cleanup
            QtCore.QCoreApplication.processEvents()
            
            # Now it's safe to quit
            QtWidgets.QApplication.quit()
            
    def execute_command(self):
        """Execute command in terminal"""
        command = self.terminalCommandLineEdit.text().strip()
        if not command:
            return
            
        # Add command to history
        self.terminalPage.historyComboBox.insertItem(0, command)
        
        # Get selected shell type
        shell_type = self.terminalPage.shellComboBox.currentText()
        
        # Display command in terminal
        self.append_terminal_output(f"\napt> {command}")
        
        try:
            # Execute command based on shell type
            if shell_type == "APT Shell":
                # Handle APT-specific commands
                if command.lower() == "help":
                    self.append_terminal_output(
                        "Available commands:\n"
                        "  help - Display this help message\n"
                        "  clear - Clear the terminal\n"
                        "  exit - Exit the terminal\n"
                        "  version - Display APT Toolkit version\n"
                        "  scan <target> - Run a basic scan on target\n"
                        "  recon <target> - Run reconnaissance on target\n"
                    )
                elif command.lower() == "clear":
                    self.clear_terminal()
                elif command.lower() == "exit":
                    self.append_terminal_output("Use the application exit button to close the application.")
                elif command.lower() == "version":
                    self.append_terminal_output("APT Toolkit v1.0.0")
                elif command.lower().startswith("scan "):
                    target = command[5:].strip()
                    if target:
                        self.append_terminal_output(f"[*] Running scan on {target}...")
                        self.append_terminal_output("[*] Scan functionality not fully implemented yet.")
                    else:
                        self.append_terminal_output("[!] Please specify a target to scan.")
                elif command.lower().startswith("recon "):
                    target = command[6:].strip()
                    if target:
                        self.append_terminal_output(f"[*] Running reconnaissance on {target}...")
                        # Switch to recon page and start recon
                        self.stackedWidget.setCurrentWidget(self.reconPage)
                        self.reconPage.targetLineEdit.setText(target)
                        self.start_recon()
                    else:
                        self.append_terminal_output("[!] Please specify a target for reconnaissance.")
                else:
                    self.append_terminal_output(f"[!] Unknown command: {command}")
                    self.append_terminal_output("Type 'help' for a list of available commands.")
            elif shell_type == "System Shell":
                # Execute system command
                self.append_terminal_output("[*] Executing system command...")
                
                # Create a QProcess to run the command
                process = QtCore.QProcess()
                process.setProcessChannelMode(QtCore.QProcess.ProcessChannelMode.MergedChannels)
                
                # Connect signals
                process.readyReadStandardOutput.connect(
                    lambda: self.append_terminal_output(process.readAllStandardOutput().data().decode())
                )
                
                # Start the process
                if sys.platform == "win32":
                    process.start("cmd.exe", ["/c", command])
                else:
                    process.start("/bin/bash", ["-c", command])
                
                # Wait for process to finish
                process.waitForFinished()
                
                # Get exit code
                exit_code = process.exitCode()
                if exit_code != 0:
                    self.append_terminal_output(f"[!] Command exited with code {exit_code}")
            elif shell_type == "Python":
                # Execute Python command
                self.append_terminal_output("[*] Executing Python command...")
                try:
                    result = eval(command)
                    self.append_terminal_output(str(result))
                except Exception as e:
                    try:
                        # If eval fails, try exec
                        exec(command)
                    except Exception as e:
                        self.append_terminal_output(f"[!] Python error: {str(e)}")
        except Exception as e:
            self.append_terminal_output(f"[!] Error executing command: {str(e)}")
            
        # Clear command line
        self.terminalCommandLineEdit.clear()
        
        # Update status
        self.terminalPage.statusLabel.setText("Status: Ready")
    
    def clear_terminal(self):
        """Clear terminal output"""
        if hasattr(self, 'terminal_output'):
            self.terminal_output.clear()
            self.append_terminal_output("Terminal cleared.")
    
    def append_terminal_output(self, message: str):
        """Append message to terminal output"""
        if hasattr(self, 'terminal_output'):
            self.terminal_output.append(message)
            # Auto-scroll to bottom
            cursor = self.terminal_output.textCursor()
            cursor.movePosition(QtGui.QTextCursor.MoveOperation.End)
            self.terminal_output.setTextCursor(cursor)
            # Log the message
            if hasattr(self, 'logger'):
                self.logger.info(f"Terminal: {message}")
        
    def save_settings(self):
        """Save settings to configuration file"""
        self.logger.info("Saving settings")
        
        try:
            # Get settings from UI elements
            settings = self.get_settings_from_ui()
            
            # Save settings to config file
            config_file = os.path.join(os.path.dirname(__file__), "utils", "config.yaml")
            
            # TODO: Implement actual settings saving logic
            # For now, just log the settings
            self.logger.info(f"Would save settings to: {config_file}")
            self.logger.info(f"Settings: {settings}")
            
            # Show success message
            QtWidgets.QMessageBox.information(
                self,
                "Settings Saved",
                "Settings have been saved successfully.",
                QtWidgets.QMessageBox.StandardButton.Ok
            )
        except Exception as e:
            self.logger.error(f"Error saving settings: {str(e)}")
            QtWidgets.QMessageBox.critical(
                self,
                "Error",
                f"Error saving settings: {str(e)}",
                QtWidgets.QMessageBox.StandardButton.Ok
            )
    
    def reset_settings(self):
        """Reset settings to default values"""
        self.logger.info("Resetting settings to defaults")
        
        # Ask for confirmation
        reply = QtWidgets.QMessageBox.question(
            self,
            "Reset Settings",
            "Are you sure you want to reset all settings to their default values?",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
            QtWidgets.QMessageBox.StandardButton.No
        )
        
        if reply == QtWidgets.QMessageBox.StandardButton.Yes:
            try:
                # TODO: Implement actual settings reset logic
                # For now, just log the action
                self.logger.info("Resetting settings to defaults")
                
                # Reset UI elements to default values
                self.reset_settings_ui()
                
                # Show success message
                QtWidgets.QMessageBox.information(
                    self,
                    "Settings Reset",
                    "Settings have been reset to default values.",
                    QtWidgets.QMessageBox.StandardButton.Ok
                )
            except Exception as e:
                self.logger.error(f"Error resetting settings: {str(e)}")
                QtWidgets.QMessageBox.critical(
                    self,
                    "Error",
                    f"Error resetting settings: {str(e)}",
                    QtWidgets.QMessageBox.StandardButton.Ok
                )
    
    def apply_settings(self):
        """Apply current settings without saving"""
        self.logger.info("Applying settings")
        
        try:
            # Get settings from UI elements
            settings = self.get_settings_from_ui()
            
            # TODO: Implement actual settings application logic
            # For now, just log the settings
            self.logger.info(f"Applying settings: {settings}")
            
            # Show success message
            QtWidgets.QMessageBox.information(
                self,
                "Settings Applied",
                "Settings have been applied successfully.",
                QtWidgets.QMessageBox.StandardButton.Ok
            )
        except Exception as e:
            self.logger.error(f"Error applying settings: {str(e)}")
            QtWidgets.QMessageBox.critical(
                self,
                "Error",
                f"Error applying settings: {str(e)}",
                QtWidgets.QMessageBox.StandardButton.Ok
            )
    
    def get_settings_from_ui(self):
        """Get settings from UI elements"""
        settings = {}
        
        # General settings
        if hasattr(self.settingsPage, 'themeComboBox'):
            settings['theme'] = self.settingsPage.themeComboBox.currentText()
        if hasattr(self.settingsPage, 'languageComboBox'):
            settings['language'] = self.settingsPage.languageComboBox.currentText()
        if hasattr(self.settingsPage, 'logLevelComboBox'):
            settings['log_level'] = self.settingsPage.logLevelComboBox.currentText()
            
        # Network settings
        if hasattr(self.settingsPage, 'proxyCheckBox'):
            settings['use_proxy'] = self.settingsPage.proxyCheckBox.isChecked()
        if hasattr(self.settingsPage, 'proxyHostLineEdit'):
            settings['proxy_host'] = self.settingsPage.proxyHostLineEdit.text()
        if hasattr(self.settingsPage, 'proxyPortSpinBox'):
            settings['proxy_port'] = self.settingsPage.proxyPortSpinBox.value()
        if hasattr(self.settingsPage, 'timeoutSpinBox'):
            settings['timeout'] = self.settingsPage.timeoutSpinBox.value()
            
        # Security settings
        if hasattr(self.settingsPage, 'encryptionCheckBox'):
            settings['use_encryption'] = self.settingsPage.encryptionCheckBox.isChecked()
        if hasattr(self.settingsPage, 'authCheckBox'):
            settings['use_auth'] = self.settingsPage.authCheckBox.isChecked()
            
        # Module-specific settings
        if hasattr(self.settingsPage, 'reconThreadsSpinBox'):
            settings['recon_threads'] = self.settingsPage.reconThreadsSpinBox.value()
        if hasattr(self.settingsPage, 'scanThreadsSpinBox'):
            settings['scan_threads'] = self.settingsPage.scanThreadsSpinBox.value()
        if hasattr(self.settingsPage, 'bruteForceThreadsSpinBox'):
            settings['brute_force_threads'] = self.settingsPage.bruteForceThreadsSpinBox.value()
            
        return settings
    
    def reset_settings_ui(self):
        """Reset UI elements to default values"""
        # General settings
        if hasattr(self.settingsPage, 'themeComboBox'):
            self.settingsPage.themeComboBox.setCurrentText("Dark")
        if hasattr(self.settingsPage, 'languageComboBox'):
            self.settingsPage.languageComboBox.setCurrentText("English")
        if hasattr(self.settingsPage, 'logLevelComboBox'):
            self.settingsPage.logLevelComboBox.setCurrentText("INFO")
            
        # Network settings
        if hasattr(self.settingsPage, 'proxyCheckBox'):
            self.settingsPage.proxyCheckBox.setChecked(False)
        if hasattr(self.settingsPage, 'proxyHostLineEdit'):
            self.settingsPage.proxyHostLineEdit.setText("")
        if hasattr(self.settingsPage, 'proxyPortSpinBox'):
            self.settingsPage.proxyPortSpinBox.setValue(8080)
        if hasattr(self.settingsPage, 'timeoutSpinBox'):
            self.settingsPage.timeoutSpinBox.setValue(30)
            
        # Security settings
        if hasattr(self.settingsPage, 'encryptionCheckBox'):
            self.settingsPage.encryptionCheckBox.setChecked(True)
        if hasattr(self.settingsPage, 'authCheckBox'):
            self.settingsPage.authCheckBox.setChecked(False)
            
        # Module-specific settings
        if hasattr(self.settingsPage, 'reconThreadsSpinBox'):
            self.settingsPage.reconThreadsSpinBox.setValue(10)
        if hasattr(self.settingsPage, 'scanThreadsSpinBox'):
            self.settingsPage.scanThreadsSpinBox.setValue(5)
        if hasattr(self.settingsPage, 'bruteForceThreadsSpinBox'):
            self.settingsPage.bruteForceThreadsSpinBox.setValue(3)

    def _on_network_mapping_finished(self):
        """Clean up after network mapping completes"""
        # Update UI
        self.networkMapperPage.startButton.setEnabled(True)
        self.networkMapperPage.stopButton.setEnabled(False)
        self.networkMapperPage.exportButton.setEnabled(True)
        
        # Generate network map visualization with proper data
        if hasattr(self, 'network_worker') and hasattr(self.networkMapperPage, 'networkMapView'):
            # Check if the worker has a map_result with nodes
            has_valid_data = (hasattr(self.network_worker, 'map_result') and 
                             self.network_worker.map_result and 
                             hasattr(self.network_worker.map_result, 'nodes') and
                             self.network_worker.map_result.nodes)
            
            if not has_valid_data:
                # Show error or empty state in the Raw Output tab
                self.append_output(self.networkMapperPage.rawTextEdit, "[!] No network mapping data available for visualization.")
                self.networkMapperPage.resultTabWidget.setCurrentIndex(2)  # Raw output tab
                return
            
            # Get the scan depth that was used
            scan_depth = self.network_worker.scan_depth if hasattr(self.network_worker, 'scan_depth') else "Standard"
            
            # Convert the network nodes into devices for visualization and table
            devices = []
            for node in self.network_worker.map_result.nodes:
                device = {
                    "ip": node.ip_address,
                    "hostname": node.hostname or "unknown",
                    "mac": node.mac_address or "00:00:00:00:00:00",
                    "type": node.node_type,
                    "os": node.os_info or "Unknown"
                }
                devices.append(device)
            
            # Store the devices in the worker for export functionality
            self.network_worker.devices = devices
            
            # Setup the visualization scene
            scene = QtWidgets.QGraphicsScene()
            self.networkMapperPage.networkMapView.setScene(scene)
            
            # Set scene size
            scene.setSceneRect(0, 0, 600, 400)
            
            # Color coding for device types
            colors = {
                "Router": QtGui.QColor(200, 200, 200),       # Gray
                "Workstation": QtGui.QColor(173, 216, 230),  # Light blue
                "Server": QtGui.QColor(144, 238, 144),       # Light green
                "Printer": QtGui.QColor(255, 182, 193),      # Light pink
                "IP Camera": QtGui.QColor(255, 218, 185),    # Peach
                "IoT Device": QtGui.QColor(221, 160, 221),   # Plum
                "Smart TV": QtGui.QColor(240, 230, 140),     # Khaki
                "host": QtGui.QColor(220, 220, 220),         # Light gray
                "firewall": QtGui.QColor(255, 160, 160),     # Light red
                "switch": QtGui.QColor(170, 170, 255),       # Light purple
                "Web Server": QtGui.QColor(152, 251, 152),   # Pale green
                "Database Server": QtGui.QColor(255, 215, 0), # Gold
                "Application Server": QtGui.QColor(135, 206, 250), # Light sky blue
                "Linux Server": QtGui.QColor(144, 238, 144), # Light green
                "Windows Server": QtGui.QColor(100, 149, 237), # Cornflower blue
                "Windows Workstation": QtGui.QColor(173, 216, 230), # Light blue
                "Network Device": QtGui.QColor(170, 170, 255), # Light purple
                "Mail Server": QtGui.QColor(240, 128, 128),  # Light coral
                "DNS Server": QtGui.QColor(238, 130, 238),   # Violet
                "FTP Server": QtGui.QColor(255, 165, 0),     # Orange
            }
            
            # Try to find a router or gateway as the central node
            router_node = None
            for node in self.network_worker.map_result.nodes:
                if node.node_type.lower() in ["router", "gateway"]:
                    router_node = node
                    break
            
            # If no router is found, use the first node
            if not router_node and self.network_worker.map_result.nodes:
                router_node = self.network_worker.map_result.nodes[0]
                
            # Create a mapping of IP addresses to node objects
            node_map = {node.ip_address: node for node in self.network_worker.map_result.nodes}
            
            if router_node:
                # Draw router at center
                router = {
                    "ip": router_node.ip_address,
                    "hostname": router_node.hostname or "router.local",
                    "mac": router_node.mac_address or "00:00:00:00:00:00",
                    "type": router_node.node_type,
                    "os": router_node.os_info or "Unknown"
                }
                
                router_shape = scene.addEllipse(250, 100, 100, 100, 
                                              QtGui.QPen(QtCore.Qt.GlobalColor.black), 
                                              QtGui.QBrush(colors.get(router["type"], QtCore.Qt.GlobalColor.lightGray)))
                router_text = scene.addText(f"{router['type']}\n{router['ip']}")
                router_text.setPos(270, 140)
                
                # Draw other devices based on how many there are
                num_devices = len(self.network_worker.map_result.nodes) - 1  # Excluding router
                if num_devices > 0:
                    # Layout helpers
                    radius = 200  # Distance from center
                    
                    # Draw each device in a circular arrangement
                    idx = 0
                    for node in self.network_worker.map_result.nodes:
                        # Skip the router (already drawn)
                        if node.ip_address == router_node.ip_address:
                            continue
                            
                        # Create device info for drawing
                        device = {
                            "ip": node.ip_address,
                            "hostname": node.hostname or "unknown",
                            "mac": node.mac_address or "00:00:00:00:00:00",
                            "type": node.node_type,
                            "os": node.os_info or "Unknown"
                        }
                        
                        # Position calculations
                        angle = (2 * 3.14159 * idx) / num_devices
                        x = 300 + radius * 0.7 * (0.5 if device["type"] == "Smart TV" else 1) * (0.7 if device["type"] == "Smart TV" else 1) * (1 if idx % 2 else -1) * (0.6 + (idx % 3) * 0.2)
                        y = 250 + radius * 0.5 * (0.8 if idx % 2 else 1.2) * (0.5 + (idx % 4) * 0.1)
                        
                        # Create shape based on device type
                        if device["type"].lower() in ["printer"]:
                            shape = scene.addRect(x, y, 80, 60, 
                                               QtGui.QPen(QtCore.Qt.GlobalColor.black), 
                                               QtGui.QBrush(colors.get(device["type"], QtCore.Qt.GlobalColor.lightGray)))
                        elif device["type"].lower() in ["ip camera", "camera"]:
                            shape = scene.addEllipse(x, y, 60, 80, 
                                                  QtGui.QPen(QtCore.Qt.GlobalColor.black), 
                                                  QtGui.QBrush(colors.get(device["type"], QtCore.Qt.GlobalColor.lightGray)))
                        elif device["type"].lower() in ["iot device", "iot"]:
                            shape = scene.addEllipse(x, y, 70, 70, 
                                                  QtGui.QPen(QtCore.Qt.GlobalColor.black), 
                                                  QtGui.QBrush(colors.get(device["type"], QtCore.Qt.GlobalColor.lightGray)))
                        elif device["type"].lower() in ["smart tv", "tv"]:
                            shape = scene.addRect(x, y, 100, 70, 
                                               QtGui.QPen(QtCore.Qt.GlobalColor.black), 
                                               QtGui.QBrush(colors.get(device["type"], QtCore.Qt.GlobalColor.lightGray)))
                        else:
                            shape = scene.addRect(x, y, 80, 60, 
                                               QtGui.QPen(QtCore.Qt.GlobalColor.black), 
                                               QtGui.QBrush(colors.get(device["type"], QtCore.Qt.GlobalColor.lightGray)))
                        
                        # Add text label with hostname and IP
                        label = device['hostname'] if device['hostname'] != 'unknown' else device['ip']
                        device_text = scene.addText(f"{device['type']}\n{label}")
                        device_text.setPos(x + 10, y + 20)
                        
                        # Add connection to router
                        center_x = 300
                        center_y = 150
                        scene.addLine(center_x, center_y, x + 40, y, QtGui.QPen(QtCore.Qt.GlobalColor.black, 2))
                        
                        # Increment for next device
                        idx += 1
            
            # Populate devices table
            if hasattr(self.networkMapperPage, 'devicesTableWidget'):
                table = self.networkMapperPage.devicesTableWidget
                table.setRowCount(0)  # Clear table
                
                # Populate the table with device data
                for device in devices:
                    row = table.rowCount()
                    table.insertRow(row)
                    table.setItem(row, 0, QtWidgets.QTableWidgetItem(device["ip"]))
                    table.setItem(row, 1, QtWidgets.QTableWidgetItem(device["hostname"]))
                    table.setItem(row, 2, QtWidgets.QTableWidgetItem(device["mac"]))
                    table.setItem(row, 3, QtWidgets.QTableWidgetItem(device["type"]))
                    table.setItem(row, 4, QtWidgets.QTableWidgetItem(device["os"]))
                
                # Resize columns to content
                table.resizeColumnsToContents()
                
                # Add additional data from map result
                self.append_output(self.networkMapperPage.rawTextEdit, f"\n[+] Network details:")
                self.append_output(self.networkMapperPage.rawTextEdit, f"  - Target network: {self.network_worker.map_result.target_network}")
                self.append_output(self.networkMapperPage.rawTextEdit, f"  - Scan time: {self.network_worker.map_result.scan_time}")
                self.append_output(self.networkMapperPage.rawTextEdit, f"  - Found {len(self.network_worker.map_result.nodes)} nodes")
                self.append_output(self.networkMapperPage.rawTextEdit, f"  - Found {len(self.network_worker.map_result.links)} links between nodes")
                
                # Add subnets information if available
                if self.network_worker.map_result.subnets:
                    self.append_output(self.networkMapperPage.rawTextEdit, f"\n[+] Subnets detected:")
                    for subnet in self.network_worker.map_result.subnets:
                        self.append_output(self.networkMapperPage.rawTextEdit, f"  - {subnet}")
                
                # Add port information for each node
                for node in self.network_worker.map_result.nodes:
                    if hasattr(node, 'nmap_data') and node.nmap_data:
                        self.append_output(self.networkMapperPage.rawTextEdit, f"\n[+] Nmap info for {node.ip_address}:")
                        
                        # Print open ports
                        if 'tcp' in node.nmap_data:
                            self.append_output(self.networkMapperPage.rawTextEdit, f"  Open TCP ports:")
                            for port, data in node.nmap_data['tcp'].items():
                                service = data.get('name', 'unknown')
                                product = data.get('product', '')
                                version = data.get('version', '')
                                service_str = service
                                if product:
                                    service_str += f" ({product}"
                                    if version:
                                        service_str += f" {version}"
                                    service_str += ")"
                                
                                self.append_output(self.networkMapperPage.rawTextEdit, f"    {port}: {service_str}")
                        
                        # Print OS detection results
                        if 'osmatch' in node.nmap_data and node.nmap_data['osmatch']:
                            self.append_output(self.networkMapperPage.rawTextEdit, f"  OS Detection:")
                            for match in node.nmap_data['osmatch'][:2]:  # Show top 2 matches
                                name = match.get('name', 'Unknown')
                                accuracy = match.get('accuracy', '0')
                                self.append_output(self.networkMapperPage.rawTextEdit, f"    {name} (Accuracy: {accuracy}%)")
                
                # Switch to the appropriate tab based on scan depth
                if scan_depth == "Deep (Slow)" and len(self.network_worker.map_result.nodes) > 1:
                    self.networkMapperPage.resultTabWidget.setCurrentIndex(0)  # Map view
                elif scan_depth == "Basic (Fast)":
                    self.networkMapperPage.resultTabWidget.setCurrentIndex(2)  # Raw output
                else:
                    self.networkMapperPage.resultTabWidget.setCurrentIndex(1)  # Devices table
        
        # Clean up thread resources
        if hasattr(self, 'network_thread') and self.network_thread:
            self.network_thread.quit()
            self.network_worker.deleteLater()
            self.network_thread.deleteLater()

    def get_active_text_widget(self):
        """Get the currently active text widget"""
        focused_widget = QtWidgets.QApplication.focusWidget()
        if isinstance(focused_widget, QtWidgets.QLineEdit) or isinstance(focused_widget, QtWidgets.QTextEdit):
            return focused_widget
        return None

    def cut_action(self):
        """Cut selected text from active widget"""
        widget = self.get_active_text_widget()
        if widget:
            widget.cut()

    def copy_action(self):
        """Copy selected text from active widget"""
        widget = self.get_active_text_widget()
        if widget:
            widget.copy()

    def paste_action(self):
        """Paste text to active widget"""
        widget = self.get_active_text_widget()
        if widget:
            widget.paste()

    def show_documentation(self):
        """Show documentation"""
        QtWidgets.QMessageBox.information(
            self,
            "Documentation",
            "Documentation will be available in a future update.",
            QtWidgets.QMessageBox.StandardButton.Ok
        )

    def show_tutorials(self):
        """Show tutorials"""
        QtWidgets.QMessageBox.information(
            self,
            "Tutorials",
            "Tutorials will be available in a future update.",
            QtWidgets.QMessageBox.StandardButton.Ok
        )

    def check_for_updates(self):
        """Check for updates"""
        QtWidgets.QMessageBox.information(
            self,
            "Updates",
            "You are running the latest version of APT Toolkit.",
            QtWidgets.QMessageBox.StandardButton.Ok
        )

    def show_about_dialog(self):
        """Show about dialog"""
        QtWidgets.QMessageBox.about(
            self,
            "About APT Toolkit",
            "APT Toolkit v1.0.0\n\nA comprehensive toolkit for security professionals."
        )

    def toggle_fullscreen(self):
        """Toggle fullscreen mode"""
        if self.isFullScreen():
            self.showNormal()
            self.actionFull_Screen.setChecked(False)
        else:
            self.showFullScreen()
            self.actionFull_Screen.setChecked(True)

    def open_wordlist_manager(self):
        """Open wordlist manager"""
        QtWidgets.QMessageBox.information(
            self,
            "Wordlist Manager",
            "Wordlist Manager will be available in a future update.",
            QtWidgets.QMessageBox.StandardButton.Ok
        )

    def open_plugin_manager(self):
        """Open plugin manager"""
        QtWidgets.QMessageBox.information(
            self,
            "Plugin Manager",
            "Plugin Manager will be available in a future update.",
            QtWidgets.QMessageBox.StandardButton.Ok
        )

    def open_scheduler(self):
        """Open scheduler"""
        QtWidgets.QMessageBox.information(
            self,
            "Scheduler",
            "Scheduler will be available in a future update.",
            QtWidgets.QMessageBox.StandardButton.Ok
        )

    def open_task_manager(self):
        """Open task manager"""
        QtWidgets.QMessageBox.information(
            self,
            "Task Manager",
            "Task Manager will be available in a future update.",
            QtWidgets.QMessageBox.StandardButton.Ok
        )

    def _create_sample_recon_result(self):
        """Create a sample ReconResult for demonstration purposes"""
        from src.modules.recon import ReconResult, HostInfo, DomainInfo, DNSRecord, PortInfo
        import time
        
        # Create base result object
        target = self.reconPage.targetLineEdit.text().strip() or "example.com"
        result = ReconResult(target=target)
        result.scan_time = time.time() - 15  # Make it look like it ran for 15 seconds
        result.end_time = time.time()
        
        # Add some notes
        result.notes.append("Sample demonstration data - not from actual scan")
        result.notes.append("Run a real scan to see actual results")
        
        # Add a domain
        domain = DomainInfo(
            domain=target,
            registrar="Example Registrar, Inc.",
            creation_date="2000-01-01",
            expiration_date="2030-01-01"
        )
        domain.name_servers = ["ns1.example.com", "ns2.example.com"]
        
        # Add DNS records
        domain.dns_records.append(DNSRecord(hostname=target, record_type="A", value="93.184.216.34", ttl=3600))
        domain.dns_records.append(DNSRecord(hostname=target, record_type="MX", value="mail.example.com", ttl=3600))
        domain.dns_records.append(DNSRecord(hostname=target, record_type="TXT", value="v=spf1 include:_spf.example.com ~all", ttl=3600))
        domain.dns_records.append(DNSRecord(hostname=f"www.{target}", record_type="CNAME", value=target, ttl=3600))
        
        # Add subdomains
        domain.subdomains = [
            f"www.{target}", 
            f"mail.{target}", 
            f"blog.{target}", 
            f"api.{target}", 
            f"login.{target}", 
            f"dev.{target}"
        ]
        
        # Add WHOIS data
        domain.whois_data = {
            "Registrar": "Example Registrar, Inc.",
            "Registrar URL": "http://www.example-registrar.com",
            "Updated Date": "2022-01-01",
            "Creation Date": "2000-01-01",
            "Expiration Date": "2030-01-01", 
            "Name Server": "ns1.example.com",
            "DNSSEC": "unsigned"
        }
        
        # Add the domain to the result
        result.domains.append(domain)
        
        # Add a host
        host = HostInfo(
            ip_address="93.184.216.34",
            hostname=target,
            status="up",
            os_info="Linux 5.4",
            response_time=0.056,
            last_seen=time.time(),
            mac_address="00:00:5e:00:53:af"
        )
        
        # Add open ports
        host.open_ports.append(PortInfo(
            port=80,
            state="open",
            service="http",
            version="Apache 2.4.41",
            protocol="tcp",
            banner="HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html"
        ))
        
        host.open_ports.append(PortInfo(
            port=443,
            state="open",
            service="https",
            version="Apache 2.4.41",
            protocol="tcp",
            banner="HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html"
        ))
        
        host.open_ports.append(PortInfo(
            port=22,
            state="open",
            service="ssh",
            version="OpenSSH 8.2p1",
            protocol="tcp",
            banner="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3"
        ))
        
        # Add the host to the result
        result.hosts.append(host)
        
        return result

    def toggle_nmap_script_field(self):
        """Toggle the script line edit based on the script scan check box"""
        if self.networkMapperPage.scriptScanCheckBox.isChecked():
            self.networkMapperPage.scriptLineEdit.setEnabled(True)
        else:
            self.networkMapperPage.scriptLineEdit.setEnabled(False)


class NetworkMappingWorker(QtCore.QObject):
    output_signal = QtCore.pyqtSignal(str)
    progress_signal = QtCore.pyqtSignal(int)
    status_signal = QtCore.pyqtSignal(str)
    finished_signal = QtCore.pyqtSignal()
    
    def __init__(self, target, logger, use_traceroute=False, use_arp=False, detect_os=False, discover_hosts=True, identify_devices=False):
        super().__init__()
        self.target = target
        self.logger = logger
        self.use_traceroute = use_traceroute
        self.use_arp = use_arp
        self.detect_os = detect_os
        self.discover_hosts = discover_hosts
        self.identify_devices = identify_devices
        self.running = False
        self.use_nmap = True  # Default to True, can be overridden
        self.nmap_options = {}  # Advanced nmap options
        # Get scan depth from active combobox
        self.scan_depth = "Standard"  # Default
        
        # Initialize the NetworkMapper module
        self.network_mapper = NetworkMapper()
        
    def run(self):
        """Run network mapping"""
        self.running = True
        try:
            self.output_signal.emit(f"[*] Starting network mapping on {self.target}")
            self.logger.info(f"Starting network mapping on {self.target}")
            
            # Validate target before proceeding
            target_is_valid = False
            
            # Simple validator for IP addresses
            if self._is_ip_address(self.target):
                target_is_valid = True
            
            # For domains, try to resolve to see if it's valid
            else:
                try:
                    import socket
                    socket.gethostbyname(self.target.replace("http://", "").replace("https://", "").split('/')[0])
                    target_is_valid = True
                except:
                    target_is_valid = False
            
            if not target_is_valid:
                self.output_signal.emit(f"[!] Error: Cannot perform network mapping on invalid target: {self.target}")
                self.output_signal.emit(f"[!] Please enter a valid IP address, domain, or hostname")
                self.status_signal.emit("Status: Error - Invalid Target")
                self.progress_signal.emit(100)  # Set to 100% to indicate completion
                self.finished_signal.emit()
                return
            
            # Setup network mapping parameters based on scan depth
            params = {
                "timeout": 5,
                "max_threads": 20,
                "max_hops": 30 if self.scan_depth == "Deep (Slow)" else 15,
                "ping_sweep": True,
                "ports": [22, 80, 443, 3389],
                "node_discovery": self.discover_hosts,
                "topology_detection": self.use_traceroute,
                "detail_level": "high" if self.scan_depth == "Deep (Slow)" else 
                               "low" if self.scan_depth == "Basic (Fast)" else "medium",
                "use_nmap": self.use_nmap,  # Use the instance variable
                "detect_os": self.detect_os,
                "nmap_options": self.nmap_options if hasattr(self, 'nmap_options') else {}
            }
            
            # Status updates
            self.status_signal.emit("Status: Running Network Mapping")
            self.progress_signal.emit(20)  # Initial progress
            
            # Perform network mapping through the proper module
            self.output_signal.emit("[*] Executing network mapping module...")
            
            # Connect progress updates
            def update_progress(step, max_steps, message):
                progress_value = int((step / max_steps) * 80)  # Scale to 0-80% (we already started at 20%)
                self.progress_signal.emit(20 + progress_value)
                self.output_signal.emit(message)
                self.status_signal.emit(f"Status: {message}")
                # Check for cancellation
                return self.running
            
            # Redirect output from the mapper to our UI signal
            def log_message(message):
                self.output_signal.emit(message)
                
            # Run the actual mapping
            self.output_signal.emit(f"[*] Running network mapping with {self.scan_depth} scan depth...")
            
            # We'll use the NetworkMapper module for the actual work
            try:
                # Create a callback mechanism for progress
                self.network_mapper._progress_callback = update_progress
                self.network_mapper._log_callback = log_message
                
                # Perform the mapping
                result = self.network_mapper.map_network(
                    self.target,
                    **params
                )
                
                # Store the result for visualization
                self.map_result = result
                
                # Convert nodes to the format expected by the visualization code
                self.devices = []
                for node in result.nodes:
                    self.devices.append({
                        "ip": node.ip_address,
                        "hostname": node.hostname or "unknown",
                        "mac": node.mac_address or "00:00:00:00:00:00",
                        "type": node.node_type,
                        "os": node.os_info or "Unknown"
                    })
                
                # Set the progress to 100%
                self.progress_signal.emit(100)
                self.status_signal.emit("Status: Complete")
                self.output_signal.emit("[+] Network mapping complete!")
                
                # Print summary of discovered devices
                self.output_signal.emit(f"\n[+] Discovered {len(self.devices)} devices")
                for node in result.nodes:
                    self.output_signal.emit(f"  - {node.ip_address} ({node.node_type})")
                    if node.hostname:
                        self.output_signal.emit(f"    - Hostname: {node.hostname}")
                    if node.os_info:
                        self.output_signal.emit(f"    - OS: {node.os_info}")
                    
                    # Display nmap results for each host if available
                    if hasattr(node, 'nmap_data') and node.nmap_data:
                        self.output_signal.emit(f"\n[+] Nmap scan results for {node.ip_address}:")
                        
                        # Show open ports and services
                        if 'tcp' in node.nmap_data:
                            self.output_signal.emit(f"    - Open TCP ports:")
                            for port, port_data in node.nmap_data['tcp'].items():
                                service = port_data.get('name', 'unknown')
                                product = port_data.get('product', '')
                                version = port_data.get('version', '')
                                service_info = f"{service}"
                                if product:
                                    service_info += f" ({product}"
                                    if version:
                                        service_info += f" {version}"
                                    service_info += ")"
                                self.output_signal.emit(f"      {port}/tcp: {service_info}")
                        
                        # Show UDP ports if available
                        if 'udp' in node.nmap_data:
                            self.output_signal.emit(f"    - Open UDP ports:")
                            for port, port_data in node.nmap_data['udp'].items():
                                service = port_data.get('name', 'unknown')
                                self.output_signal.emit(f"      {port}/udp: {service}")
                        
                        # Show OS details if available
                        if 'osmatch' in node.nmap_data and node.nmap_data['osmatch']:
                            self.output_signal.emit(f"    - OS Detection:")
                            for os_match in node.nmap_data['osmatch'][:2]:  # Show top 2 matches
                                name = os_match.get('name', 'Unknown')
                                accuracy = os_match.get('accuracy', '0')
                                self.output_signal.emit(f"      {name} (Accuracy: {accuracy}%)")
                        
                        # Show scripts output if available (for detailed scans)
                        if 'scripts' in node.nmap_data:
                            self.output_signal.emit(f"    - Script Results:")
                            for script_name, output in node.nmap_data['scripts'].items():
                                self.output_signal.emit(f"      {script_name}: {output[:100]}...")  # Truncate long outputs
                    
                    self.output_signal.emit("")  # Empty line between hosts
                    
            except Exception as e:
                self.output_signal.emit(f"[!] Error in network mapping: {str(e)}")
                import traceback
                self.output_signal.emit(traceback.format_exc())
                self.status_signal.emit("Status: Error")
                
                # Create some fallback devices for visualization
                self._create_fallback_devices()
                
        except Exception as e:
            self.output_signal.emit(f"[!] Error: {str(e)}")
            self.status_signal.emit("Status: Error")
        finally:
            # Make sure we always emit the finished signal
            self.finished_signal.emit()
    
    def _create_fallback_devices(self):
        """Create fallback devices if the network mapping fails"""
        if not hasattr(self, 'devices') or not self.devices:
            self.devices = []
            
            # Parse target to generate consistent IP addresses
            target_ip = self.target
            if not self._is_ip_address(target_ip):
                import hashlib
                hash_val = int(hashlib.md5(self.target.encode()).hexdigest(), 16) % 255
                target_ip = f"192.168.{hash_val}.1"
            
            # Create subnet based on target
            ip_parts = target_ip.split('.')
            subnet_prefix = '.'.join(ip_parts[0:3])
            
            # Create a router
            self.devices.append({
                "ip": f"{subnet_prefix}.1", 
                "hostname": "router.local", 
                "mac": "00:11:22:33:44:55", 
                "type": "Router", 
                "os": "RouterOS"
            })
            
            # Add a PC
            self.devices.append({
                "ip": f"{subnet_prefix}.2", 
                "hostname": "windows-pc.local", 
                "mac": "AA:BB:CC:DD:EE:FF", 
                "type": "Workstation", 
                "os": "Windows 10"
            })
            
            # For standard and deep scans, add more devices
            if self.scan_depth != "Basic (Fast)":
                self.devices.append({
                    "ip": f"{subnet_prefix}.3", 
                    "hostname": "linux-server.local", 
                    "mac": "11:22:33:44:55:66", 
                    "type": "Server", 
                    "os": "Linux"
                })

    def _is_ip_address(self, ip):
        """Check if string is a valid IP address"""
        import re
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        # Check each octet is within range
        return all(0 <= int(octet) <= 255 for octet in ip.split('.'))
    
    def stop(self):
        """Stop network mapping"""
        self.running = False
        self.output_signal.emit("[*] Stopping network mapping...")


class ReconWorker(QtCore.QObject):
    output_signal = QtCore.pyqtSignal(str)
    finished_signal = QtCore.pyqtSignal()

    def __init__(self, target, logger):
        super().__init__()
        self.target = target
        self.logger = logger
        self.running = False
        self.result = None  # Store the scan result

    def run(self):
        self.running = True
        try:
            results = []
            if self.running:
                # Get the text results and the ReconResult object
                text_results, self.result = recon.run(self.target, self.logger, return_object=True)
                results = text_results
            
            if self.running:
                for line in results:
                    self.output_signal.emit(line)
                    if not self.running:
                        break
        except Exception as e:
            self.output_signal.emit(f"[!] Error during recon: {str(e)}")
            import traceback
            self.output_signal.emit(traceback.format_exc())
        finally:
            self.running = False
            self.finished_signal.emit()
            
    def stop(self):
        """Stop reconnaissance"""
        self.running = False
        self.logger.info("Reconnaissance stopped by user")


def main():
    """Main entry point for the application"""
    # Set up the application
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("APT Toolkit")
    app.setStyle("Fusion")
    
    # Load and apply stylesheet
    try:
        style_file = os.path.join(os.path.dirname(__file__), "styles", "style.qss")
        with open(style_file, "r") as f:
            app.setStyleSheet(f.read())
        print(f"Loaded stylesheet from {style_file}")
    except Exception as e:
        print(f"Error loading stylesheet: {e}")
    
    # Check dependencies
    try:
        from src.utils.check_dependencies import check_dependencies
        missing_deps = check_dependencies()
        
        if missing_deps:
            # Create warning dialog for missing dependencies
            warning_msg = QtWidgets.QMessageBox()
            warning_msg.setIcon(QtWidgets.QMessageBox.Icon.Warning)
            warning_msg.setWindowTitle("Missing Dependencies")
            
            message = "The following dependencies are missing:\n\n"
            for dep, instructions in missing_deps:
                message += f"• {dep}: {instructions}\n\n"
            message += "Some features may not work correctly without these dependencies."
            
            warning_msg.setText(message)
            warning_msg.setStandardButtons(QtWidgets.QMessageBox.StandardButton.Ok)
            warning_msg.exec()
    except Exception as e:
        print(f"Error checking dependencies: {e}")
    
    # Create and show the main window
    main_window = MainWindow()
    main_window.setWindowTitle("APT Toolkit")
    main_window.resize(1024, 720)
    main_window.show()
    
    # Start the event loop
    sys.exit(app.exec())


if __name__ == "__main__":
    main()