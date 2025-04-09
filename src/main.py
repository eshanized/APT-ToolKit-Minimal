import sys
import os

# Add the parent directory of 'src' to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from PyQt6 import QtWidgets, uic, QtGui, QtCore, QtPrintSupport
from modules import recon
from utils.logger import get_logger


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()

        # Load main window UI
        uic.loadUi("src/ui/main_window.ui", self)

        # Load stacked pages
        self.reconPage = uic.loadUi("src/ui/recon.ui")
        self.networkMapperPage = uic.loadUi("src/ui/network_mapper.ui")
        self.serviceEnumPage = QtWidgets.QWidget()    # Placeholder until UI file is created
        self.scanResultPage = uic.loadUi("src/ui/scan_result.ui")
        self.webScannerPage = QtWidgets.QWidget()     # Placeholder until UI file is created
        self.vulnScannerPage = uic.loadUi("src/ui/vuln_scanner.ui")
        self.bruteForceePage = uic.loadUi("src/ui/brute_force.ui")
        self.authBypassPage = QtWidgets.QWidget()     # Placeholder until UI file is created
        self.payloadGenPage = uic.loadUi("src/ui/payload_gen.ui")
        self.exploitExecPage = uic.loadUi("src/ui/exploit_exec.ui")
        self.reportPage = uic.loadUi("src/ui/report.ui")
        self.settingsPage = uic.loadUi("src/ui/settings.ui")
        self.terminalPage = uic.loadUi("src/ui/terminal.ui")
        self.logsPage = uic.loadUi("src/ui/logs.ui")

        # Add to stacked widget
        self.stackedWidget.addWidget(self.reconPage)
        self.stackedWidget.addWidget(self.networkMapperPage)
        self.stackedWidget.addWidget(self.serviceEnumPage)
        self.stackedWidget.addWidget(self.scanResultPage)
        self.stackedWidget.addWidget(self.webScannerPage)
        self.stackedWidget.addWidget(self.vulnScannerPage)
        self.stackedWidget.addWidget(self.bruteForceePage)
        self.stackedWidget.addWidget(self.authBypassPage)
        self.stackedWidget.addWidget(self.payloadGenPage)
        self.stackedWidget.addWidget(self.exploitExecPage)
        self.stackedWidget.addWidget(self.reportPage)
        self.stackedWidget.addWidget(self.settingsPage)
        self.stackedWidget.addWidget(self.terminalPage)
        self.stackedWidget.addWidget(self.logsPage)

        # Connect dashboard module buttons to stacked pages
        self.reconButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.reconPage))
        self.networkMapperButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.networkMapperPage))
        self.serviceEnumButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.serviceEnumPage))
        self.scanEngineButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.scanResultPage))
        self.webScannerButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.webScannerPage))
        self.vulnScannerButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.vulnScannerPage))
        self.bruteForceButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.bruteForceePage))
        self.authBypassButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.authBypassPage))
        self.payloadGenButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.payloadGenPage))
        self.exploitExecButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.exploitExecPage))
        self.reportGenButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.reportPage))
        self.settingsButton.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.settingsPage))
        
        # Connect menu actions
        self.actionLogs.triggered.connect(lambda: self.logsDockWidget.setVisible(not self.logsDockWidget.isVisible()))
        self.actionTerminal.triggered.connect(lambda: self.terminalDockWidget.setVisible(not self.terminalDockWidget.isVisible()))
        self.actionDashboard.triggered.connect(lambda: self.stackedWidget.setCurrentIndex(0))
        
        # Connect file menu actions
        self.actionNew_Project.triggered.connect(self.new_project)
        self.actionOpen_Project.triggered.connect(self.open_project)
        self.actionExit.triggered.connect(self.quit_application)
        
        # Connect toolbar actions
        self.actionReconnaissance.triggered.connect(lambda: self.stackedWidget.setCurrentWidget(self.reconPage))
        self.actionNetwork_Mapper.triggered.connect(lambda: self.stackedWidget.setCurrentWidget(self.networkMapperPage))
        self.actionService_Enumeration.triggered.connect(lambda: self.stackedWidget.setCurrentWidget(self.serviceEnumPage))
        self.actionScan_Engine.triggered.connect(lambda: self.stackedWidget.setCurrentWidget(self.scanResultPage))
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
        self.logsPage.clearButton.clicked.connect(self.clear_logs)
        self.logsPage.exportButton.clicked.connect(self.export_logs)
        
        # Connect Vulnerability Scanner buttons
        self.vulnScannerPage.startButton.clicked.connect(self.start_vuln_scan)
        self.vulnScannerPage.stopButton.clicked.connect(self.stop_vuln_scan)
        
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
        self.terminalPage.executeButton.clicked.connect(self.execute_command)
        self.terminalPage.commandLineEdit.returnPressed.connect(self.execute_command)
        self.terminalPage.clearButton.clicked.connect(self.clear_terminal)
        self.terminalPage.saveButton.clicked.connect(self.save_terminal_output)
        self.terminalPage.clearHistoryButton.clicked.connect(self.clear_terminal_history)
        
        # Connect Settings buttons (assuming common settings UI elements)
        if hasattr(self.settingsPage, 'saveButton'):
            self.settingsPage.saveButton.clicked.connect(self.save_settings)
        if hasattr(self.settingsPage, 'resetButton'):
            self.settingsPage.resetButton.clicked.connect(self.reset_settings)
        if hasattr(self.settingsPage, 'applyButton'):
            self.settingsPage.applyButton.clicked.connect(self.apply_settings)

        # Logging
        self.logger = get_logger("APTToolkit")
        self.recon_output = self.reconPage.rawTextEdit
        self.log_output = self.logsPage.detailsTextEdit
        self.terminal_output = self.terminalPage.terminalTextEdit

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
        """Start reconnaissance on target"""
        target = self.reconPage.targetLineEdit.text().strip()
        if not target:
            self.append_recon_output("[!] Please enter a valid target.")
            return

        self.append_recon_output(f"[*] Running reconnaissance on: {target}")
        self.spinner.setVisible(True)
        self.spinner.movie().start()
        
        # Update UI state
        self.reconPage.startButton.setEnabled(False)
        self.reconPage.stopButton.setEnabled(True)

        # Run recon in separate thread
        self.recon_thread = QtCore.QThread()
        self.recon_worker = ReconWorker(target, self.logger)
        self.recon_worker.moveToThread(self.recon_thread)

        self.recon_worker.output_signal.connect(self.append_recon_output)
        self.recon_worker.finished_signal.connect(self._on_recon_finished)
        
        self.recon_thread.started.connect(self.recon_worker.run)
        self.recon_thread.start()
        
    def _on_recon_finished(self):
        """Handle recon completion"""
        # Update UI
        self.spinner.setVisible(False)
        self.reconPage.startButton.setEnabled(True)
        self.reconPage.stopButton.setEnabled(False)
        
        # Clean up thread resources
        if hasattr(self, 'recon_thread') and self.recon_thread:
            self.recon_thread.quit()
            self.recon_worker.deleteLater()
            self.recon_thread.deleteLater()
        
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
        target = self.vulnScannerPage.targetLineEdit.text().strip()
        if not target:
            self.append_output(self.vulnScannerPage.statusTextEdit, "[!] Please enter a valid target.")
            return
            
        self.append_output(self.vulnScannerPage.statusTextEdit, f"[*] Starting vulnerability scan on: {target}")
        # Implement actual vulnerability scanning functionality
        
    def stop_vuln_scan(self):
        """Stop vulnerability scanning"""
        self.append_output(self.vulnScannerPage.statusTextEdit, "[*] Stopping vulnerability scan...")
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
            self.append_output(self.networkMapperPage.statusTextEdit, "[!] Please enter a valid target.")
            return
            
        # Get options
        use_traceroute = self.networkMapperPage.tracerouteCheckBox.isChecked()
        use_arp = self.networkMapperPage.arpCheckBox.isChecked()
        detect_os = self.networkMapperPage.osDetectionCheckBox.isChecked()
        discover_hosts = self.networkMapperPage.hostDiscoveryCheckBox.isChecked()
        identify_devices = self.networkMapperPage.deviceIdentificationCheckBox.isChecked()
        
        # Initialize visualization
        # For now, clear existing visualization
        self.networkMapperPage.visualizationWidget.clear()
        self.networkMapperPage.visualizationWidget.setSceneRect(0, 0, 500, 300)
        
        # Clear status text
        self.networkMapperPage.statusTextEdit.clear()
        
        # Update status
        self.append_output(self.networkMapperPage.statusTextEdit, f"[*] Starting network mapping on {target}")
        self.append_output(self.networkMapperPage.statusTextEdit, f"[*] Options:")
        self.append_output(self.networkMapperPage.statusTextEdit, f"    - Traceroute: {'Enabled' if use_traceroute else 'Disabled'}")
        self.append_output(self.networkMapperPage.statusTextEdit, f"    - ARP: {'Enabled' if use_arp else 'Disabled'}")
        self.append_output(self.networkMapperPage.statusTextEdit, f"    - OS Detection: {'Enabled' if detect_os else 'Disabled'}")
        self.append_output(self.networkMapperPage.statusTextEdit, f"    - Host Discovery: {'Enabled' if discover_hosts else 'Disabled'}")
        self.append_output(self.networkMapperPage.statusTextEdit, f"    - Device Identification: {'Enabled' if identify_devices else 'Disabled'}")
        
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
        self.network_worker.moveToThread(self.network_thread)
        
        # Connect signals
        self.network_worker.output_signal.connect(lambda msg: self.append_output(self.networkMapperPage.statusTextEdit, msg))
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
            self.append_output(self.networkMapperPage.statusTextEdit, "[*] Stopping network mapping...")
            self.networkMapperPage.statusLabel.setText("Status: Stopping")
            
            # Give some time for the thread to clean up
            if hasattr(self, 'network_thread') and self.network_thread.isRunning():
                self.network_thread.quit()
                self.network_thread.wait(1000)  # Wait up to 1 second
        else:
            self.append_output(self.networkMapperPage.statusTextEdit, "[!] No network mapping in progress.")
    
    def export_network_map(self):
        """Export network map"""
        # Check if we have results to export
        if not hasattr(self.networkMapperPage, 'networkView') or not self.networkMapperPage.networkView.scene():
            self.append_output(self.networkMapperPage.statusTextEdit, "[!] No network map to export. Run a scan first.")
            return
            
        # Ask for export format and location
        path, format_filter = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Export Network Map",
            "",
            "PNG Image (*.png);;JPEG Image (*.jpg);;SVG Image (*.svg);;PDF Document (*.pdf);;Text Report (*.txt)"
        )
        
        if not path:
            return
            
        try:
            # Determine export format from filter
            if "PNG" in format_filter:
                self.export_network_map_image(path, "PNG")
            elif "JPEG" in format_filter:
                self.export_network_map_image(path, "JPG")
            elif "SVG" in format_filter:
                self.export_network_map_image(path, "SVG")
            elif "PDF" in format_filter:
                self.export_network_map_pdf(path)
            elif "Text" in format_filter:
                self.export_network_map_text(path)
                
            self.append_output(self.networkMapperPage.statusTextEdit, f"[+] Network map exported to: {path}")
        except Exception as e:
            self.append_output(self.networkMapperPage.statusTextEdit, f"[!] Error exporting network map: {str(e)}")
    
    def export_network_map_image(self, path, format_type):
        """Export network map as image"""
        # Get the scene from the network view
        scene = self.networkMapperPage.networkView.scene()
        
        # Create a pixmap to render the scene
        pixmap = QtGui.QPixmap(scene.sceneRect().size().toSize())
        pixmap.fill(QtCore.Qt.GlobalColor.transparent)
        
        # Create a painter to render the scene to the pixmap
        painter = QtGui.QPainter(pixmap)
        scene.render(painter)
        painter.end()
        
        # Save the pixmap to the specified path
        pixmap.save(path, format_type)
    
    def export_network_map_pdf(self, path):
        """Export network map as PDF"""
        # Get the scene from the network view
        scene = self.networkMapperPage.networkView.scene()
        
        # Create a printer
        printer = QtPrintSupport.QPrinter(QtPrintSupport.QPrinter.PrinterMode.HighResolution)
        printer.setOutputFormat(QtPrintSupport.QPrinter.OutputFormat.PdfFormat)
        printer.setOutputFileName(path)
        printer.setPageSize(QtPrintSupport.QPageSize(QtPrintSupport.QPageSize.PageSizeId.A4))
        
        # Create a painter to render the scene to the printer
        painter = QtGui.QPainter(printer)
        scene.render(painter)
        painter.end()
    
    def export_network_map_text(self, path):
        """Export network map as text report"""
        # Get the devices from the table
        device_count = self.networkMapperPage.devicesTable.rowCount()
        
        with open(path, "w") as f:
            f.write("Network Mapping Report\n")
            f.write("=====================\n\n")
            
            # Write scan information
            f.write(f"Target: {self.networkMapperPage.targetLineEdit.text().strip()}\n")
            f.write(f"Scan Date: {QtCore.QDateTime.currentDateTime().toString()}\n")
            f.write(f"Devices Found: {device_count}\n\n")
            
            # Write device information
            f.write("Devices\n")
            f.write("-------\n\n")
            
            for row in range(device_count):
                ip = self.networkMapperPage.devicesTable.item(row, 0).text()
                hostname = self.networkMapperPage.devicesTable.item(row, 1).text()
                mac = self.networkMapperPage.devicesTable.item(row, 2).text()
                device_type = self.networkMapperPage.devicesTable.item(row, 3).text()
                os = self.networkMapperPage.devicesTable.item(row, 4).text()
                
                f.write(f"Device {row+1}:\n")
                f.write(f"  IP Address: {ip}\n")
                f.write(f"  Hostname: {hostname}\n")
                f.write(f"  MAC Address: {mac}\n")
                f.write(f"  Device Type: {device_type}\n")
                f.write(f"  Operating System: {os}\n\n")
            
            # Write raw output
            f.write("Raw Output\n")
            f.write("----------\n\n")
            f.write(self.networkMapperPage.rawOutputTextEdit.toPlainText())
    
    def generate_report(self):
        """Generate report"""
        report_title = self.reportPage.reportTitleLineEdit.text().strip()
        if not report_title:
            report_title = "Security Assessment Report"
            
        self.append_output(self.reportPage.statusLabel, f"[*] Generating report: {report_title}")
        # Implement report generation functionality
        
    def append_recon_output(self, message: str):
        """Append message to recon output and log it"""
        self.recon_output.append(message)
        self.log_output.append(message)

    def append_output(self, text_widget, message: str):
        """Append message to specified text widget and log it"""
        text_widget.append(message)
        self.log_output.append(message)
        
    def clear_logs(self):
        """Clear logs"""
        self.log_output.clear()

    def export_logs(self):
        """Export logs to file"""
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Logs", "", "Text Files (*.txt)")
        if path:
            with open(path, "w") as f:
                f.write(self.log_output.toPlainText())
            self.append_recon_output(f"[+] Logs exported to: {path}")
    
    def new_project(self):
        """Create a new project"""
        # Ask for confirmation if there are unsaved changes
        reply = QtWidgets.QMessageBox.question(
            self, 
            "New Project", 
            "Are you sure you want to create a new project? Any unsaved changes will be lost.",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
            QtWidgets.QMessageBox.StandardButton.No
        )
        
        if reply == QtWidgets.QMessageBox.StandardButton.Yes:
            # Clear current data and set up a new workspace
            self.logger.info("Creating new project")
            self.append_output(self.log_output, "[*] Creating new project")
            
            # Reset UI elements
            self.stackedWidget.setCurrentIndex(0)  # Go to dashboard
            
            # TODO: Implement actual project creation logic
            self.append_output(self.log_output, "[+] New project created")
    
    def open_project(self):
        """Open an existing project"""
        # Ask for confirmation if there are unsaved changes
        reply = QtWidgets.QMessageBox.question(
            self, 
            "Open Project", 
            "Are you sure you want to open a project? Any unsaved changes will be lost.",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
            QtWidgets.QMessageBox.StandardButton.No
        )
        
        if reply == QtWidgets.QMessageBox.StandardButton.Yes:
            # Show file dialog to select project file
            path, _ = QtWidgets.QFileDialog.getOpenFileName(
                self, 
                "Open Project", 
                "", 
                "APT Toolkit Projects (*.apt);;All Files (*)"
            )
            
            if path:
                self.logger.info(f"Opening project: {path}")
                self.append_output(self.log_output, f"[*] Opening project: {path}")
                
                # TODO: Implement actual project loading logic
                self.append_output(self.log_output, f"[+] Project loaded: {path}")
    
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
        command = self.terminalPage.commandLineEdit.text().strip()
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
        self.terminalPage.commandLineEdit.clear()
        
        # Update status
        self.terminalPage.statusLabel.setText("Status: Ready")
    
    def clear_terminal(self):
        """Clear terminal output"""
        self.terminal_output.clear()
        self.append_terminal_output("APT Toolkit Terminal v1.0.0")
        self.append_terminal_output("Type 'help' for a list of available commands.")
        self.append_terminal_output("\napt> ")
    
    def save_terminal_output(self):
        """Save terminal output to file"""
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, 
            "Save Terminal Output", 
            "", 
            "Text Files (*.txt)"
        )
        
        if path:
            with open(path, "w") as f:
                f.write(self.terminal_output.toPlainText())
            self.append_terminal_output(f"[+] Terminal output saved to: {path}")
    
    def clear_terminal_history(self):
        """Clear terminal command history"""
        self.terminalPage.historyComboBox.clear()
        self.append_terminal_output("[*] Command history cleared")
    
    def append_terminal_output(self, message: str):
        """Append message to terminal output"""
        self.terminal_output.append(message)
        # Ensure the latest output is visible
        cursor = self.terminal_output.textCursor()
        cursor.movePosition(QtGui.QTextCursor.MoveOperation.End)
        self.terminal_output.setTextCursor(cursor)
        
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
        
        # Clean up thread resources
        if hasattr(self, 'network_thread') and self.network_thread:
            self.network_thread.quit()
            self.network_worker.deleteLater()
            self.network_thread.deleteLater()


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
        
    def run(self):
        """Run network mapping"""
        self.running = True
        try:
            self.output_signal.emit(f"[*] Starting network mapping on {self.target}")
            self.logger.info(f"Starting network mapping on {self.target}")
            
            # Simulate network mapping with progress updates
            total_steps = 5
            current_step = 0
            
            # Step 1: Host discovery
            if not self.running:
                self.output_signal.emit("[*] Network mapping cancelled.")
                self.status_signal.emit("Status: Cancelled")
                self.finished_signal.emit()
                return
                
            self.output_signal.emit("[*] Performing host discovery...")
            self.status_signal.emit("Status: Host Discovery")
            self.progress_signal.emit(int((current_step / total_steps) * 100))
            # TODO: Implement actual host discovery
            # For now, just simulate a delay
            QtCore.QThread.sleep(2)
            current_step += 1
            
            # Step 2: Port scanning
            if not self.running:
                self.output_signal.emit("[*] Network mapping cancelled.")
                self.status_signal.emit("Status: Cancelled")
                self.finished_signal.emit()
                return
                
            self.output_signal.emit("[*] Performing port scanning...")
            self.status_signal.emit("Status: Port Scanning")
            self.progress_signal.emit(int((current_step / total_steps) * 100))
            # TODO: Implement actual port scanning
            # For now, just simulate a delay
            QtCore.QThread.sleep(2)
            current_step += 1
            
            # Step 3: Service detection
            if not self.running:
                self.output_signal.emit("[*] Network mapping cancelled.")
                self.status_signal.emit("Status: Cancelled")
                self.finished_signal.emit()
                return
                
            self.output_signal.emit("[*] Performing service detection...")
            self.status_signal.emit("Status: Service Detection")
            self.progress_signal.emit(int((current_step / total_steps) * 100))
            # TODO: Implement actual service detection
            # For now, just simulate a delay
            QtCore.QThread.sleep(2)
            current_step += 1
            
            # Step 4: OS detection (if enabled)
            if self.detect_os:
                if not self.running:
                    self.output_signal.emit("[*] Network mapping cancelled.")
                    self.status_signal.emit("Status: Cancelled")
                    self.finished_signal.emit()
                    return
                    
                self.output_signal.emit("[*] Performing OS detection...")
                self.status_signal.emit("Status: OS Detection")
                self.progress_signal.emit(int((current_step / total_steps) * 100))
                # TODO: Implement actual OS detection
                # For now, just simulate a delay
                QtCore.QThread.sleep(2)
            current_step += 1
            
            # Step 5: Traceroute (if enabled)
            if self.use_traceroute:
                if not self.running:
                    self.output_signal.emit("[*] Network mapping cancelled.")
                    self.status_signal.emit("Status: Cancelled")
                    self.finished_signal.emit()
                    return
                    
                self.output_signal.emit("[*] Performing traceroute...")
                self.status_signal.emit("Status: Traceroute")
                self.progress_signal.emit(int((current_step / total_steps) * 100))
                # TODO: Implement actual traceroute
                # For now, just simulate a delay
                QtCore.QThread.sleep(2)
            current_step += 1
            
            # Finalize
            self.progress_signal.emit(100)
            self.status_signal.emit("Status: Complete")
            self.output_signal.emit("[+] Network mapping complete!")
            
            # Generate some sample results
            self.output_signal.emit("\n[+] Hosts discovered:")
            self.output_signal.emit("  - 192.168.1.1 (Router)")
            self.output_signal.emit("  - 192.168.1.2 (Windows 10)")
            self.output_signal.emit("  - 192.168.1.3 (Linux)")
            self.output_signal.emit("  - 192.168.1.4 (macOS)")
            
        except Exception as e:
            self.output_signal.emit(f"[!] Error during network mapping: {str(e)}")
            self.status_signal.emit("Status: Error")
            self.logger.error(f"Error during network mapping: {str(e)}")
        finally:
            self.running = False
            self.finished_signal.emit()
    
    def stop(self):
        """Stop network mapping"""
        self.running = False
        self.logger.info("Network mapping stopped by user")


class ReconWorker(QtCore.QObject):
    output_signal = QtCore.pyqtSignal(str)
    finished_signal = QtCore.pyqtSignal()

    def __init__(self, target, logger):
        super().__init__()
        self.target = target
        self.logger = logger
        self.running = False

    def run(self):
        self.running = True
        try:
            results = []
            if self.running:
                results = recon.run(self.target, self.logger)
            
            if self.running:
                for line in results:
                    self.output_signal.emit(line)
                    if not self.running:
                        break
        except Exception as e:
            self.output_signal.emit(f"[!] Error during recon: {str(e)}")
        finally:
            self.running = False
            self.finished_signal.emit()
            
    def stop(self):
        """Stop reconnaissance"""
        self.running = False
        self.logger.info("Reconnaissance stopped by user")


def main():
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
    
    window = MainWindow()
    window.setWindowTitle("APT Toolkit")
    window.resize(1024, 720)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()