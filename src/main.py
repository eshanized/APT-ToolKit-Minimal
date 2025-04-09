import sys
import os
from PyQt6 import QtWidgets, uic, QtGui, QtCore
from modules import recon
from utils.logger import get_logger


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()

        # Load main window UI
        uic.loadUi("src/ui/main_window.ui", self)

        # Load stacked pages
        self.reconPage = uic.loadUi("src/ui/recon.ui")
        self.logsPage = uic.loadUi("src/ui/logs.ui")
        self.scanResultPage = uic.loadUi("src/ui/scan_result.ui")
        self.vulnScannerPage = uic.loadUi("src/ui/vuln_scanner.ui")
        self.bruteForceePage = uic.loadUi("src/ui/brute_force.ui")
        self.payloadGenPage = uic.loadUi("src/ui/payload_gen.ui")
        self.exploitExecPage = uic.loadUi("src/ui/exploit_exec.ui")
        self.reportPage = uic.loadUi("src/ui/report.ui")
        self.settingsPage = uic.loadUi("src/ui/settings.ui")
        self.terminalPage = uic.loadUi("src/ui/terminal.ui")

        # Add to stacked widget
        self.stackedWidget.addWidget(self.reconPage)
        self.stackedWidget.addWidget(self.logsPage)
        self.stackedWidget.addWidget(self.scanResultPage)
        self.stackedWidget.addWidget(self.vulnScannerPage)
        self.stackedWidget.addWidget(self.bruteForceePage)
        self.stackedWidget.addWidget(self.payloadGenPage)
        self.stackedWidget.addWidget(self.exploitExecPage)
        self.stackedWidget.addWidget(self.reportPage)
        self.stackedWidget.addWidget(self.settingsPage)
        self.stackedWidget.addWidget(self.terminalPage)

        # Connect side nav buttons to stacked pages
        self.btnRecon.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.reconPage))
        self.btnLogs.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.logsPage))
        
        # Connect additional navigation buttons (assuming these exist in main_window.ui)
        # You'll need to adjust these based on the actual button names in your main_window.ui
        if hasattr(self, 'btnScanResult'):
            self.btnScanResult.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.scanResultPage))
        if hasattr(self, 'btnVulnScanner'):
            self.btnVulnScanner.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.vulnScannerPage))
        if hasattr(self, 'btnBruteForce'):
            self.btnBruteForce.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.bruteForceePage))
        if hasattr(self, 'btnPayloadGen'):
            self.btnPayloadGen.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.payloadGenPage))
        if hasattr(self, 'btnExploitExec'):
            self.btnExploitExec.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.exploitExecPage))
        if hasattr(self, 'btnReport'):
            self.btnReport.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.reportPage))
        if hasattr(self, 'btnSettings'):
            self.btnSettings.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.settingsPage))
        if hasattr(self, 'btnTerminal'):
            self.btnTerminal.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.terminalPage))

        # Set default page
        self.stackedWidget.setCurrentWidget(self.reconPage)

        # Connect Recon buttons
        self.reconPage.startButton.clicked.connect(self.start_recon)
        
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

        # Logging
        self.logger = get_logger("APTToolkit")
        self.recon_output = self.reconPage.rawTextEdit
        self.log_output = self.logsPage.detailsTextEdit

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

        # Run recon in separate thread
        thread = QtCore.QThread()
        worker = ReconWorker(target, self.logger)
        worker.moveToThread(thread)

        worker.output_signal.connect(self.append_recon_output)
        worker.finished_signal.connect(lambda: self.spinner.setVisible(False))
        worker.finished_signal.connect(thread.quit)
        worker.finished_signal.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)

        thread.started.connect(worker.run)
        thread.start()

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


class ReconWorker(QtCore.QObject):
    output_signal = QtCore.pyqtSignal(str)
    finished_signal = QtCore.pyqtSignal()

    def __init__(self, target, logger):
        super().__init__()
        self.target = target
        self.logger = logger

    def run(self):
        try:
            results = recon.run(self.target, self.logger)
            for line in results:
                self.output_signal.emit(line)
        except Exception as e:
            self.output_signal.emit(f"[!] Error during recon: {str(e)}")
        self.finished_signal.emit()


def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("APT Toolkit")
    app.setStyle("Fusion")
    window = MainWindow()
    window.setWindowTitle("APT Toolkit")
    window.resize(1024, 720)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()