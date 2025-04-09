from PyQt6 import QtWidgets, uic, QtCore, QtGui
from PyQt6.QtWidgets import QFileDialog, QMessageBox
import os
import sys
import json
from typing import Dict, Any, Optional

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.utils.visualization import ReconVisualization
from src.utils.logger import get_module_logger

logger = get_module_logger("recon_viz")

class ReconVizTab(QtWidgets.QWidget):
    """
    A tab widget for visualizing reconnaissance results
    """
    
    def __init__(self, parent=None):
        """Initialize the recon visualization tab"""
        super().__init__(parent)
        
        # Load the UI
        uic.loadUi(os.path.join(os.path.dirname(__file__), "recon_viz.ui"), self)
        
        # Initialize the visualization module
        self.viz = ReconVisualization()
        
        # Current visualization data
        self.recon_data = None
        
        # Connect signals and slots
        self.vizTabWidget.currentChanged.connect(self.update_current_tab)
        self.vizTypeComboBox.currentIndexChanged.connect(self.update_current_tab)
        self.dataSelectComboBox.currentIndexChanged.connect(self.update_current_tab)
        self.refreshButton.clicked.connect(self.refresh_visualization)
        self.exportButton.clicked.connect(self.export_visualization)
    
    def load_data(self, data: Dict[str, Any]) -> None:
        """
        Load reconnaissance data for visualization
        
        Args:
            data: Dictionary containing recon results
        """
        self.recon_data = data
        self.viz.load_data(data)
        self.update_current_tab()
        
    def update_current_tab(self) -> None:
        """Update the visualization in the current tab"""
        if not self.recon_data:
            return
        
        current_tab = self.vizTabWidget.currentWidget()
        tab_name = self.vizTabWidget.tabText(self.vizTabWidget.currentIndex())
        
        # Get the visualization widget in the current tab
        viz_widget = None
        if tab_name == "Host Map":
            viz_widget = self.hostMapWidget
        elif tab_name == "Port Distribution":
            viz_widget = self.portDistWidget
        elif tab_name == "Subdomains":
            viz_widget = self.subdomainWidget
        elif tab_name == "Summary":
            viz_widget = self.summaryWidget
        
        if not viz_widget:
            return
        
        # Create the appropriate visualization
        if tab_name == "Host Map":
            self.viz.current_canvas = self.viz.create_host_network_graph(viz_widget)
        elif tab_name == "Port Distribution":
            self.viz.current_canvas = self.viz.create_port_distribution(viz_widget)
        elif tab_name == "Subdomains":
            self.viz.current_canvas = self.viz.create_subdomain_visualization(viz_widget)
        elif tab_name == "Summary":
            self.viz.current_canvas = self.viz.create_summary_visualization(viz_widget)
    
    def refresh_visualization(self) -> None:
        """Refresh the current visualization"""
        self.update_current_tab()
    
    def export_visualization(self) -> None:
        """Export the current visualization to a file"""
        if not self.viz.current_canvas:
            QMessageBox.warning(self, "Export Error", "No visualization to export.")
            return
        
        # Get file path
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Visualization", "", 
            "PNG Images (*.png);;JPEG Images (*.jpg);;PDF Documents (*.pdf);;SVG Images (*.svg)"
        )
        
        if not file_path:
            return
        
        # Export the visualization
        success = self.viz.export_current_visualization(file_path)
        
        if success:
            QMessageBox.information(self, "Export Successful", f"Visualization exported to {file_path}")
        else:
            QMessageBox.warning(self, "Export Error", "Failed to export visualization.")
    
    def load_data_from_file(self, file_path: str) -> bool:
        """
        Load recon data from a JSON file
        
        Args:
            file_path: Path to the JSON file
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            self.load_data(data)
            return True
        except Exception as e:
            logger.error(f"Failed to load data from {file_path}: {e}")
            return False 