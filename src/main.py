from PyQt6 import QtWidgets
import sys

def main():
    app = QtWidgets.QApplication(sys.argv)
    # Load UI here
    print("[*] APT Toolkit UI started.")
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
