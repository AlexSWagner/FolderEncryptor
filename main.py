import sys
from utils.logger import setup_logger
from ui.gui import GUI

def main():
    # Setup logging
    setup_logger()
    
    # Start the GUI
    gui = GUI()
    gui.run()

if __name__ == "__main__":
    main()
