import sys
import subprocess
from PyQt5.QtWidgets import QApplication, QSplashScreen, QLabel, QVBoxLayout
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QPixmap

class LoadingScreen(QSplashScreen):
    def __init__(self, logo_image_path):
        super().__init__(QPixmap(logo_image_path))  # Initialize with logo pixmap
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)

class LoadingScreen(QSplashScreen):
    def __init__(self, logo_image_path):
        super().__init__(QPixmap(logo_image_path))  # Initialize with logo pixmap
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)

        # Logo label
        self.logo_label = QLabel(self)
        logo_pixmap = QPixmap(logo_image_path).scaledToWidth(10, Qt.SmoothTransformation)
        #self.logo_label.setPixmap(logo_pixmap)
        self.logo_label.setAlignment(Qt.AlignCenter)

        # Text label for "Denaro Core" and version
        self.text_label = QLabel("Denaro Core\nVersion v1.0.0", self)
        self.text_label.setAlignment(Qt.AlignBottom | Qt.AlignHCenter)
        self.text_label.setStyleSheet("""
            QLabel {
                color: #000080;
                font-size: 16pt;
                font-weight: bold;
            }
        """)

        # Positioning the labels within the splash screen
        layout = QVBoxLayout(self)
        layout.addWidget(self.logo_label, alignment=Qt.AlignCenter)
        layout.addWidget(self.text_label, alignment=Qt.AlignBottom | Qt.AlignHCenter)

    def showEvent(self, event):
        # Center the splash screen on the screen
        screen = QApplication.primaryScreen().geometry()
        splash_size = self.geometry()
        self.move((screen.width() - splash_size.width()) / 8,
                  (screen.height() - splash_size.height()) / 8)
        super().showEvent(event)

def show_main_window():
    # Run the mainui.py script
    subprocess.Popen(["python3", "/home/cyract-root/32seed/DenaroWalletClient/mainui.py"])

def main():
    app = QApplication(sys.argv)
    logo_image_path = "black.jpg"  # Update with the path to your logo
    splash = LoadingScreen(logo_image_path)
    splash.show()

    # Set a timer to close the splash screen
    QTimer.singleShot(5000, splash.close)  # 10 seconds display time

    # Set a timer to open the main window, slightly after the splash screen closes
    QTimer.singleShot(3000, show_main_window)  # Delay to ensure it opens after splash screen

    sys.exit(app.exec_())

if __name__ == '__main__':
    main()

