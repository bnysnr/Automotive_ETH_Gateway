
import sys
from PyQt5.QtWidgets import QApplication, QWidget, QFrame, QLabel, QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap



class MyWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Signal State Dashboard")
        self.setFixedSize(1200, 450)

        # Boxen erstellen
        self.titleBox()
        self.egomotionBox()
        self.sensorconfigmsgstatusbox()

    def titleBox(self):
        self.box1 = QFrame(self)
        self.box1.setFrameShape(QFrame.Box)
        self.box1.setLineWidth(0)

        # Box-Höhe etwas größer, damit das Logo mehr Platz hat
        box_height = int(self.height() * 0.15)  # vorher 0.1, jetzt 15% der Fensterhöhe
        self.box1.setGeometry(0, 0, self.width(), box_height)

        # Logo-Label größer machen
        logo_width = 200   # gewünschte Breite des Logos
        logo_height = box_height  # Höhe basierend auf Box-Höhe
        self.logo_label = QLabel(self.box1)
        self.logo_label.setGeometry(5, 5, logo_width, logo_height)  # minimaler Abstand links und oben

        # Logo laden und proportional skalieren

        pix = QPixmap(r"/home/admin/Praxissemester/script/Aumovio_Logo_orange_black_transparent.png")

        if not pix.isNull():
            scaled_pix = pix.scaled(self.logo_label.width(), self.logo_label.height(), Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.logo_label.setPixmap(scaled_pix)

        # Überschrift zentriert lassen

        self.label1 = QLabel("Signal State Dashboard", self.box1)
        self.label1.setStyleSheet("font-size: 24px; font-weight: bold; font-family: Aumovio;")
        self.label1.setAlignment(Qt.AlignCenter)
        self.label1.setGeometry(0, 0, self.width(), box_height)

    def egomotionBox(self):
        self.box2 = QFrame(self)
        self.box2.setFrameShape(QFrame.Box)
        self.box2.setLineWidth(0)

        self.label2 = QLabel("Egomotion", self.box2, alignment=Qt.AlignHCenter)
        self.label2.setStyleSheet("font-size: 20px; font-weight: bold; font-family: Aumovio;")

        # Tabelle EGOMOTION
        self.table_ego = QTableWidget(9, 2, self.box2) # 9 Zeilen, 2 Spalten
        self.table_ego.setHorizontalHeaderLabels(["Signalname", "Value"])
        self.table_ego.setShowGrid(False) # Keine Gitterlinien
        self.table_ego.setFrameStyle(QFrame.NoFrame) # Kein Rahmen
        self.table_ego.verticalHeader().setVisible(False) # Vertikale Header ausblenden
        self.table_ego.setEditTriggers(QAbstractItemView.NoEditTriggers) # Nicht editierbar

        # Spaltenbreite anpassen (50% jeweils)

        header = self.table_ego.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Stretch)

        # Signalnamen
        ego_signalnames = [
            "Yaw Rate", "Steering Wheel Angle", "Lateral Acceleration",
            "Wheel Velocity Front Left", "Wheel Velocity Front Right",
            "Wheel Velocity Rear Left", "Wheel Velocity Rear Right",
            "Vehicle Velocity", "Vehicle Longitudinal Acceleration"
        ]

        for i, name in enumerate(ego_signalnames):
            self.table_ego.setItem(i, 0, QTableWidgetItem(name))

        # Positionierung
        box_y = int(self.height() * 0.1) + 10
        box_height = int(self.height() * 0.85)
        usable_width = self.width() - 30
        box2_width = int(usable_width * 0.6)

        self.box2.setGeometry(10, box_y, box2_width, box_height)
        self.label2.setGeometry(0, 0, box2_width, 40)
        self.table_ego.setGeometry(10, 50, box2_width - 20, box_height - 60)


    def sensorconfigmsgstatusbox(self):
        self.box3 = QFrame(self)
        self.box3.setFrameShape(QFrame.Box)
        self.box3.setLineWidth(0)

        self.label3 = QLabel("Sensor Config Message Status", self.box3, alignment=Qt.AlignHCenter)
        self.label3.setStyleSheet("font-size: 20px; font-weight: bold; font-family: Aumovio;")

        box_y = int(self.height() * 0.1) + 10
        box_height = int(self.height() * 0.85)
        usable_width = self.width() - 30

        box2_width = int(usable_width * 0.6)
        box3_width = int(usable_width * 0.4)

        x = 10 + box2_width + 10
        self.box3.setGeometry(x, box_y, box3_width, box_height)
        self.label3.setGeometry(0, 0, box3_width, 40)

        # Tabelle CONFIG

        self.table_cfg = QTableWidget(7, 2, self.box3)
        self.table_cfg.setHorizontalHeaderLabels(["Signalname", "Status"])
        self.table_cfg.setShowGrid(False)
        self.table_cfg.setFrameStyle(QFrame.NoFrame)
        self.table_cfg.verticalHeader().setVisible(False)
        self.table_cfg.setEditTriggers(QAbstractItemView.NoEditTriggers)

        header = self.table_cfg.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Stretch)

        names_cfg = [
            "LongitudinalVelocity", "LongitudinalAcceleration", "LateralAcceleration", "YawRate", "SteeringAngle", "DrivingDirection", "CharacteristicSpeed"
        ]

        for i, name in enumerate(names_cfg):
            self.table_cfg.setItem(i, 0, QTableWidgetItem(name))

        self.table_cfg.setGeometry(10, 50, box3_width - 20, box_height - 60)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MyWindow()
    window.show()
    sys.exit(app.exec_())