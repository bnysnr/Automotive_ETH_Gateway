import sys
from PyQt5.QtWidgets import QApplication, QWidget, QFrame, QLabel, QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap, QFontDatabase, QFont, QColor, QBrush


def apply_font_to_table(table, font):
        table.setFont(font)
        table.horizontalHeader().setFont(font)
        table.verticalHeader().setFont(font)
        for r in range(table.rowCount()):
            for c in range(table.columnCount()):
                item = table.item(r, c)
                if item:
                    item.setFont(font)


class MyWindow(QWidget):

    def __init__(self):
        super().__init__()

        # --- globale Font laden ---
        font_id = QFontDatabase.addApplicationFont('/home/admin/Praxissemester/font/TTF/AUMOVIOOffice-Regular.ttf')
        if font_id == -1:
            print("Fehler beim Laden der Schriftart!")
            self.gui_font = QFont()
        else:
            font_family = QFontDatabase.applicationFontFamilies(font_id)[0]
            self.gui_font = QFont(font_family, 12)
            QApplication.instance().setFont(self.gui_font)

        # --- Fenster-Einstellungen ---
        self.setWindowTitle("Signal State Dashboard")
        self.setFixedSize(1200, 475)

        # --- GUI erstellen ---
        self.titleBox()
        self.egomotionBox()
        self.sensorconfigmsgstatusbox()

        apply_font_to_table(self.table_ego, self.gui_font)
        apply_font_to_table(self.table_cfg, self.gui_font)


    # ---------------- Widgets ----------------
    def titleBox(self):
        self.box1 = QFrame(self)
        self.box1.setFrameShape(QFrame.Box)
        self.box1.setLineWidth(0)

        box_height = int(self.height() * 0.15)
        self.box1.setGeometry(0, 0, self.width(), box_height)

        self.logo_label = QLabel(self.box1)
        self.logo_label.setGeometry(5, 5, 200, box_height)
        pix = QPixmap("/home/admin/Praxissemester/script/Aumovio_Logo_orange_black_transparent.png")
        if not pix.isNull():
            scaled_pix = pix.scaled(self.logo_label.width(), self.logo_label.height(), Qt.KeepAspectRatio)
            self.logo_label.setPixmap(scaled_pix)

        self.label1 = QLabel("Signal State Dashboard", self.box1)
        self.label1.setStyleSheet("font-size: 24px; font-weight: bold;")
        self.label1.setAlignment(Qt.AlignCenter)
        self.label1.setGeometry(0, 0, self.width(), box_height)


    def egomotionBox(self):
        self.box2 = QFrame(self)
        self.box2.setFrameShape(QFrame.Box)
        self.box2.setLineWidth(0)

        self.label2 = QLabel("Egomotion", self.box2, alignment=Qt.AlignHCenter)
        self.label2.setStyleSheet("font-size: 20px; font-weight: bold;")

        self.table_ego = QTableWidget(9, 2, self.box2)
        self.table_ego.setHorizontalHeaderLabels(["Signalname", "Value"])
        self.table_ego.setShowGrid(False)
        self.table_ego.setFrameStyle(QFrame.NoFrame)
        self.table_ego.verticalHeader().setVisible(False)
        self.table_ego.setEditTriggers(QAbstractItemView.NoEditTriggers)

        header = self.table_ego.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Fixed)

        ego_names = [
            "Yaw Rate", "Steering Wheel Angle", "Lateral Acceleration",
            "Wheel Velocity Front Left", "Wheel Velocity Front Right",
            "Wheel Velocity Rear Left", "Wheel Velocity Rear Right",
            "Vehicle Velocity", "Vehicle Longitudinal Acceleration"
        ]

        for i, name in enumerate(ego_names):
            item = QTableWidgetItem(name)
            item.setFont(self.gui_font)
            self.table_ego.setItem(i, 0, item)

        box_y = int(self.height() * 0.1) + 10
        box_height = int(self.height() * 0.85)
        usable_width = self.width() - 30
        box2_width = int(usable_width * 0.5)

        self.box2.setGeometry(10, box_y, box2_width, box_height)
        self.label2.setGeometry(0, 15, box2_width, 40)
        self.table_ego.setGeometry(10, 50, box2_width - 20, box_height - 60)


    def sensorconfigmsgstatusbox(self):
        self.box3 = QFrame(self)
        self.box3.setFrameShape(QFrame.Box)
        self.box3.setLineWidth(0)

        self.label3 = QLabel("Sensor Config Message Status", self.box3, alignment=Qt.AlignHCenter)
        self.label3.setStyleSheet("font-size: 20px; font-weight: bold;")

        box_y = int(self.height() * 0.1) + 10
        box_height = int(self.height() * 0.85)
        usable_width = self.width() - 30
        box2_width = int(usable_width * 0.5)
        box3_width = int(usable_width * 0.5)
        x = 10 + box2_width + 10

        self.box3.setGeometry(x, box_y, box3_width, box_height)
        self.label3.setGeometry(0, 15, box3_width, 40)

        self.table_cfg = QTableWidget(7, 3, self.box3)
        self.table_cfg.setHorizontalHeaderLabels(["Signalname", "Status", "Description"])
        self.table_cfg.setShowGrid(False)
        self.table_cfg.setFrameStyle(QFrame.NoFrame)
        self.table_cfg.verticalHeader().setVisible(False)
        self.table_cfg.setEditTriggers(QAbstractItemView.NoEditTriggers)

        header = self.table_cfg.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Fixed)

        signal_names = [
            "LongitudinalVelocity", "LongitudinalAcceleration",
            "LateralAcceleration", "YawRate",
            "SteeringAngle", "DrivingDirection",
            "CharacteristicSpeed"
        ]

        for i, name in enumerate(signal_names):
            item = QTableWidgetItem(name)
            item.setFont(self.gui_font)
            self.table_cfg.setItem(i, 0, item)

        self.table_cfg.setGeometry(10, 50, box3_width - 20, box_height - 60)


    # --- Spaltenbreiten proportional anpassen ---
    def resizeEvent(self, event):
        super().resizeEvent(event)

        # Tabelle in Box2 (Ego) 70/30
        ego_width = self.table_ego.viewport().width()
        self.table_ego.setColumnWidth(0, int(ego_width * 0.7))
        self.table_ego.setColumnWidth(1, int(ego_width * 0.3))

        # Tabelle in Box3 (Config) 70/30
        cfg_width = self.table_cfg.viewport().width()
        self.table_cfg.setColumnWidth(0, int(cfg_width * 0.4))
        self.table_cfg.setColumnWidth(1, int(cfg_width * 0.2))
        self.table_cfg.setColumnWidth(2, int(cfg_width * 0.4))


    # Live-Updates der Werte
    def update_values(self, values):
        for i, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setTextAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
            item.setFont(self.gui_font)

            if values[i] == '00':
                item.setForeground(QBrush(QColor("green")))
            else:
                item.setForeground(QBrush(QColor("red")))

            self.table_cfg.setItem(i, 1, item)

            desc_text = self.sensorcfgmsgstatus_description(int(values[i]))
            desc_item = QTableWidgetItem(desc_text)
            desc_item.setFont(self.gui_font)
            desc_item.setTextAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
            self.table_cfg.setItem(i, 2, desc_item)

    def sensorcfgmsgstatus_description(self, value):
        if value == 0:
            return "STATE VALID"
        elif value == 1:
            return "STATE INVALID"
        elif value == 2:
            return "STATE NOT AVAILABLE"
        elif value == 3:
            return "STATE DECREASED"
        elif value == 4:
            return "STATE SUBSTITUE"
        elif value == 5:
            return "STATE INPLAUSIBLE"
        elif value == 6:
            return "STATE OF CALC"
        elif value == 7:
            return "STATE SENSOR"
        elif value == 8:
            return "STATE EXTRAPOLATED"
        elif value == 15:
            return "STATE INIT"
        elif value == 255:
            return "STATE MAX"
        else:
            return "UNKNOWN"


# Main
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MyWindow()
    window.show()
    sys.exit(app.exec_())
