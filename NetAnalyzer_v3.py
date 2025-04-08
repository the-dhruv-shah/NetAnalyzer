import sys
import threading
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem, QTextEdit, QLabel, QSplitter, QComboBox, QPushButton)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from scapy.all import sniff, Packet
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

class PacketAnalyzer(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Network Packet Analyzer")
        self.setGeometry(100, 100, 1200, 700)

        self.layout = QVBoxLayout(self)

        self.splitter = QSplitter(Qt.Horizontal)
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["No.", "Source", "Destination", "Protocol", "Length"])
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.itemSelectionChanged.connect(self.display_packet_details)

        self.details = QTextEdit()
        self.details.setReadOnly(True)

        self.graph_canvas = FigureCanvas(Figure(figsize=(5, 3)))
        self.ax = self.graph_canvas.figure.subplots()
        self.protocol_counts = {}

        self.color_filter = QComboBox()
        self.color_filter.addItems(["All", "TCP", "UDP", "ICMP"])
        self.color_filter.currentTextChanged.connect(self.apply_filter)

        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.clear_packets)

        top_controls = QHBoxLayout()
        top_controls.addWidget(QLabel("Protocol Filter:"))
        top_controls.addWidget(self.color_filter)
        top_controls.addStretch()
        top_controls.addWidget(self.clear_button)

        self.splitter.addWidget(self.table)
        self.splitter.addWidget(self.details)
        self.splitter.setSizes([700, 500])

        self.layout.addLayout(top_controls)
        self.layout.addWidget(self.splitter)
        self.layout.addWidget(self.graph_canvas)

        self.packet_list = []
        self.filtered_packets = []
        self.packet_number = 0

        self.capture_thread = threading.Thread(target=self.capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def capture_packets(self):
        sniff(prn=self.process_packet, store=False)

    def process_packet(self, packet: Packet):
        self.packet_list.append(packet)
        self.packet_number += 1

        src = packet[0].src if hasattr(packet[0], 'src') else 'N/A'
        dst = packet[0].dst if hasattr(packet[0], 'dst') else 'N/A'
        proto = packet.lastlayer().name
        length = len(packet)

        self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1
        self.update_graph()

        self.add_packet_to_table(self.packet_number, src, dst, proto, length, packet)

    def add_packet_to_table(self, number, src, dst, proto, length, packet):
        filter_type = self.color_filter.currentText()
        if filter_type != "All" and proto != filter_type:
            return

        row_position = self.table.rowCount()
        self.table.insertRow(row_position)
        self.filtered_packets.append(packet)

        self.table.setItem(row_position, 0, QTableWidgetItem(str(number)))
        self.table.setItem(row_position, 1, QTableWidgetItem(src))
        self.table.setItem(row_position, 2, QTableWidgetItem(dst))
        self.table.setItem(row_position, 3, QTableWidgetItem(proto))
        self.table.setItem(row_position, 4, QTableWidgetItem(str(length)))

        for col in range(5):
            item = self.table.item(row_position, col)
            if proto == "TCP":
                item.setBackground(QColor("lightblue"))
            elif proto == "UDP":
                item.setBackground(QColor("lightgreen"))
            elif proto == "ICMP":
                item.setBackground(QColor("lightcoral"))

    def display_packet_details(self):
        selected_row = self.table.currentRow()
        if selected_row >= 0 and selected_row < len(self.filtered_packets):
            packet = self.filtered_packets[selected_row]
            self.details.setText(str(packet.show(dump=True)))

    def apply_filter(self):
        self.table.setRowCount(0)
        self.filtered_packets.clear()
        for index, pkt in enumerate(self.packet_list):
            src = pkt[0].src if hasattr(pkt[0], 'src') else 'N/A'
            dst = pkt[0].dst if hasattr(pkt[0], 'dst') else 'N/A'
            proto = pkt.lastlayer().name
            length = len(pkt)
            self.add_packet_to_table(index+1, src, dst, proto, length, pkt)

    def update_graph(self):
        self.ax.clear()
        self.ax.bar(self.protocol_counts.keys(), self.protocol_counts.values(), color='skyblue')
        self.ax.set_title("Protocol Usage")
        self.graph_canvas.draw()

    def clear_packets(self):
        self.packet_list.clear()
        self.filtered_packets.clear()
        self.protocol_counts.clear()
        self.packet_number = 0
        self.table.setRowCount(0)
        self.details.clear()
        self.update_graph()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    analyzer = PacketAnalyzer()
    analyzer.show()
    sys.exit(app.exec_())
