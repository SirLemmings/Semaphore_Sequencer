from typing import List
from wrappers import Alias, BCPointer, Index, Pubkey, Nym
import config as cfg
import params as pm
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QScrollArea, QGroupBox, QGridLayout, QLabel, QSizePolicy, QPushButton, QHBoxLayout, QLineEdit
from PyQt5.QtCore import pyqtSignal,QTimer
import sys
from datetime import datetime
import connections as cn
import sched
import time
from threading import Thread

#NOTE: i made this in like an hour using chatgpt. do not take it too seriously pls

class Broadcast():
    def __init__(self, alias: Alias, parent: BCPointer, epoch: Index, message: bytes):
        self.alias = alias
        self.parent = parent
        self.epoch = epoch
        self.message = message

    @property
    def pointer(self) -> BCPointer:
        return BCPointer(bytes(self.epoch)+bytes(self.alias))

def decompose(archive:bytes,epoch:Index) -> List[Broadcast]:
    if len(archive) == 0:
        return []
    broadcasts = []

    i = 0
    while i < len(archive):
        bc_len = archive[i]
        i += 1
        blob = archive[i:i+bc_len]
        alias, blob = Alias(blob[:pm.ALIAS_LENGTH]), blob[pm.ALIAS_LENGTH:]
        parent, message = BCPointer(blob[:pm.PARENT_LENGTH]), blob[pm.PARENT_LENGTH:]
        broadcast = Broadcast(alias, parent, epoch, message)
        broadcasts.append(broadcast)
        i += bc_len
    return broadcasts

def archive_to_list() -> List[Broadcast]:#type: ignore
    broadcasts = []
    for key, value in cfg.db.archive:
        broadcasts+=decompose(value,Index(key)) 
    return broadcasts

broadcasts = []

class ClickableGroupBox(QGroupBox):
    clicked = pyqtSignal()
    def __init__(self,index, input_box,*args, **kwargs):
        self.index = index
        self.input_box = input_box
        super().__init__(*args, **kwargs)

    def mousePressEvent(self, event):
        self.input_box.setText(f'@{broadcasts[self.index].pointer.hex()} ')
        self.clicked.emit()
        super().mousePressEvent(event)

class SocialMediaFeed(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()


    def initUI(self):
        timer = QTimer(self)
        timer.timeout.connect(self.refresh)
        timer.start(1000)
        self.input_box = QLineEdit()
        self.setWindowTitle('Semaphore Feed')

        # Create scroll area and set vertical scrollbar policy
        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True) # Allow the scroll area to resize with the window
        scroll_area.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding) # Expand the size of the scroll area
        scroll_area.setFrameShape(QScrollArea.NoFrame) # Remove the frame around the scroll area
        scroll_area.setVerticalScrollBarPolicy(2) # 2 represents always-on scrollbar
        scroll_area.setStyleSheet('QScrollArea { background-color: #000; padding: 0; }') # Set the background color of the scroll area to #000 and remove padding

        self.feed_widget = QWidget()

        # Create a vertical layout for the feed widget
        self.feed_layout = QVBoxLayout(self.feed_widget)
        self.feed_layout.setContentsMargins(10, 10, 10, 10) # Set a constant margin between the message boxes and the scroll area

        # Create message boxes for each post
        self.show_posts(self.input_box)

        # Set the layout of the feed widget
        self.feed_widget.setLayout(self.feed_layout)

        # Set the widget to be the scroll area's widget
        scroll_area.setWidget(self.feed_widget)

        # Set the main window's layout to a vertical layout
        # Create a constant panel of placeholder buttons at the bottom of the window
        button_panel = QWidget()
        button_layout = QHBoxLayout(button_panel)

        # refresh_button = QPushButton('Refresh')
        # refresh_button.clicked.connect(self.refresh)

        broadcast_button = QPushButton('Broadcast')
        #when braodcast button is clicked, add the input box text to the posts
        broadcast_button.clicked.connect(lambda: self.add_message(self.input_box.text()))


        # button_layout.addWidget(refresh_button)
        button_layout.addWidget(self.input_box)
        button_layout.addWidget(broadcast_button)

        button_layout.setContentsMargins(10, 10, 10, 10)
        button_panel.setLayout(button_layout)

        # Set the main window's layout to a vertical layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0) # Remove padding around the main window
        main_layout.addWidget(scroll_area)
        main_layout.addWidget(button_panel)

        #set the default size of the window
        self.resize(400, 600)

    def show_posts(self,box):
        if broadcasts is None:
            return
        for bc in broadcasts:
            message_box = ClickableGroupBox(broadcasts.index(bc),box)
            message_box.clicked.connect(lambda: print(message_box.index))

            message_box.setStyleSheet('QGroupBox { border: 2px solid #555; border-radius: 10px; padding: 10px; margin: 0; }')
            message_box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding) # Expand the size of the message boxes
            message_box_layout = QGridLayout(message_box)

            timestamp = datetime.fromtimestamp(int(bc.epoch)).strftime('%Y-%m-%d %H:%M:%S')
            if bc.parent != BCPointer(b'\x00'*pm.PARENT_LENGTH):
                for p in broadcasts:
                    if p.pointer == bc.parent:
                        parent_box = ClickableGroupBox(broadcasts.index(p),box)
                        parent_box.clicked.connect(lambda: print(parent_box.index))


                        parent_text1 = QLabel()
                        parent_nym = cfg.db.rev_identity_nym.get(p.alias).decode('utf-8')
                        parent_timestamp = datetime.fromtimestamp(int(p.epoch)).strftime('%Y-%m-%d %H:%M:%S')
                        parent_message = p.message.decode('utf-8')
                        parent_text1.setText(f'<html><b>{parent_nym}</b> <span style="color: #999999;">{parent_timestamp}</span></html>')
                        parent_text1.setWordWrap(True)
                        parent_text1.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
                        perent_text2 = QLabel()
                        perent_text2.setText(parent_message)
                        perent_text2.setWordWrap(True)
                        perent_text2.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
                        parent_box_layout = QVBoxLayout(parent_box)
                        parent_box_layout.addWidget(parent_text1)
                        parent_box_layout.addWidget(perent_text2)



                

            username_label = QLabel()
            nym = (cfg.db.rev_identity_nym.get(bc.alias)).decode('utf-8')
            username_label.setText(f'<html><b>{nym}</b> <span style="color: #999999;">{timestamp}</span></html>')
            username_label.setWordWrap(True)
            username_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)

            message_text = QLabel()
            message_text.setText(bc.message.decode('utf-8'))
            message_text.setWordWrap(True)

            if bc.parent!= BCPointer(b'\x00'*pm.PARENT_LENGTH):
                # message_box_layout.addWidget(parent_text1,0,0)
                # message_box_layout.addWidget(perent_text2,1,0)
                message_box_layout.addWidget(parent_box,0,0) #type:ignore
            message_box_layout.addWidget(username_label, 1, 0)
            message_box_layout.addWidget(message_text, 2, 0)

            self.feed_layout.addWidget(message_box)

    def resizeEvent(self, event):
        # Iterate over all message boxes in the feed
        for message_box in self.findChildren(QGroupBox):
            # Get the QLabel containing the message text
            message_text = message_box.findChild(QLabel)

            # Set the width of the message box to the width of the scroll area minus the margin and border widths
            message_box_width = self.width() - 40

            # Set the maximum width of the message text label to the width of the message box minus the padding
            message_text.setMaximumWidth(message_box_width - 20)

            # Set the size policy of the message text label to expanding so it will resize vertically
            message_text.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        super().resizeEvent(event)

    def refresh(self):
        global broadcasts
        broadcasts = archive_to_list()
        # Remove all the message boxes from the feed layout
        for i in reversed(range(self.feed_layout.count())):
            self.feed_layout.itemAt(i).widget().setParent(None)

        # Create message boxes for each post
        self.show_posts(self.input_box)
        self.feed_widget.update()

    def add_message(self, message:str):
        try:
            if message[0]=='!':
                if message[1:5]=='mint':
                    cn.request_alias(Pubkey(cfg.client_pubkey.to_string()))#type: ignore
                elif message[1:4]=='nym':
                    if cfg.alias is None:
                        return
                    nym = message[4:].strip()
                    cn.request_nym_update(
                            cfg.alias, Nym(nym.encode("utf-8")), cfg.client_privkey
                        )
            elif message[0]=='@':
                try:
                    parent = message[1:pm.PARENT_LENGTH*2+1]
                    parent = BCPointer(bytes.fromhex(parent))
                    msg = message[pm.PARENT_LENGTH*2+2:].encode('utf-8')
                    cn.generate_broadcast(parent, msg)
                except Exception as e:
                    print(e)
                    return
            else:
                msg = message.encode('utf-8')#type: ignore
                parent = int(0).to_bytes(pm.PARENT_LENGTH, "big")
                cn.generate_broadcast(BCPointer(parent), msg)
        except IndentationError as e:
            pass
        except IndexError as e:
            pass
        self.input_box.setText('')

    def time_events(self) -> None:
        def event_loop() -> None:
            print("refreshing")
            self.refresh()
            offset = time.time() % pm.EPOCH_TIME-1
            s.enter(pm.EPOCH_TIME - offset, 0, event_loop)

        s = sched.scheduler(time.time, time.sleep)
        offsest = time.time() % pm.EPOCH_TIME-1
        s.enter(pm.EPOCH_TIME - offsest, 0, event_loop)
        s.run()

def start():
    app = QApplication(sys.argv)
    feed = SocialMediaFeed()
    feed.show()
    sys.exit(app.exec_())

