import sys
from PyQt5 import QtGui, uic
from PyQt5.QtCore import QCoreApplication, QMetaObject, QObject, QRect, QThread, Qt, pyqtSignal, pyqtSlot
from PyQt5.QtWidgets import *
import json
import os
from sqli_detect import *
import dir_scan
import XSS_detect

class Thread(QThread):
    output_str = pyqtSignal(str)
    progress_int = pyqtSignal(int)
    end_thread = pyqtSignal()
    report_sg = pyqtSignal(str)
    

    def __init__(self, parent, url, cookie):
        super().__init__(parent)
        self.parent = parent
        self.url = url
        self.cookie = cookie
        self.report_dir = []
        self.report_sqli_url = []
        self.report_sqli_error = []
        self.report_sqli_boolean = []
        self.report_xss_reflected = []
        self.report_xss_dom = []
        self.check_scan = [0,0,0]

    def run(self):
        self.output_str.emit("\t\t\t[SCAN START]")
        self.form_list = parse_form(self.url, self.cookie)
        if self.parent.checkBox.isChecked(): #dir
            self.check_scan[0] = 1
            self.output_str.emit("\n<연결된 웹페이지를 찾습니다...>\n")
            self.report_dir = dir_scan.discover_directory(self.url, self.cookie, self)
        self.progress_int.emit(33)
        
        if self.parent.checkBox_2.isChecked(): #sqli
            self.check_scan[1] = 1
            percent = 33
            add_val = int(33/(len(self.form_list)))
            self.output_str.emit("\n<SQL Injection에 취약한 부분을 탐색합니다...>")
            with open(os.path.dirname(os.path.realpath(__file__))+'/payloads/sql payload.txt', 'r', encoding='utf8') as f:
                sqli_payloads = f.read().split('\n')
            with open(os.path.dirname(os.path.realpath(__file__))+'/payloads/sqli_boolean.txt','r',encoding='utf8') as f:
                bool_payloads = f.read().split('\n')
            with open(os.path.dirname(os.path.realpath(__file__))+'/payloads/spl error.txt','r',encoding='utf8') as f:
                error_codes = f.read().split('\n')
            self.report_sqli_url = sqli_url_scan(self.url, self.cookie, sqli_payloads[:9], error_codes, self)
            self.from_list_sqli_vuln = [0]*len(self.form_list)
            for i, form in enumerate(self.form_list):
                self.output_str.emit(f"\n [+] 발견된 FORM에 공격을 시도합니다...\n  <form action=\"{form['action']}\", method=\"{form['method']}\"> {form['inputs']}")
                print(form)
                a, b = sqli_form_scan(self.url, self.cookie, sqli_payloads, bool_payloads, error_codes, form, self)
                if len(a) or len(b):
                    self.from_list_sqli_vuln[i] = 1
                self.report_sqli_error+=a
                self.report_sqli_boolean+=b
                percent+=add_val
                self.progress_int.emit(percent)
        self.progress_int.emit(66)   

        if self.parent.checkBox_3.isChecked(): #xss
            self.check_scan[2] = 1
            percent = 66
            add_val = int(33/(len(self.form_list)))
            self.output_str.emit("\n<XSS에 취약한 부분을 탐색합니다...>")
            with open(os.path.dirname(os.path.realpath(__file__))+'/payloads/xss_payloads_list.txt', "r", encoding="utf-8") as vector_file:
                xss_payloads = vector_file.read().split('\n')
            self.from_list_xss_vuln = [0]*len(self.form_list)
            for i, form in enumerate(self.form_list) : 
                self.output_str.emit(f"\n [+] 발견된 FORM에 공격을 시도합니다...\n  <form action=\"{form['action']}\", method=\"{form['method']}\"> {form['inputs']}")
                a = XSS_detect.reflected_scan_xss(form, self.url, xss_payloads, self.cookie, self)
                if len(a):
                    self.from_list_xss_vuln[i] = 1
                self.report_xss_reflected += a
                percent+=add_val
                self.progress_int.emit(percent)
            self.report_xss_dom = XSS_detect.dom_scan_xss(self.url, self.cookie, self)
        self.progress_int.emit(99)

        self.output_str.emit(f"""\n\t\t\t[SCAN COMPLETE]
---------------------------------------------------------------------------------------------------""")
        vuln = len(self.report_sqli_url)+len(self.report_sqli_error)+len(self.report_sqli_boolean)+len(self.report_xss_reflected)+len(self.report_xss_dom)
        if self.check_scan[0]: #dir
            report_dir_str = "\n [+]".join(self.report_dir)
            self.output_str.emit(f"""
\t\t         [웹페이지에 연결된 페이지]
\n [+]{report_dir_str}
""")
        if self.check_scan[1] and self.check_scan[2]:
            self.output_str.emit(f"""
\t\t         [웹페이지가 취약한 Payload 수]

\t\t[SQL Injection 취약점]\t\t{len(self.report_sqli_url)+len(self.report_sqli_error)+len(self.report_sqli_boolean)}개
\t\t  <URL based>\t\t{len(self.report_sqli_url)}개
\t\t  <Error based>\t\t{len(self.report_sqli_error)}개
\t\t  <Boolean based>\t\t{len(self.report_sqli_boolean)}개

\t\t[XSS 취약점]\t\t\t{len(self.report_xss_reflected)+len(self.report_xss_dom)}개
\t\t  <Reflected>\t\t\t{len(self.report_xss_reflected)}개 
\t\t  <DOM>\t\t\t{len(self.report_xss_dom)}개
""")
        elif self.check_scan[1]: #sqli
            self.output_str.emit(f"""
\t\t         [웹페이지가 취약한 Payload 수]

\t\t[SQL Injection 취약점]\t\t{len(self.report_sqli_url)+len(self.report_sqli_error)+len(self.report_sqli_boolean)}개
\t\t  <URL based>\t\t{len(self.report_sqli_url)}개
\t\t  <Error based>\t\t{len(self.report_sqli_error)}개
\t\t  <Boolean based>\t\t{len(self.report_sqli_boolean)}개
""")
        elif self.check_scan[2]: #xss
            self.output_str.emit(f"""
\t\t         [웹페이지가 취약한 Payload 수]

\t\t[XSS 취약점]\t\t\t{len(self.report_xss_reflected)+len(self.report_xss_dom)}개
\t\t  <Reflected>\t\t\t{len(self.report_xss_reflected)}개 
\t\t  <DOM>\t\t\t{len(self.report_xss_dom)}개
""")
        if vuln:
            self.output_str.emit("\t     해당 웹페이지는 취약점이 식별되어 정보 유출의 가능성이 있습니다.")
        self.progress_int.emit(100)
        self.end_thread.emit()
        self.mk_report()
        self.check_scan = [0,0,0]

    def mk_report(self):
        v_sqli_form = [str(j) for i, j in zip(self.from_list_sqli_vuln, self.form_list) if i]
        v_xss_form = [str(j) for i, j in zip(self.from_list_xss_vuln, self.form_list) if i]

        report = "-----------------------[[웹페이지 스캔 보고서]]-----------------------\n"
        if self.check_scan[0]:
            report += f"[연결된 URL]\t\t\t{len(self.report_dir)}개\n"
        if self.check_scan[1]:
            report += f"[SQL Injection 취약점]\t\t{len(self.report_sqli_url)+len(self.report_sqli_error)+len(self.report_sqli_boolean)}개\n"
            report += f"  <취약한 Form>\t\t\t{len(v_sqli_form)}개\n"
            report += f"  <URL based SQLI>\t\t{len(self.report_sqli_url)}개\n"
            report += f"  <Error based SQLI>\t\t{len(self.report_sqli_error)}개\n"
            report += f"  <Boolean based SQLI>\t\t{len(self.report_sqli_boolean)}개\n"
        if self.check_scan[2]:
            report += f"[XSS 취약점]\t\t\t{len(self.report_xss_reflected)+len(self.report_xss_dom)}개\n"
            report += f"  <취약한 Form>\t\t\t{len(v_xss_form)}개\n"
            report += f"  <Reflected XSS>\t\t\t{len(self.report_xss_reflected)}개\n"
            report += f"  <DOM XSS>\t\t\t{len(self.report_xss_dom)}개\n"
            

        report += "----------------------------[[세부 정보]]----------------------------"
        if self.check_scan[0]:
            report+="\n[연결된 URL]\n    [+] "
            report+="\n    [+] ".join(self.report_dir)
        if self.check_scan[1]:
            report+="\n[SQL Injection 취약점]"
            report+="\n  <SQLI 취약 Form>\n    [+] "
            report+="\n    [+] ".join(v_sqli_form)
            report+="\n  <SQL Injection URL based>\n    [+] "
            report+="\n    [+] ".join(self.report_sqli_url)
            report+="\n  <SQL Injection Error based>\n    [+] "
            report+="\n    [+] ".join(self.report_sqli_error)
            report+="\n  <SQL Injection Boolean based>\n    [+] "
            report+="\n    [+] ".join(self.report_sqli_boolean)
        if self.check_scan[2]:
            report+="\n[XSS 취약점]"
            report+="\n  <XSS 취약 Form>\n    [+] "
            report+="\n    [+] ".join(v_xss_form)
            report+="\n  <Reflected XSS>\n    [+] "
            report+="\n    [+] ".join(self.report_xss_reflected)
            report+="\n  <DOM XSS>\n    [+] "
            report+="\n    [+] ".join(self.report_xss_dom)
        self.report_sg.emit(report)


class OptionWindow(QDialog):
    def __init__(self, parent):  
        super(OptionWindow, self).__init__(parent)
        self.setWindowTitle("도움말")
        self.setWindowIcon(QtGui.QIcon('vuln_detector\학교로고.png'))
        self.setFixedSize(359, 240)
        self.setupUi(self)
        self.show()

    def setupUi(self, Form):
        self.frame_2 = QFrame(Form)
        self.frame_2.setObjectName(u"frame_2")
        self.frame_2.setGeometry(QRect(0, 0, 361, 241))
        self.frame_2.setStyleSheet(u"background-color:rgb(4, 46, 110)")
        self.frame_2.setFrameShape(QFrame.StyledPanel)
        self.frame_2.setFrameShadow(QFrame.Raised)
        self.label_2 = QLabel(self.frame_2)
        self.label_2.setObjectName(u"label_2")
        self.label_2.setGeometry(QRect(150, 10, 61, 31))
        self.label_2.setStyleSheet(u"font: 75 17pt \"\ud55c\ucef4 \ub9d0\ub791\ub9d0\ub791 Bold\";\n"
                                   "color: rgb(255, 255, 255);")
        self.label_3 = QLabel(self.frame_2)
        self.label_3.setObjectName(u"label_3")
        self.label_3.setGeometry(QRect(10, 60, 301, 21))
        self.label_3.setStyleSheet(u"font: 75 11pt \"\ud55c\ucef4 \ub9d0\ub791\ub9d0\ub791 Bold\";\n"
                                   "color: rgb(255, 255, 255);")
        self.label_6 = QLabel(self.frame_2)
        self.label_6.setObjectName(u"label_6")
        self.label_6.setGeometry(QRect(10, 110, 311, 21))
        self.label_6.setStyleSheet(u"font: 75 11pt \"\ud55c\ucef4 \ub9d0\ub791\ub9d0\ub791 Bold\";\n"
                                   "color: rgb(255, 255, 255);")
        self.label_7 = QLabel(self.frame_2)
        self.label_7.setObjectName(u"label_7")
        self.label_7.setGeometry(QRect(10, 160, 341, 21))
        self.label_7.setStyleSheet(u"font: 75 11pt \"\ud55c\ucef4 \ub9d0\ub791\ub9d0\ub791 Bold\";\n"
                                   "color: rgb(255, 255, 255);")
        self.label_8 = QLabel(self.frame_2)
        self.label_8.setObjectName(u"label_8")
        self.label_8.setGeometry(QRect(30, 80, 301, 16))
        self.label_8.setStyleSheet(u"font: 75 10pt \"\ud55c\ucef4 \ub9d0\ub791\ub9d0\ub791 Bold\";\n"
                                   "color: rgb(255, 255, 14);")

        self.retranslateUi(Form)

        QMetaObject.connectSlotsByName(Form)
    # setupUi

    def retranslateUi(self, Form):
        self.label_2.setText(QCoreApplication.translate(
            "Form", u"\ub3c4\uc6c0\ub9d0", None))
        self.label_3.setText(QCoreApplication.translate(
            "Form", u"1. \uc6d0\ud558\ub294 \uc0ac\uc774\ud2b8\uc758 URL\uacfc Cookie\ub97c \uc785\ub825\ud55c\ub2e4.", None))
        self.label_6.setText(QCoreApplication.translate(
            "Form", u"2. \uc2a4\uce94\ud560 \ucde8\uc57d\uc810\uc744 \uc120\ud0dd\ud558\uace0 START \ubc84\ud2bc\uc744 \ub204\ub978\ub2e4.", None))
        self.label_7.setText(QCoreApplication.translate(
            "Form", u"3. \ubd84\uc11d\uc774 \ub05d\ub098\uba74 Save Report \ubc84\ud2bc\uc744 \ub20c\ub7ec \uc800\uc7a5\ud55c\ub2e4.", None))
        self.label_8.setText(QCoreApplication.translate(
            "Form", u"[Cookie\ub294 Json \ud615\uc2dd\uc73c\ub85c \ucd94\uac00\ud55c\ub2e4.]", None))
    # retranslateUi


class WindowClass(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Hansung Vuln Catcher(웹 취약점 분석 도구)")
        self.setWindowIcon(QtGui.QIcon('vuln_detector\학교로고.png'))
        self.setFixedSize(640, 480)
        self.setupUi(self)

    def setupUi(self, Form):
        self.frame = QFrame(Form)
        self.frame.setObjectName(u"frame")
        self.frame.setGeometry(QRect(10, 10, 621, 121))
        self.frame.setStyleSheet(u"background-color:rgb(4, 46, 110)")
        self.urlEdit = QLineEdit(self.frame)
        self.urlEdit.setObjectName(u"urlEdit")
        self.urlEdit.setGeometry(QRect(180, 10, 391, 20))
        self.urlEdit.setStyleSheet(u"background-color:rgb(255, 255, 255)")
        self.urlEdit.setPlaceholderText("http://127.0.0.1/DVWA/vulnerabilities/sqli/")
        self.Logo = QLabel(self.frame)
        self.Logo.setPixmap(QtGui.QPixmap('vuln_detector\학교로고.png'))
        self.Logo.setScaledContents(1)
        self.Logo.setObjectName(u"Logo")
        self.Logo.setGeometry(QRect(15, 10, 81, 81))
        self.Logo.setLayoutDirection(Qt.LeftToRight)
        self.Logo.setStyleSheet(u"color: rgb(255, 255, 255);\n"
                                 "font: 75 26pt \"\ud55c\ucef4 \ub9d0\ub791\ub9d0\ub791 Bold\";")
        self.teamLabel = QLabel(self.frame)
        self.teamLabel.setScaledContents(1)
        self.teamLabel.setObjectName(u"teamLabel")
        self.teamLabel.setGeometry(QRect(15, 90, 81, 20))
        self.teamLabel.setLayoutDirection(Qt.LeftToRight)
        self.teamLabel.setStyleSheet(u"color: rgb(255, 255, 255);\n"
                                 "font: 75 11pt \"\ud55c\ucef4 \ub9d0\ub791\ub9d0\ub791 Bold\";")
        self.helpButton = QPushButton(self.frame)
        self.helpButton.setObjectName(u"helpButton")
        self.helpButton.setGeometry(QRect(584, 10, 21, 23))
        self.helpButton.setStyleSheet(u"QPushButton{\n"
                                      " background-color:rgb(4, 46, 110);\n"
                                      "	border-style: outset;\n"
                                      "	border-width: 2px;\n"
                                      "	border-radius: 10px;\n"
                                      "	border-color: rgb(255, 255, 255);\n"
                                      "	font: 75 12pt \"\ud55c\ucef4 \ub9d0\ub791\ub9d0\ub791 Bold\";\n"
                                      "	color: rgb(255, 255, 255);\n"
                                      "}\n"
                                      "QPushButton:hover{\n"
                                      "	background-color: rgb(255, 255, 0);\n"
                                      "	color: rgb(0,0,0);\n"
                                      "}\n"
                                      "QPushButton:pressed{\n"
                                      "	background-color: rgb(255, 230, 0);\n"
                                      "	color: rgb(0,0,0);\n"
                                      "}")
        self.helpButton.clicked.connect(self.help)
        self.startButton = QPushButton(self.frame)
        self.startButton.setObjectName(u"startButton")
        self.startButton.setGeometry(QRect(420, 80, 81, 31))
        self.startButton.setStyleSheet(u"QPushButton{\n"
                                        "   background-color:rgb(4, 46, 110);\n"
                                        "	border-style: outset;\n"
                                        "	border-width: 2px;\n"
                                        "	border-radius: 10px;\n"
                                        "	border-color: rgb(255, 255, 255);\n"
                                        "	font: 75 12pt \"\ud55c\ucef4 \ub9d0\ub791\ub9d0\ub791 Bold\";\n"
                                        "	color: rgb(255, 255, 255);\n"
                                        "}\n"
                                        "QPushButton:hover{\n"
                                        "	background-color:rgb(85, 255, 0);	\n"
                                        "	color: rgb(0,0,0);\n"
                                        "}\n"
                                        "QPushButton:pressed{\n"
                                        "	background-color:rgb(85, 220, 0);	\n"
                                        "	color: rgb(0,0,0);\n"
                                        "}\n"
                                        "QPushButton:disabled{\n"
                                        "	background-color: rgb(100, 100, 100);\n"
                                        "	color: rgb(255, 255, 255);\n"
                                        "}"
                                        )
        self.startButton.clicked.connect(self.scan_start)
        self.cookieEdit = QLineEdit(self.frame)
        self.cookieEdit.setObjectName(u"cookieEdit")
        self.cookieEdit.setGeometry(QRect(180, 40, 391, 20))
        self.cookieEdit.setStyleSheet(u"background-color:rgb(255, 255, 255)")
        self.cookieEdit.setPlaceholderText("{\"PHPSESSID\": \"pefefk32\", \"security\":\"low\"}")
        self.stopButton = QPushButton(self.frame)
        self.stopButton.setObjectName(u"stopButton")
        self.stopButton.setGeometry(QRect(530, 80, 75, 31))
        self.stopButton.setStyleSheet(u"QPushButton{\n"
                                        "   background-color:rgb(4, 46, 110);\n"
                                        "	border-style: outset;\n"
                                        "	border-width: 2px;\n"
                                        "	border-radius: 10px;\n"
                                        "	border-color: rgb(255, 255, 255);\n"
                                        "	font: 75 12pt \"\ud55c\ucef4 \ub9d0\ub791\ub9d0\ub791 Bold\";\n"
                                        "	color: rgb(255, 255, 255);\n"
                                        "}\n"
                                        "QPushButton:hover{\n"
                                        "	background-color: rgb(255, 0, 0);\n"
                                        "	color: rgb(0,0,0);\n"
                                        "}\n"
                                        "QPushButton:pressed{\n"
                                        "	background-color: rgb(230, 0, 0);\n"
                                        "	color: rgb(0,0,0);\n"
                                        "}\n"
                                        "QPushButton:disabled{\n"
                                        "	background-color: rgb(100, 100, 100);\n"
                                        "	color: rgb(255, 255, 255);\n"
                                        "}")
        self.stopButton.clicked.connect(self.stop)
        self.stopButton.setDisabled(1)
        self.urlLabel = QLabel(self.frame)
        self.urlLabel.setObjectName(u"urlLabel")
        self.urlLabel.setGeometry(QRect(130, 10, 51, 21))
        self.urlLabel.setStyleSheet(u"color: rgb(255, 255, 255);\n"
                                   "font: 75 12pt \"\ud55c\ucef4 \ub9d0\ub791\ub9d0\ub791 Bold\";")
        self.cookieLabel = QLabel(self.frame)
        self.cookieLabel.setObjectName(u"cookieLabel")
        self.cookieLabel.setGeometry(QRect(110, 40, 71, 21))
        self.cookieLabel.setStyleSheet(u"color: rgb(255, 255, 255);\n"
                                   "font: 75 12pt \"\ud55c\ucef4 \ub9d0\ub791\ub9d0\ub791 Bold\";")
        self.groupBox = QGroupBox(self.frame)
        self.groupBox.setObjectName(u"groupBox")
        self.groupBox.setGeometry(QRect(120, 70, 281, 41))
        self.groupBox.setStyleSheet(u"background-color:rgb(4, 46, 110);\n"
                                    "color: rgb(255, 255, 255);\n"
                                    "font: 75 8pt \"\ud55c\ucef4 \ub9d0\ub791\ub9d0\ub791 Bold\";")
        self.checkBox = QCheckBox(self.groupBox)
        self.checkBox.setObjectName(u"checkBox")
        self.checkBox.setGeometry(QRect(10, 16, 91, 20))
        self.checkBox.setStyleSheet(u"color: rgb(255, 255, 255);\n"
                                    "font: 75 9pt \"\ud55c\ucef4 \ub9d0\ub791\ub9d0\ub791 Bold\";")
        self.checkBox_2 = QCheckBox(self.groupBox)
        self.checkBox_2.setObjectName(u"checkBox_2")
        self.checkBox_2.setGeometry(QRect(110, 16, 91, 20))
        self.checkBox_2.setStyleSheet(u"color: rgb(255, 255, 255);\n"
                                    "font: 75 9pt \"\ud55c\ucef4 \ub9d0\ub791\ub9d0\ub791 Bold\";")
        self.checkBox_3 = QCheckBox(self.groupBox)
        self.checkBox_3.setObjectName(u"checkBox_3")
        self.checkBox_3.setGeometry(QRect(220, 16, 51, 20))
        self.checkBox_3.setStyleSheet(u"color: rgb(255, 255, 255);\n"
                                      "font: 75 9pt \"\ud55c\ucef4 \ub9d0\ub791\ub9d0\ub791 Bold\";")
        self.startButton.raise_()
        self.urlEdit.raise_()
        self.Logo.raise_()
        self.helpButton.raise_()
        self.cookieEdit.raise_()
        self.stopButton.raise_()
        self.urlLabel.raise_()
        self.cookieLabel.raise_()
        self.groupBox.raise_()
        self.progressBar = QProgressBar(Form)
        self.progressBar.setObjectName(u"progressBar")
        self.progressBar.setGeometry(QRect(20, 140, 611, 23))
        self.progressBar.setStyleSheet(
            u"font: 75 12pt \"\ud55c\ucef4 \ub9d0\ub791\ub9d0\ub791 Bold\";")
        self.progressBar.setValue(0)
        self.resultTextEdit = QPlainTextEdit(Form)
        self.resultTextEdit.setObjectName(u"resultTextEdit")
        self.resultTextEdit.setGeometry(QRect(10, 170, 621, 251))
        self.resultTextEdit.setReadOnly(True)
        self.resultTextEdit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        
        self.frame_2 = QFrame(Form)
        self.frame_2.setObjectName(u"frame_2")
        self.frame_2.setGeometry(QRect(10, 430, 621, 41))
        self.frame_2.setStyleSheet(u"background-color:rgb(4, 46, 110)")
        self.frame_2.setFrameShape(QFrame.StyledPanel)
        self.frame_2.setFrameShadow(QFrame.Raised)
        self.saveButton = QPushButton(self.frame_2)
        self.saveButton.setObjectName(u"saveButton")
        self.saveButton.setGeometry(QRect(10, 10, 111, 21))
        self.saveButton.setStyleSheet(u"QPushButton{\n"
                                        "	background-color:rgb(85, 255, 0);\n"
                                        "	border-style: outset;\n"
                                        "	border-width: 2px;\n"
                                        "	border-radius: 10px;\n"
                                        "	border-color: rgb(255, 255, 255);\n"
                                        "	font: 75 12pt \"\ud55c\ucef4 \ub9d0\ub791\ub9d0\ub791 Bold\";\n"
                                        "}\n"
                                        "QPushButton:hover{\n"
                                        "	background-color:rgb(85, 240, 0);	\n"
                                        "	color: rgb(0,0,0);\n"
                                        "}\n"
                                        "QPushButton:pressed{\n"
                                        "	background-color:rgb(85, 220, 0);	\n"
                                        "	color: rgb(0,0,0);\n"
                                        "}\n"
                                        "QPushButton:disabled{\n"
                                        "	background-color: rgb(100, 100, 100);\n"
                                        "	color: rgb(255, 255, 255);\n"
                                        "}")
        self.saveButton.setDisabled(1)
        self.saveButton.clicked.connect(self.save)
        self.resetButton = QPushButton(self.frame_2)
        self.resetButton.setObjectName(u"resetButton")
        self.resetButton.setGeometry(QRect(510, 10, 101, 21))
        self.resetButton.setStyleSheet(u"QPushButton{\n"
                                        "	background-color:rgb(4, 46, 110);\n"
                                        "	border-style: outset;\n"
                                        "	border-width: 2px;\n"
                                        "	border-radius: 10px;\n"
                                        "	border-color: rgb(255, 255, 255);\n"
                                        "	font: 75 12pt \"\ud55c\ucef4 \ub9d0\ub791\ub9d0\ub791 Bold\";\n"
                                        "	color: rgb(255, 255, 255);\n"
                                        "}\n"
                                        "QPushButton:hover{\n"
                                        "	background-color: rgb(255, 0, 0);\n"
                                        "	color: rgb(0,0,0);\n"
                                        "}\n"
                                        "QPushButton:pressed{\n"
                                        "	background-color: rgb(230, 0, 0);\n"
                                        "	color: rgb(0,0,0);\n"
                                        "}")
        self.resetButton.clicked.connect(self.reset)
        self.subLabel = QLabel(self.frame_2)
        self.subLabel.setObjectName(u"subLabel")
        self.subLabel.setGeometry(QRect(200, 10, 221, 21))
        self.subLabel.setStyleSheet(u"font: 75 10pt \"\ud55c\ucef4 \ub9d0\ub791\ub9d0\ub791 Bold\";\n"
                                   "color: rgb(255, 255, 255);")

        self.retranslateUi(Form)

        QMetaObject.connectSlotsByName(Form)
    # setupUi

    def retranslateUi(self, Form):
        self.teamLabel.setText(QCoreApplication.translate("Form", u"TEAM: OwL", None))
        self.helpButton.setText(QCoreApplication.translate("Form", u"?", None))
        self.startButton.setText(
            QCoreApplication.translate("Form", u"START", None))
        self.stopButton.setText(
            QCoreApplication.translate("Form", u"STOP", None))
        self.urlLabel.setText(
            QCoreApplication.translate("Form", u"URL :", None))
        self.cookieLabel.setText(
            QCoreApplication.translate("Form", u"Cookie :", None))
        self.groupBox.setTitle(QCoreApplication.translate(
            "Form", u"Scan Option", None))
        self.checkBox.setText(QCoreApplication.translate(
            "Form", u"Dir Scan", None))
        self.checkBox_2.setText(
            QCoreApplication.translate("Form", u"Sql Injection", None))
        self.checkBox_3.setText(
            QCoreApplication.translate("Form", u"XSS", None))
        self.resultTextEdit.setPlainText("")
        self.saveButton.setText(
            QCoreApplication.translate("Form", u"Save Report", None))
        self.resetButton.setText(
            QCoreApplication.translate("Form", u"Reset", None))
        self.subLabel.setText(QCoreApplication.translate(
            "Form", u"2021 제 5회 \ud55c\uc131\ub300\ud559\uad50 C&C Festival", None))
    # retranslateUi

    def scan_start(self):
        self.resultTextEdit.clear()
        try:
            scan_url = self.urlEdit.text().strip()
            if not scan_url : raise Exception
            scan_cookie = json.loads(self.cookieEdit.text() if self.cookieEdit.text() != "" else "{}")
        except Exception as e: #TODO 오류 핸들링 수정
            return self.print_result("[ERROR] 형식에 맞는 URL, Cookie를 입력하세요.")
        self.startButton.setDisabled(1)
        self.stopButton.setDisabled(0)
        self.urlEdit.setDisabled(1)
        self.cookieEdit.setDisabled(1)
        self.groupBox.setDisabled(1)
        self.saveButton.setDisabled(1)
        
        
        self.th = Thread(self, scan_url, scan_cookie)
        self.th.output_str.connect(self.print_result)
        self.th.progress_int.connect(self.print_progress)
        self.th.end_thread.connect(self.end)
        self.th.report_sg.connect(self.sv_report)
        self.th.start()

    def end(self):
        self.startButton.setDisabled(0)
        self.stopButton.setDisabled(1)
        self.urlEdit.setDisabled(0)
        self.cookieEdit.setDisabled(0)
        self.groupBox.setDisabled(0)
        self.saveButton.setDisabled(0)
        self.th.terminate()


    def help(self):
        OptionWindow(self)

    def save(self):
        FileSave = QFileDialog.getSaveFileName(self, 'Save file', './',"text files(*.txt)")
        if FileSave[0]:
            with open(FileSave[0], 'w', encoding='utf8') as f:
                f.write(self.report)
        

    def reset(self):
        self.urlEdit.setText("")
        self.cookieEdit.setText("")
        self.resultTextEdit.clear()
        self.progressBar.setValue(0)
        self.checkBox.setChecked(0)
        self.checkBox_2.setChecked(0)
        self.checkBox_3.setChecked(0)
        self.startButton.setDisabled(0)
        self.saveButton.setDisabled(1)
    
    def stop(self):
        self.th.terminate()
        self.resultTextEdit.appendPlainText("\n\t\t\t[SCAN STOP]")
        self.startButton.setDisabled(0)
        self.stopButton.setDisabled(1)
        self.urlEdit.setDisabled(0)
        self.cookieEdit.setDisabled(0)
        self.groupBox.setDisabled(0)
        self.saveButton.setDisabled(1)

    def print_progress(self, int):
        self.progressBar.setValue(int)

    def print_result(self, str):
        str = str.replace("<","&lt;")
        str = str.replace(">","&gt;")
        str = str.replace("\"","&quot;")
        str = str.replace("\'","&#39;")
        str = str.replace("\n","<br />")

        if "식별" in str : 
            html = "<pre style=\"color:Red;font-family:굴림\"><b>"+str+"</b></pre>"
        else :
            html = "<pre style=\"color:Blue;font-family:굴림\">"+str+"</pre>"

        # self.resultTextEdit.appendPlainText(str)
        self.resultTextEdit.appendHtml(html)
        self.resultTextEdit.verticalScrollBar().setValue(self.resultTextEdit.verticalScrollBar().maximum())

    def sv_report(self, str):
        self.report = str

        
        
if __name__ == "__main__":
    #QApplication : 프로그램을 실행시켜주는 클래스
    app = QApplication(sys.argv)
    #WindowClass의 인스턴스 생성
    myWindow = WindowClass()
    #프로그램 화면을 보여주는 코드
    myWindow.show()
    #프로그램을 이벤트루프로 진입시키는(프로그램을 작동시키는) 코드
    app.exec_()
