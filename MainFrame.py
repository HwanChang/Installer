from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog
import tkinter.font
import threading, collections, subprocess, os, sys, shutil, datetime, platform

class WindowsInstaller(Frame):
	def __init__(self, master):
		Frame.__init__(self, master)
		self.master = master
		self.master.title('New Project')
		self.pack(fill=BOTH, expand=True)

		self.mainFrame = Frame(self)
		self.mainFrame.pack(fill=BOTH, expand=True, padx=10, pady=10)
		self.filenames = list()
		self.search(os.path.join(os.getcwd(), 'pkg'))
		self.confCheck = False

		remainFrame = Frame(self)
		remainFrame.pack(fill=X, anchor=S, padx=10, pady=(0,10))
		self.buttonInstall = ttk.Button(remainFrame, text='설치', command=self.installThread)
		self.buttonInstall.pack(anchor=NE, padx=10, pady=(0,20))
		self.Progress = ttk.Progressbar(remainFrame, orient=HORIZONTAL, mode='determinate')
		self.Progress.pack(fill=X, anchor=S, padx=20)
		self.Progress.config(maximum=5)
		self.Percent = Label(remainFrame, width=20, text='')
		self.Percent.pack(anchor=SE, padx=5)
		self.buttonCancel = ttk.Button(remainFrame, text='취소', command=self.cancelFunction)
		self.buttonCancel.pack(side=RIGHT, padx=(5,10))
		self.buttonNext = ttk.Button(remainFrame, text='다음', command=self.nextFunction)
		self.buttonNext.pack(side=RIGHT, padx=5)
		self.buttonPast = ttk.Button(remainFrame, text='이전', command=self.pastFunction)
		self.buttonPast.pack(side=RIGHT, padx=5)
		self.buttonPast.config(state=DISABLED)
		self.buttonLog = ttk.Button(remainFrame, text='로그', command=self.mainLog)
		self.buttonLog.pack(side=LEFT, padx=5)

		self.labelMain = Label(self.mainFrame, text='자바 설치')
		self.labelMain.pack(anchor=NW)

		self.contentsFrame = Frame(self.mainFrame)
		self.contentsFrame.pack(fill=BOTH, expand=True, padx=10)

		self.checkFrame = 0
		self.javaFrame()

	def pathFunction(self):
		self.entryPath.config(state='readonly')
		self.pathStr.set(filedialog.askopenfilename(initialdir="/", title='Select file', filetypes=(('실행 파일', '*.exe'), ('모든 파일', '*.*'))))

	def search(self, dir):
		files = os.listdir(dir)
		for file in files:
			fullFilename = os.path.join(dir, file)
			if os.path.isdir(fullFilename):
				self.filenames.append(fullFilename)
				self.search(fullFilename)
			else:
				self.filenames.append(fullFilename)

	def nextFunction(self):
		self.pathStr.set('')
		if self.checkFrame == 0:
			self.buttonInstall.config(text='설치')
			self.buttonPast.config(state=NORMAL)
			self.checkFrame = 1
			self.tomcatFrame()
		elif self.checkFrame == 1:
			self.buttonInstall.config(text='복사')
			self.checkFrame = 2
			self.warFrame()
		elif self.checkFrame == 2:
			self.buttonInstall.config(text='복사')
			self.checkFrame = 3
			self.confFrame()
		elif self.checkFrame == 3:
			self.buttonInstall.config(text='실행')
			self.buttonInstall.config(state=DISABLED)
			self.checkFrame = 4
			self.buttonNext.config(text='완료')
			self.dbFrame()
		elif self.checkFrame == 4:
			self.pathFrame.destroy()
			self.buttonInstall.destroy()
			self.buttonPast.destroy()
			self.buttonNext.destroy()
			self.checkFrame = 5
			self.Percent.config(text='설치 완료')
			self.lastFrame()
		self.Progress.config(value=self.checkFrame)

	def pastFunction(self):
		self.pathStr.set('')
		if self.checkFrame == 4:
			self.buttonInstall.config(text='복사')
			self.checkFrame = 3
			self.buttonNext.config(text='다음')
			self.buttonInstall.config(state=NORMAL)
			self.confFrame()
		elif self.checkFrame == 3:
			self.checkFrame = 2
			self.buttonNext.config(text='다음')
			self.buttonInstall.config(state=NORMAL)
			self.warFrame()
		elif self.checkFrame == 2:
			self.buttonInstall.config(text='설치')
			self.checkFrame = 1
			self.buttonNext.config(state=NORMAL)
			self.buttonInstall.config(state=NORMAL)
			self.tomcatFrame()
		elif self.checkFrame == 1:
			self.buttonInstall.config(text='설치')
			self.buttonPast.config(state=DISABLED)
			self.checkFrame = 0
			self.buttonNext.config(state=NORMAL)
			self.buttonInstall.config(state=NORMAL)
			self.javaFrame()
		self.Progress.config(value=self.checkFrame)

	def javaFrame(self):
		self.labelMain.config(text='자바 설치')
		self.contentsFrame.destroy()
		self.contentsFrame = Frame(self.mainFrame)
		self.contentsFrame.pack(fill=BOTH, expand=True, padx=10)
		self.pathFrame = Frame(self.contentsFrame)
		self.pathFrame.pack(fill=X, anchor=N, expand=True, padx=10, pady=(10,0))
		self.pathStr = StringVar()
		self.entryPath = ttk.Entry(self.pathFrame, textvariable=self.pathStr)
		self.entryPath.pack(fill=X, side=LEFT, expand=True, padx=5)
		self.entryPath.config(state=DISABLED)
		self.buttonPath = ttk.Button(self.pathFrame, text='찾기', command=self.pathFunction)
		self.buttonPath.pack(side=LEFT)
		try:
			self.javaCheck = True
			checkJAVA = subprocess.check_output('REG QUERY "HKLM\\SOFTWARE\\JavaSoft" /s | findstr JavaHome', shell=True, universal_newlines=True)
			pathList = list()
			for path in checkJAVA.split('\n'):
				if path not in pathList:
					pathList.append(path)
			for path in pathList:
				if 'JavaHome' in path:
					labelPath = Label(self.contentsFrame, text=path.split('    ')[-1], relief=SUNKEN, bg='gray99')
					labelPath.pack(fill=X)
			message = Message(self.contentsFrame, text='자바가 설치되어 있습니다.\n\n다시 설치하려면 설치버튼을 넘어가려면 다음버튼을 누르세요.', width=400)
			message.pack(fill=X, side=LEFT, pady=40)
		except subprocess.CalledProcessError as e:
			self.javaCheck = False
			labelPath = Label(self.contentsFrame, text='jdk-8u191-windows-x64', relief=SUNKEN, bg='gray99')
			labelPath.pack(fill=X)
			message = Message(self.contentsFrame, text='자바가 설치되어 있지 않습니다.\n\n위 버전의 자바를 설치하려면 설치버튼을 누르세요.', width=400)
			message.pack(fill=X, side=LEFT, anchor=NW, padx=10, pady=40)

	def tomcatFrame(self):
		self.labelMain.config(text='톰캣 설치')
		self.contentsFrame.destroy()
		self.contentsFrame = Frame(self.mainFrame)
		self.contentsFrame.pack(fill=BOTH, expand=True, padx=10)
		self.pathFrame = Frame(self.contentsFrame)
		self.pathFrame.pack(fill=X, anchor=N, expand=True, padx=10, pady=(10,0))
		self.pathStr = StringVar()
		self.entryPath = ttk.Entry(self.pathFrame, textvariable=self.pathStr)
		self.entryPath.pack(fill=X, side=LEFT, expand=True, padx=5)
		self.entryPath.config(state=DISABLED)
		self.buttonPath = ttk.Button(self.pathFrame, text='찾기', command=self.pathFunction)
		self.buttonPath.pack(side=LEFT)
		try:
			checkTomcat = subprocess.check_output('REG QUERY "HKLM\\SOFTWARE\\Apache Software Foundation" /s | findstr InstallPath', shell=True, universal_newlines=True)
			# self.tomcatPath = list()
			for service in checkTomcat.split('\n'):
				if 'InstallPath' in service:
					# self.tomcatPath.append(service.split('    ')[-1])
					labelPath = Label(self.contentsFrame, text=service.split('    ')[-1], relief=SUNKEN, bg='gray99')
					labelPath.pack(fill=X)
			message = Message(self.contentsFrame, text='위 경로에 톰캣이 설치되어 있습니다.\n\n새로 설치하려면 설치버튼을 넘어가려면 다음버튼을 누르세요.', width=400)
			message.pack(fill=X, side=LEFT, pady=40)
		except subprocess.CalledProcessError as e:
			labelPath = Label(self.contentsFrame, text='apache-tomcat-8.5.35', relief=SUNKEN, bg='gray99')
			labelPath.pack(fill=X)
			message = Message(self.contentsFrame, text='톰캣이 설치되어 있지 않습니다.\n\n위 버전의 톰캣을 설치하려면 설치버튼을 누르세요.', width=400)
			message.pack(fill=X, side=LEFT, anchor=NW, padx=10, pady=40)

	def warFrame(self):
		self.labelMain.config(text='war 파일 복사')
		self.contentsFrame.destroy()
		self.contentsFrame = Frame(self.mainFrame)
		self.contentsFrame.pack(fill=BOTH, expand=True, padx=10)
		# self.comboPath = ttk.Combobox(self.contentsFrame, values=self.tomcatPath, width=400)
		# self.comboPath.pack(fill=X)
		# self.comboPath.config(state='readonly')
		# self.comboPath.current(0)

		frame = Frame(self.contentsFrame)
		frame.pack(fill=X, expand=True, padx=10, pady=(10,0))
		self.pathSave = StringVar()
		savePath = ttk.Entry(frame, textvariable=self.pathSave)
		savePath.pack(fill=X, side=LEFT, expand=True, padx=5)
		buttonPath = ttk.Button(frame, text='열기', command=self.dirPath)
		buttonPath.pack(side=LEFT)
		message = Message(self.contentsFrame, text='열기버튼을 눌러 war파일을 복사할 경로를 설정하고\n\n복사버튼을 누르세요.', width=400)
		message.pack(fill=X, side=LEFT, anchor=NW, padx=10, pady=40)

	def dirPath(self):
		self.pathSave.set(filedialog.askdirectory(initialdir="C:\\"))

	def confFrame(self):
		self.labelMain.config(text='conf 복사')
		self.contentsFrame.destroy()
		self.contentsFrame = Frame(self.mainFrame)
		self.contentsFrame.pack(fill=BOTH, expand=True, padx=10)

		frame = Frame(self.contentsFrame)
		frame.pack(fill=X, expand=True, padx=10, pady=(10,0))
		self.pathSave = StringVar()
		savePath = ttk.Entry(frame, textvariable=self.pathSave)
		savePath.pack(fill=X, side=LEFT, expand=True, padx=5)
		buttonPath = ttk.Button(frame, text='열기', command=self.dirPath)
		buttonPath.pack(side=LEFT)
		message = Message(self.contentsFrame, text='열기버튼을 눌러 conf 디렉토리를 복사할 경로를 설정하고\n\n복사버튼을 누르세요.', width=400)
		message.pack(fill=X, side=LEFT, anchor=NW, padx=10, pady=40)

	def dbFrame(self):
		self.DBCheck = True
		self.filenames = list()
		self.search(os.path.join(os.getcwd(), 'pkg'))
		self.labelMain.config(text='Database')
		self.contentsFrame.destroy()
		self.contentsFrame = Frame(self.mainFrame)
		self.contentsFrame.pack(fill=BOTH, expand=True, padx=10)

		frame = Frame(self.contentsFrame)
		frame.pack(fill=X, pady=10)
		self.comboDBMS = ttk.Combobox(frame, width=20)
		self.comboDBMS['values'] = ('Oracle / Tibero', 'MS-SQL', 'MySQL / MariaDB')
		self.comboDBMS.current(0)
		self.comboDBMS.config(state='readonly')
		self.comboDBMS.pack(side=LEFT)
		self.buttonConnect = ttk.Button(frame, text='연결 정보 입력', command=self.connectFrame)
		self.buttonConnect.pack(side=LEFT, padx=(10,0))
		self.progressState = ttk.Progressbar(frame, orient=HORIZONTAL)
		self.progressState.pack(fill=X, anchor=S, padx=(20,0))

		labelDesc = Label(self.contentsFrame, text='패키지 목록\t\t\t\t\t실행 목록')
		labelDesc.pack(fill=X)

		listFrame = Frame(self.contentsFrame)
		listFrame.pack(fill=X, pady=5)

		frame1 = Frame(listFrame)
		scrollbar1 = Scrollbar(frame1)
		scrollbar1.pack(side=RIGHT, fill=Y)
		scrollbarH1 = Scrollbar(frame1, orient=HORIZONTAL)
		scrollbarH1.pack(side=BOTTOM, fill=X)
		self.itemList1 = list()
		for file in self.filenames:
		 	if '.sql' in file:
		 		self.itemList1.append(file.split('\\')[-1])
		self.leftItem = StringVar(value=self.itemList1)
		self.listbox1 = Listbox(frame1, width=35, height=6, listvariable=self.leftItem, selectmode=EXTENDED)
		self.listbox1.pack(fill=X, padx=(10,0))
		self.listbox1.config(yscrollcommand=scrollbar1.set)
		self.listbox1.config(xscrollcommand=scrollbarH1.set)
		scrollbar1.config(command=self.listbox1.yview)
		scrollbarH1.config(command=self.listbox1.xview)
		frame1.pack(fill=X, side=LEFT)

		buttonFrame = Frame(listFrame)
		upFrame = Frame(buttonFrame)
		insertButton = ttk.Button(upFrame, text='등록->', width=6, command=self.insertFunction)
		insertButton.pack(side=LEFT, padx=5, pady=5)
		upFrame.pack(fill=X)
		downFrame = Frame(buttonFrame)
		removeButton = ttk.Button(downFrame, text='<-제거', width=6, command=self.removeFunction)
		removeButton.pack(side=LEFT, padx=5, pady=5)
		downFrame.pack(fill=X)
		buttonFrame.pack(fill=X, side=LEFT)

		frame2 = Frame(listFrame)
		scrollbar2 = Scrollbar(frame2)
		scrollbar2.pack(side=RIGHT, fill=Y)
		scrollbarH2 = Scrollbar(frame2, orient=HORIZONTAL)
		scrollbarH2.pack(side=BOTTOM, fill=X)
		self.itemList2 = list()
		self.rightItem = StringVar()
		self.listbox2 = Listbox(frame2, width=35, height=6, listvariable=self.rightItem, selectmode=SINGLE)
		self.listbox2.pack(fill=X, padx=(10,0))
		self.listbox2.config(yscrollcommand=scrollbar2.set)
		self.listbox2.config(xscrollcommand=scrollbarH2.set)
		scrollbar2.config(command=self.listbox2.yview)
		scrollbarH2.config(command=self.listbox2.xview)
		frame2.pack(fill=X, side=LEFT)
		message = Message(self.contentsFrame, text='실행하려면 연결정보를 입력한 후 스크립트 파일을 실행목록에 등록하고 실행버튼을 누르세요.', width=600)
		message.pack(fill=X, side=LEFT, anchor=NW, padx=10, pady=10)

	def insertFunction(self):
		try:
			for index in self.listbox1.curselection():
				if self.itemList1[index] in self.itemList2:
					messagebox.showwarning('경고', '이미 실행목록에 등록되어 있는 파일입니다.')
				else:
					self.itemList2.append(self.itemList1[index])
					self.rightItem.set(self.itemList2)

			path = list()
			for item in self.filenames:
				if item.split('\\')[-1] in self.itemList2:
					path.append(item)
			if self.DBCheck:
				for item in path:
					if '00.' in item or '01.' in item:
						pass
					else:
						self.configFrame()
						self.DBCheck = False
						break
		except IndexError:
			messagebox.showwarning('경고', '실행목록에 등록할 스크립트 파일을 선택하세요.')

	def removeFunction(self):
		try:
			if self.itemList2:
				self.itemList2.remove(self.itemList2[self.listbox2.curselection()[0]])
				self.rightItem.set(self.itemList2)
			else:
				messagebox.showwarning('경고', '실행목록에 스크립트 파일이 등록되어 있지 않습니다.')
			path = list()
			for item in self.filenames:
				if item.split('\\')[-1] in self.itemList2:
					path.append(item)
			check = True
			for item in path:
				if '00.' in item or '01.' in item:
					pass
				else:
					check = False
			if check:
				self.DBCheck = True
		except IndexError:
			messagebox.showwarning('경고', '실행목록에서 제거할 스크립트 파일을 선택하세요.')

	def connectFrame(self):
		self.connectionWindow = Toplevel()
		self.connectionWindow.title('DB Connection')
		self.connectionWindow.geometry('580x140+200+200')
		self.connectionWindow.resizable(False, False)

		frame_C1 = Frame(self.connectionWindow)
		frame_C1.pack(fill=X, padx=10, pady=(10,0))
		labelAddr = Label(frame_C1, text='IP')
		labelAddr.pack(side=LEFT, padx=5, pady=10)
		self.entryAddr = ttk.Entry(frame_C1)
		self.entryAddr.pack(side=LEFT, expand=False, padx=(0,5))
		labelPort = Label(frame_C1, text='Port')
		labelPort.pack(side=LEFT, padx=5, pady=10)
		self.entryPort = ttk.Entry(frame_C1)
		self.entryPort.pack(side=LEFT, expand=False, padx=(0,5))
		if self.comboDBMS.get() == 'Oracle / Tibero':
			labelSid = Label(frame_C1, text='sid')
			labelSid.pack(side=LEFT, padx=5, pady=10)
		elif self.comboDBMS.get() == 'MySQL / MariaDB' or self.comboDBMS.get() == 'MS-SQL':
			labelDB = Label(frame_C1, text='DB')
			labelDB.pack(side=LEFT, padx=5, pady=10)
		self.entrySid = ttk.Entry(frame_C1)
		self.entrySid.pack(side=LEFT, expand=False)

	# User info.
		frameC2 = Frame(self.connectionWindow)
		frameC2.pack(fill=X, padx=10)
		labelID = Label(frameC2, text='ID')
		labelID.pack(side=LEFT, padx=5, pady=10)
		self.entryID = ttk.Entry(frameC2)
		self.entryID.pack(side=LEFT, expand=False, padx=(0,5))
		labelPW = Label(frameC2, text='PW')
		labelPW.pack(side=LEFT, padx=5, pady=10)
		self.entryPW = ttk.Entry(frameC2, show="*")
		self.entryPW.pack(side=LEFT, expand=False)

	# Connect button.
		frameC3 = Frame(self.connectionWindow)
		frameC3.pack(fill=X, padx=10)
		self.buttonConnectSave = ttk.Button(frameC3, text='입력 완료', width=21, command=self.connectFunction)
		self.buttonConnectSave.pack(side=RIGHT, padx=5)

	def connectFunction(self):
		self.host = self.entryAddr.get()
		self.port = self.entryPort.get()
		self.user = self.entryID.get()
		self.password = self.entryPW.get()
		self.database = self.entrySid.get()
		self.connectionWindow.destroy()
		self.buttonInstall.config(state=NORMAL)

	def lastFrame(self):
		self.labelMain.config(text='완료')
		self.buttonCancel.config(text='닫기')
		self.contentsFrame.destroy()
		self.contentsFrame = Frame(self.mainFrame)
		self.contentsFrame.pack(fill=BOTH, expand=True, padx=10, pady=10)
		message = Message(self.contentsFrame, text='모든 설치가 완료되었습니다.', width=400)
		message.pack(fill=X, side=LEFT, anchor=NW, padx=10, pady=60)

	def installThread(self):
		installTh = threading.Thread(target=self.installFunction)
		installTh.start()

	def installFunction(self):
		try:
			self.datetime = datetime.datetime.now()
			if self.checkFrame == 0:
				if self.pathStr.get() == '':
					javaName = os.getcwd() + '\\pkg\\jdk-8u191-windows-x64.exe'
				else:
					javaName = self.pathStr.get()
				subprocess.check_call(javaName, shell=True)
				self.buttonNext.config(state=NORMAL)
				self.Percent.config(text='자바 설치 완료')
				with open(os.getcwd()+'\\log\\log.txt', 'a') as f:
					f.write(self.datetime.strftime('[ %Y-%m-%d %H:%M:%S ]\t\t') + "%-70s" % ('[' + javaName.split('\\')[-1] + ']') + "%-20s" % '자바 설치.' + '\n')
				self.javaFrame()
			elif self.checkFrame == 1:
				if self.javaCheck:
					if self.pathStr.get() == '':
						tomcatName = os.getcwd() + '\\pkg\\apache-tomcat-8.5.35.exe'
					else:
						tomcatName = self.pathStr.get()
					subprocess.check_call(tomcatName, shell=True)
					self.buttonNext.config(state=NORMAL)
					self.Percent.config(text='톰캣 설치 완료')
					with open(os.getcwd()+'\\log\\log.txt', 'a') as f:
						f.write(self.datetime.strftime('[ %Y-%m-%d %H:%M:%S ]\t\t') + "%-70s" % ('[' + tomcatName.split('\\')[-1] + ']') + "%-20s" % '톰캣 설치.' + '\n')
					self.tomcatFrame()
				else:
					self.installJavaCheck = messagebox.askyesno('설치', '자바가 설치되어 있지 않습니다.\n자바를 먼저 설치하시겠습니까?')
					if self.installJavaCheck:
						if self.pathStr.get() == '':
							tomcatName = os.getcwd() + '\\pkg\\apache-tomcat-8.5.35.exe'
						else:
							tomcatName = self.pathStr.get()
						subprocess.check_call(os.getcwd() + '\\pkg\\jdk-8u191-windows-x64.exe', shell=True)
						subprocess.check_call(tomcatName, shell=True)
						self.buttonNext.config(state=NORMAL)
						self.Percent.config(text='톰캣 설치 완료')
						with open(os.getcwd()+'\\log\\log.txt', 'a') as f:
							f.write(self.datetime.strftime('[ %Y-%m-%d %H:%M:%S ]\t\t') + "%-70s" % ('[' + tomcatName.split('\\')[-1] + ']') + "%-20s" % '톰캣 설치.' + '\n')
						self.tomcatFrame()
					else:
						messagebox.showerror('실패', '톰캣을 설치하기 전 자바를 먼저 설치해 주세요.')
			elif self.checkFrame == 2:
				try:
					for file in self.filenames:
						self.datetime = datetime.datetime.now()
						if '.war' in file:
							if self.pathStr.get() == '':
								warName = file
							else:
								warName = self.pathStr.get()
							shutil.copy(warName, self.pathSave.get())
							with open(os.getcwd()+'\\log\\log.txt', 'a') as f:
								f.write(self.datetime.strftime('[ %Y-%m-%d %H:%M:%S ]\t\t') + "%-70s" % ('[' + warName.split('\\')[-1] + ']') + "%-20s" % 'war파일 복사.' + '\n')
					self.Percent.config(text='war파일 복사 완료')
				except FileNotFoundError:
					messagebox.showerror('실패', '복사할 경로를 선택해 주세요.')

			elif self.checkFrame == 3:
				if self.pathSave.get() != '':
					for file in self.filenames:
						self.datetime = datetime.datetime.now()
						if 'conf' == file.split('\\')[-1]:
							shutil.copytree(file, self.pathSave.get()+'\\conf')
							self.confCheck = True
							with open(os.getcwd()+'\\log\\log.txt', 'a') as f:
								f.write(self.datetime.strftime('[ %Y-%m-%d %H:%M:%S ]\t\t') + "%-70s" % ('[conf]') + "%-20s" % 'conf 복사.' + '\n')
					self.Percent.config(text='conf 복사 완료')
				else:
					messagebox.showerror('실패', '복사할 경로를 선택해 주세요.')

			elif self.checkFrame == 4:
				try:
					path = list()
					for item in self.filenames:
						if item.split('\\')[-1] in self.itemList2:
							path.append(item)
					if self.comboDBMS.get() == 'Oracle / Tibero':
						self.logWindow()
						with open(os.getcwd()+'\\login.sql', 'w') as f:
							f.write('set sqlblanklines on')
						messageList = list()
						logList = list()
						lineCount = 0
					for sqlFile in path:
						self.datetime = datetime.datetime.now()
						self.progressState.config(mode='indeterminate')
						self.progressState.start(10)
						if self.comboDBMS.get() == 'Oracle / Tibero':
							if '00.' in sqlFile.split('\\')[-1] or '01.' in sqlFile.split('\\')[-1]:
								logDB = subprocess.Popen('sqlplus '+self.user+'/'+self.password+'@'+self.host+':'+self.port+'/'+self.database+' < "'+sqlFile+'"', shell=True, stdout=subprocess.PIPE)
							else:
								logDB = subprocess.Popen('sqlplus '+self.dbuser+'/'+self.dbpw+'@'+self.host+':'+self.port+'/'+self.database+' < "'+sqlFile+'"', shell=True, stdout=subprocess.PIPE)
							try:
								count = 0
								while True:
									line = logDB.stdout.readline().rstrip().decode('cp949')
									if line == '' and logDB.poll() is not None:
										break
									if line:
										lineCount += 1
										if 'ERROR' in line:
											count += 1
										self.textLog.insert(END, line+'\n\n')
										self.textLog.see(END)
								if count > 0:
									messageList.append(sqlFile.split('\\')[-1] + '에서 ' + str(count) + '개의 에러가 발생했습니다.')
							except:
								self.progressState.config(mode='determinate')
								self.progressState.stop()
								self.logWindowFrame.destroy()
						elif self.comboDBMS.get() == 'MySQL / MariaDB':
							subprocess.check_output('mysql -h '+self.host+' -u '+self.user+' -P '+self.port+' -p '+self.database+' --password='+self.password+' < "'+sqlFile+'"', shell=True)
						elif self.comboDBMS.get() == 'MS-SQL':
							subprocess.check_output('sqlcmd -S '+self.host+','+self.port+' -i "'+sqlFile+'" -U '+self.user+' -P '+self.password+' -d '+self.database)
						with open(os.getcwd()+'\\log\\log.txt', 'a') as f:
							f.write(self.datetime.strftime('[ %Y-%m-%d %H:%M:%S ]\t\t') + "%-70s" % ('[' + sqlFile.split('\\')[-1] + ']') + "%-20s" % 'DB스크립트 실행.' + '\n')
					self.logWindowFrame.lift()
					self.buttonClose.config(state=NORMAL)
					self.textLog.config(state=DISABLED)
					self.progressState.config(mode='determinate')
					self.progressState.stop()
					self.Percent.config(text='DB 스크립트 실행 완료')
					oneLine = str()
					for msg in messageList:
						oneLine += msg
						if msg != messageList:
							oneLine += '\n'
					if oneLine != '':
						messagebox.showerror('실패', oneLine)
					# if self.confCheck:
					# 	self.configFrame()
					if lineCount != 0:
						logList.append(self.textLog.get('1.0', END))
					oneLog = str()
					for log in logList:
						oneLog += (log + '\n\n')
					with open(os.getcwd()+'\\log\\result_log.txt', 'w') as f:
						f.write(oneLog)
					self.itemList2 = list()
					self.rightItem.set(self.itemList2)
				except AttributeError:
					messagebox.showwarning('경고', '실행시킬 스크립트 파일을 선택하세요.')
					self.progressState.config(mode='determinate')
					self.progressState.stop()
		except FileExistsError:
			self.progressState.config(mode='determinate')
			self.progressState.stop()
			shutil.rmtree(self.pathSave.get()+'\\conf')
			self.installThread()
		except subprocess.CalledProcessError as e:
			self.datetime = datetime.datetime.now()
			if self.checkFrame == 4:
				self.progressState.config(mode='determinate')
				self.progressState.stop()
				messagebox.showerror('실패', '스크립트 파일 실행을 정상적으로 완료하지 못했습니다.\n다시 실행하려면 실행버튼을 눌러주세요.')
				with open(os.getcwd()+'\\log\\log.txt', 'a') as f:
					f.write(self.datetime.strftime('[ %Y-%m-%d %H:%M:%S ]\t\t') + "%-70s" % ('[' + sqlFile.split('\\')[-1] + ']') + "%-20s" % 'DB스크립트 실행 실패.' + '\n')
			else:
				messagebox.showerror('실패', '설치를 정상적으로 완료하지 못했습니다.\n다시 설치하려면 설치버튼을 눌러주세요.')
				if self.checkFrame == 0:
					with open(os.getcwd()+'\\log\\log.txt', 'a') as f:
						f.write(self.datetime.strftime('[ %Y-%m-%d %H:%M:%S ]\t\t') + "%-70s" % ('[' + javaName.split('\\')[-1] + ']') + "%-20s" % '자바 설치 실패.' + '\n')
				elif self.checkFrame == 1:
					if self.installJavaCheck:
						with open(os.getcwd()+'\\log\\log.txt', 'a') as f:
							f.write(self.datetime.strftime('[ %Y-%m-%d %H:%M:%S ]\t\t') + "%-70s" % ('[jdk-8u191-windows-x64.exe]') + "%-20s" % '자바 설치 실패.' + '\n')
					with open(os.getcwd()+'\\log\\log.txt', 'a') as f:
						f.write(self.datetime.strftime('[ %Y-%m-%d %H:%M:%S ]\t\t') + "%-70s" % ('[' + tomcatName.split('\\')[-1] + ']') + "%-20s" % '톰캣 설치 실패.' + '\n')

	def configFrame(self):
		self.confWindow = Toplevel()
		self.confWindow.title('Conf')
		self.confWindow.geometry('200x140+200+200')
		self.confWindow.resizable(False, False)

		frame_C1 = Frame(self.confWindow)
		frame_C1.pack(fill=X, padx=10, pady=(10,0))
		labelAddr = Label(frame_C1, text='USER')
		labelAddr.pack(side=LEFT, padx=5, pady=10)
		self.dbuserEntry = ttk.Entry(frame_C1, width=15)
		self.dbuserEntry.pack(side=RIGHT, expand=False, padx=(0,5))

	# User info.
		frameC2 = Frame(self.confWindow)
		frameC2.pack(fill=X, padx=10)
		labelID = Label(frameC2, text='PW')
		labelID.pack(side=LEFT, padx=5, pady=10)
		self.dbpwEntry = ttk.Entry(frameC2, width=15)
		self.dbpwEntry.pack(side=RIGHT, expand=False, padx=(0,5))

	# Connect button.
		frameC3 = Frame(self.confWindow)
		frameC3.pack(fill=X, padx=10)
		buttonConnectSave = ttk.Button(frameC3, text='입력 완료', width=21, command=self.configFunction)
		buttonConnectSave.pack(side=RIGHT, padx=5)

	def configFunction(self):
		self.dbuser = self.dbuserEntry.get()
		self.dbpw = self.dbpwEntry.get()
		if self.confCheck:
			count = 0
			stringFile = str()
			with open(self.pathSave.get()+'\\conf\\jdbc.conf', 'r', encoding='UTF8') as f:
				while True:
					line = f.readline()
					count += 1
					if not line: break
					if count in [14, 15, 16, 17, 18, 19]:
						if count == 14:
							stringFile += 'dbtype=oracle\ndbaddr=' + self.host + '\ndbport=' + self.port + '\nsid=' + self.database + '\ndbuser=' + self.dbuser + '\ndbpwd=' + self.dbpw + '\n'
						continue
					else:
						stringFile += line
			with open(self.pathSave.get()+'\\conf\\jdbc.conf', 'w', encoding='UTF8') as f:
				f.write(stringFile)
		self.confWindow.destroy()

	def logWindow(self):
		self.logWindowFrame = Toplevel()
		self.logWindowFrame.title('DataBase')
		self.logWindowFrame.geometry('600x400+755+100')
		self.logWindowFrame.resizable(False, False)
		label = Label(self.logWindowFrame, text='진행상황')
		label.pack(anchor=NW, padx=5, pady=10)
		frame = Frame(self.logWindowFrame)
		frame.pack()
		scrollbar = Scrollbar(frame)
		scrollbar.pack(side=RIGHT, fill=Y)
		self.textLog = Text(frame)
		self.textLog.pack(fill=BOTH, expand=True, padx=(10,0))
		self.textLog.config(yscrollcommand=scrollbar.set)
		scrollbar.config(command=self.textLog.yview)
		self.buttonClose = ttk.Button(self.logWindowFrame, text='닫기', command=self.logWindowFrame.destroy)
		self.buttonClose.pack(anchor=SE, padx=30, pady=10)
		self.buttonClose.config(state=DISABLED)

	def mainLog(self):
		logWindow = Toplevel()
		logWindow.title('Log')
		logWindow.geometry('900x400+200+200')
		logWindow.resizable(False, False)

		frame_log = Frame(logWindow)
		frame_log.pack(fill=BOTH, padx=10, pady=10)

		scrollbar = Scrollbar(frame_log)
		scrollbar.pack(side=RIGHT, fill=Y)
		textLog = Text(frame_log)
		textLog.pack(fill=BOTH, expand=True)
		textLog.config(yscrollcommand=scrollbar.set)
		with open(os.getcwd() + '\\log\\log.txt', 'r') as f:
			lines = f.readlines()
			for line in lines:
				textLog.insert(END, line)
		textLog.config(state=DISABLED)
		scrollbar.config(command=textLog.yview)

	def cancelFunction(self):
		check = messagebox.askokcancel('종료', '프로그램을 종료하시겠습니까?')
		if check:
			self.master.destroy()

class LinuxInstaller():
	def Java(self):
		checkJava = input('자바를 설치하시겠습니까? (Y/N) : ')
		if checkJava == 'Y':
			try:
				subprocess.check_call('java -version', shell=True)
				print('자바가 이미 설치되어 있습니다.')
				self.Tomcat()
			except subprocess.CalledProcessError as e:
				filenames = os.listdir(os.getcwd()+'/pkg')
				jdkList = list()
				for filename in filenames:
					if ('jdk' in filename) and ('.tar.gz' in filename):
						fullpath = os.path.join(os.getcwd()+'/pkg', filename)
						jdkList.append(fullpath)
				if len(jdkList) == 0:
					print('자바 설치파일이 존재하지 않습니다.')
					exit()
				else:
					if len(jdkList) > 1:
						for item in jdkList:
							print(item)
						fullpath = input('위 파일 중 설치를 실행할 파일명을 입력하세요. : ')
					subprocess.check_call('tar xvzf ' + fullpath, shell=True)
					try:
						subprocess.check_call('mv ' + os.path.join(os.getcwd(), 'jdk1.* /usr/local/'), shell=True)
					except subprocess.CalledProcessError as e:
						print('자바가 이미 설치되어 있습니다.')
					with open(os.getcwd()+'/log/log.txt', 'a') as f:
						f.write(datetime.datetime.now().strftime('[ %Y-%m-%d %H:%M:%S ]\t\t') + "%-70s" % ('[/usr/local/' + fullpath.split('/')[-1] + ']') + "%-20s" % '자바 설치.' + '\n')
					self.Tomcat()
		elif checkJava == 'N':
			self.Tomcat()
		else:
			print('정확히 입력해 주세요.')
			self.Java()

	def Tomcat(self):
		checkTomcat = input('톰캣을 설치하시겠습니까? (Y/N) : ')
		if checkTomcat == 'Y':
			try:
				subprocess.check_call('java -version', shell=True)
				filenames = os.listdir(os.getcwd()+'/pkg')
				tomcatList = list()
				for filename in filenames:
					if ('apache-tomcat' in filename) and ('.tar.gz' in filename):
						fullpath = os.path.join(os.getcwd()+'/pkg', filename)
						tomcatList.append(fullpath)
				if len(tomcatList) == 0:
					print('톰캣 설치파일이 존재하지 않습니다.')
					exit()
				else:
					if len(tomcatList) > 1:
						for item in tomcatList:
							print(item)
						fullpath = input('위 파일 중 설치를 실행할 파일명을 입력하세요. : ')
					subprocess.check_call('tar xvzf ' + fullpath, shell=True)
					try:
						subprocess.check_call('mv ' + os.path.join(os.getcwd(), 'apache-tomcat* /usr/local/'), shell=True)
					except subprocess.CalledProcessError as e:
						subprocess.check_call('rm -rf ' + os.path.join(os.getcwd(), 'apache-tomcat*'), shell=True)
						print('톰캣이 이미 설치되어 있습니다.')
					with open(os.getcwd()+'/log/log.txt', 'a') as f:
						f.write(datetime.datetime.now().strftime('[ %Y-%m-%d %H:%M:%S ]\t\t') + "%-70s" % ('[/usr/local/' + fullpath.split('/')[-1] + ']') + "%-20s" % '톰캣 설치.' + '\n')
					self.War()
			except subprocess.CalledProcessError as e:
				print('자바를 먼저 설치하세요.')
				self.Java()
		elif checkTomcat == 'N':
			self.War()
		else:
			print('정확히 입력해 주세요.')
			self.Tomcat()

	def War(self):
		checkWar = input('war 파일을 복사하시겠습니까? (Y/N) : ')
		if checkWar == 'Y':
			checkPath = subprocess.check_output('find /usr/local -name apache-tomcat-8.5.35 -type d', shell=True)
			if checkPath == b'':
				print('톰캣을 먼저 설치하세요.')
				self.Tomcat()
			else:
				filenames = os.listdir(os.getcwd()+'/pkg')
				for file in filenames:
					if '.war' in file:
						shutil.copy(os.path.join(os.getcwd()+'/pkg', file), '/usr/local/apache-tomcat-8.5.35/webapps')
						with open(os.getcwd()+'/log/log.txt', 'a') as f:
							f.write(datetime.datetime.now().strftime('[ %Y-%m-%d %H:%M:%S ]\t\t') + "%-70s" % ('[/usr/local/apache-tomcat-8.5.35/webapps/' + file + ']') + "%-20s" % 'war파일 복사.' + '\n')
				self.Database()
		elif checkWar == 'N':
			self.Database()
		else:
			print('정확히 입력해 주세요.')
			self.War()

	def Database(self):
		checkConn = input('스크립트 파일을 실행하겠습니까? (Y/N) : ')
		if checkConn == 'Y':
			filenames = os.listdir(os.getcwd()+'/pkg')
			while True:
				checkDBMS = input('연결할 DBMS를 선택하세요. ( Oracle / MySQL / MSSQL ) : ')
				if checkDBMS == 'Oracle':
					host = input('연결할 호스트를 입력하세요. : ')
					port = input('연결할 포트를 입력하세요. : ')
					user = input('연결할 유저명을 입력하세요. : ')
					password = input('패스워드를 입력하세요. : ')
					database = input('sid를 입력하세요. : ')
					while True:
						for file in filenames:
							if '.sql' in file:
								sqlFile = os.path.join(os.getcwd()+'/pkg', file)
								print(sqlFile)
						sqlFile = input('위 DB스크립트 파일중 실행시킬 파일명을 입력하세요. (종료는 N을 입력하세요.) : ')
						if sqlFile == 'N':
							break
						try:
							subprocess.check_call('sqlplus '+user+'/'+password+'@'+host+':'+port+'/'+database+' < "'+sqlFile+'"', shell=True)
							with open(os.getcwd()+'/log/log.txt', 'a') as f:
								f.write(datetime.datetime.now().strftime('[ %Y-%m-%d %H:%M:%S ]\t\t') + "%-70s" % ('[' + sqlFile + ']') + "%-20s" % 'DB스크립트 실행.' + '\n')
						except subprocess.CalledProcessError as e:
							print('파일명을 정확히 입력하세요.')
					break
				elif checkDBMS == 'MySQL' or checkDBMS == 'MSSQL':
					host = input('연결할 호스트를 입력하세요. : ')
					port = input('연결할 포트를 입력하세요. : ')
					user = input('연결할 유저명을 입력하세요. : ')
					password = input('패스워드를 입력하세요. : ')
					database = input('연결할 database를 입력하세요. : ')
					while True:
						for file in filenames:
							if '.sql' in file:
								sqlFile = os.path.join(os.getcwd()+'/pkg', file)
								print(sqlFile)
						sqlFile = input('위 DB스크립트 파일중 실행시킬 파일명을 입력하세요. (종료는 N을 입력하세요.) : ')
						if sqlFile == 'N':
							break
						try:
							if checkDBMS == 'MySQL':
								subprocess.check_call('mysql -h '+host+' -u '+user+' -P '+port+' -p '+database+' --password='+password+' < "'+sqlFile+'"', shell=True)
							elif checkDBMS == 'MSSQL':
								subprocess.check_call('sqlcmd -S '+host+','+port+' -i "'+sqlFile+'" -U '+user+' -P '+password+' -d '+database)
							with open(os.getcwd()+'/log/log.txt', 'a') as f:
								f.write(datetime.datetime.now().strftime('[ %Y-%m-%d %H:%M:%S ]\t\t') + "%-70s" % ('[' + sqlFile + ']') + "%-20s" % 'DB스크립트 실행.' + '\n')
						except subprocess.CalledProcessError as e:
							print('파일명을 정확히 입력하세요.')
					break
				else:
					print('정확히 입력해 주세요.')
			self.End()
		elif checkConn == 'N':
			self.End()
		else:
			print('정확히 입력해 주세요.')
			self.Database()

	def End(self):
		print('프로그램을 종료합니다.')

def main():
# Create window.
	if platform.system() == 'Windows':
		window = Tk()
		window.geometry('650x400+100+100')
		window.resizable(False, False)
		WindowsInstaller(window)
		window.mainloop()
	elif platform.system() == 'Linux':
		linux = LinuxInstaller()
		linux.Java()

if __name__ == '__main__':
	main()