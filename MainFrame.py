from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog
import threading, collections, subprocess, os, sys, shutil, datetime, platform

class WindowsInstaller(Frame):
	def __init__(self, master):
		Frame.__init__(self, master)
		self.master = master
		self.master.title('New Project')
		self.pack(fill=BOTH, expand=True)

		self.mainFrame = Frame(self)
		self.mainFrame.pack(fill=BOTH, expand=True, padx=10, pady=10)

		remainFrame = Frame(self)
		remainFrame.pack(fill=X, anchor=S, padx=10, pady=(0,10))
		self.buttonInstall = ttk.Button(remainFrame, text='설치', command=self.installThread)
		self.buttonInstall.pack(anchor=NE, padx=10, pady=(0,20))
		self.Progress = ttk.Progressbar(remainFrame, orient=HORIZONTAL, mode='determinate')
		self.Progress.pack(fill=X, anchor=S, padx=20)
		self.filenames = os.listdir(os.getcwd()+'\\pkg')
		cnt = 0
		for file in self.filenames:
			if '.sql' in file:
				cnt += 1
		self.Progress.config(maximum=4)
		self.count = 0
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
		self.pathFrame = Frame(self.mainFrame)
		self.pathFrame.pack(fill=X, anchor=N, expand=True, padx=10, pady=(10,0))
		self.pathStr = StringVar()
		self.entryPath = ttk.Entry(self.pathFrame, textvariable=self.pathStr)
		self.entryPath.pack(fill=X, side=LEFT, expand=True, padx=5)
		self.entryPath.config(state=DISABLED)
		self.buttonPath = ttk.Button(self.pathFrame, text='다른경로에서 찾기', command=self.pathFunction)
		self.buttonPath.pack(side=LEFT)
		self.contentsFrame = Frame(self.mainFrame)
		self.contentsFrame.pack(fill=BOTH, expand=True, padx=10)

		self.checkFrame = 0
		self.javaFrame()

	def pathFunction(self):
		self.entryPath.config(state='readonly')
		self.pathStr.set(filedialog.askopenfilename(initialdir="/", title='Select file', filetypes=(('실행 파일', '*.exe'), ('모든 파일', '*.*'))))

	def nextFunction(self):
		self.filenames = os.listdir(os.getcwd()+'\\pkg')
		self.pathStr.set('')
		self.entryPath.config(state=DISABLED)
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
			self.buttonPath.config(state=DISABLED)
			self.buttonInstall.config(text='실행')
			self.buttonInstall.config(state=DISABLED)
			self.checkFrame = 3
			self.buttonNext.config(text='완료')
			self.dbFrame()
		elif self.checkFrame == 3:
			self.pathFrame.destroy()
			self.buttonInstall.destroy()
			self.Percent.config(text='설치 완료')
			self.lastFrame()
		self.count += 1
		self.Progress.config(value=self.count)

	def pastFunction(self):
		self.filenames = os.listdir(os.getcwd()+'\\pkg')
		self.pathStr.set('')
		self.entryPath.config(state=DISABLED)
		if self.checkFrame == 3:
			self.buttonPath.config(state=NORMAL)
			self.buttonInstall.config(text='복사')
			self.checkFrame = 2
			self.buttonNext.config(text='다음')
			self.warFrame()
		elif self.checkFrame == 2:
			self.buttonInstall.config(text='설치')
			self.checkFrame = 1
			self.buttonNext.config(state=NORMAL)
			self.tomcatFrame()
		elif self.checkFrame == 1:
			self.buttonInstall.config(text='설치')
			self.buttonPast.config(state=DISABLED)
			self.checkFrame = 0
			self.buttonNext.config(state=NORMAL)
			self.javaFrame()
		self.count -= 1
		self.Progress.config(value=self.count)

	def javaFrame(self):
		self.labelMain.config(text='자바 설치')
		self.contentsFrame.destroy()
		self.contentsFrame = Frame(self.mainFrame)
		self.contentsFrame.pack(fill=BOTH, expand=True, padx=10)
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
			message.pack(fill=X, side=LEFT)
		except subprocess.CalledProcessError as e:
			self.javaCheck = False
			message = Message(self.contentsFrame, text='자바가 설치되어 있지 않습니다.\n\n설치하려면 설치버튼을 누르세요.', width=400)
			message.pack(fill=X, side=LEFT, anchor=NW, padx=10, pady=20)

	def tomcatFrame(self):
		self.labelMain.config(text='톰캣 설치')
		self.contentsFrame.destroy()
		self.contentsFrame = Frame(self.mainFrame)
		self.contentsFrame.pack(fill=BOTH, expand=True, padx=10, pady=10)
		try:
			checkTomcat = subprocess.check_output('REG QUERY "HKLM\\SOFTWARE\\Apache Software Foundation" /s | findstr InstallPath', shell=True, universal_newlines=True)
			self.tomcatPath = list()
			for service in checkTomcat.split('\n'):
				if 'InstallPath' in service:
					self.tomcatPath.append(service.split('    ')[-1])
					labelPath = Label(self.contentsFrame, text=service.split('    ')[-1], relief=SUNKEN, bg='gray99')
					labelPath.pack(fill=X)
			message = Message(self.contentsFrame, text='위 경로에 톰캣이 설치되어 있습니다.\n\n새로 설치하려면 설치버튼을 넘어가려면 다음버튼을 누르세요.', width=400)
			message.pack(fill=X, side=LEFT)
		except subprocess.CalledProcessError as e:
			message = Message(self.contentsFrame, text='톰캣이 설치되어 있지 않습니다.\n\n설치하려면 설치버튼을 누르세요.', width=400)
			message.pack(fill=X, side=LEFT, anchor=NW, padx=10, pady=20)

	def warFrame(self):
		self.labelMain.config(text='war 파일 복사')
		self.contentsFrame.destroy()
		self.contentsFrame = Frame(self.mainFrame)
		self.contentsFrame.pack(fill=BOTH, expand=True, padx=10)
		try:
			self.comboPath = ttk.Combobox(self.contentsFrame, values=self.tomcatPath, width=400)
			self.comboPath.pack(fill=X)
			self.comboPath.config(state='readonly')
			self.comboPath.current(0)
			message = Message(self.contentsFrame, text='위 경로의 톰캣에 war파일을 복사하시겠습니까?\n\n복사하려면 복사버튼을 누르세요.', width=400)
			message.pack(fill=X, side=LEFT, anchor=NW, padx=10, pady=20)
		except AttributeError as e:
			message = Message(self.contentsFrame, text='톰캣이 설치되어 있지 않습니다.\n\nwar파일을 배포하시려면 이전버튼을 눌러 톰캣을 설치해 주세요.', width=400)
			message.pack(fill=X, side=LEFT, anchor=NW, padx=10, pady=20)

	def onselect(self, evt):
		w = evt.widget
		if self.lastselectionList:
			changeList = w.curselection()
			if len(changeList) < len(self.lastselectionList):
				for lastItem in self.lastselectionList:
					if lastItem in changeList:
						continue
					self.changedSelection.remove(lastItem)
			if len(changeList) != len(self.lastselectionList):
				for changeItem in changeList:
					if changeItem in self.changedSelection:
						continue
					self.changedSelection.append(changeItem)
			else:
				self.changedSelection = list(w.curselection())
			self.lastselectionList = w.curselection()
		else:
			self.lastselectionList = w.curselection()
			self.changedSelection = list(w.curselection())
		listStr = str()
		self.exeList = list()
		for item in self.changedSelection:
			self.exeList.append(w.get(int(item)))
			listStr += (w.get(int(item)).split('\\')[-1] + '  ')
		self.sqlList.config(text=listStr)

	def dbFrame(self):
		self.labelMain.config(text='DataBase')
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
		self.fileName = collections.OrderedDict()
		self.intVar = collections.OrderedDict()

		frameSQL = Frame(self.contentsFrame)
		scrollbar = Scrollbar(frameSQL)
		scrollbar.pack(side=RIGHT, fill=Y)
		self.lastselectionList = list()
		self.listboxSQL = Listbox(frameSQL, width=100, height=6, selectmode=EXTENDED)
		self.listboxSQL.bind('<<ListboxSelect>>', self.onselect)
		self.listboxSQL.pack(fill=X, padx=(10,0))
		self.listboxSQL.delete(0, END)
		for file in self.filenames:
		 	if '.sql' in file:
		 		self.listboxSQL.insert(END, os.path.join(os.getcwd()+'\\pkg\\', file))
		self.listboxSQL.config(yscrollcommand=scrollbar.set)
		scrollbar.config(command=self.listboxSQL.yview)
		frameSQL.pack()
		self.sqlList = Label(self.contentsFrame, text='')
		self.sqlList.pack(fill=X)
		message = Message(self.contentsFrame, text='실행하려면 실행버튼을 누르세요.', width=400)
		message.pack(fill=X, side=LEFT, anchor=NW, padx=10)

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
		self.buttonPast.destroy()
		self.buttonNext.destroy()
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
					f.write(self.datetime.strftime('[ %Y-%m-%d %H:%M:%S ]\t\t') + "%-40s" % ('[' + javaName.split('\\')[-1] + ']') + "%-20s" % '자바 설치.' + '\n')
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
						f.write(self.datetime.strftime('[ %Y-%m-%d %H:%M:%S ]\t\t') + "%-40s" % ('[' + tomcatName.split('\\')[-1] + ']') + "%-20s" % '톰캣 설치.' + '\n')
					self.tomcatFrame()
				else:
					check = messagebox.askyesno('설치', '자바가 설치되어 있지 않습니다.\n자바를 먼저 설치하시겠습니까?')
					if check:
						subprocess.check_call(os.getcwd() + '\\pkg\\jdk-8u191-windows-x64.exe', shell=True)
						if self.pathStr.get() == '':
							tomcatName = os.getcwd() + '\\pkg\\apache-tomcat-8.5.35.exe'
						else:
							tomcatName = self.pathStr.get()
						subprocess.check_call(tomcatName, shell=True)
						self.buttonNext.config(state=NORMAL)
						self.Percent.config(text='톰캣 설치 완료')
						with open(os.getcwd()+'\\log\\log.txt', 'a') as f:
							f.write(self.datetime.strftime('[ %Y-%m-%d %H:%M:%S ]\t\t') + "%-40s" % ('[' + tomcatName.split('\\')[-1] + ']') + "%-20s" % '톰캣 설치.' + '\n')
						self.tomcatFrame()
					else:
						messagebox.showerror('실패', '톰캣을 설치하기 전 자바를 먼저 설치해 주세요.')
			elif self.checkFrame == 2:
				for file in self.filenames:
					if '.war' in file:
						if self.pathStr.get() == '':
							warName = os.path.join(os.getcwd()+'\\pkg', file)
						else:
							warName = self.pathStr.get()
						shutil.copy(warName, self.comboPath.get()+'\\webapps')
						with open(os.getcwd()+'\\log\\log.txt', 'a') as f:
							f.write(self.datetime.strftime('[ %Y-%m-%d %H:%M:%S ]\t\t') + "%-40s" % ('[' + warName.split('\\')[-1] + ']') + "%-20s" % 'war파일 복사.' + '\n')
				self.Percent.config(text='war파일 복사 완료')
			elif self.checkFrame == 3:
				self.progressState.config(mode='indeterminate')
				self.progressState.start(10)
				if self.comboDBMS.get() == 'Oracle / Tibero':
					self.logWindow()
				for sqlFile in self.exeList:
					if self.comboDBMS.get() == 'Oracle / Tibero':
						logDB = subprocess.Popen('sqlplus '+self.user+'/'+self.password+'@'+self.host+':'+self.port+'/'+self.database+' < "'+sqlFile+'"', shell=True, stdout=subprocess.PIPE)
						try:
							while True:
								line = logDB.stdout.readline().rstrip().decode('cp949')
								if line == '' and logDB.poll() is not None:
									break
								if line:
									self.textLog.insert(END, line+'\n\n')
									self.textLog.see(END)
							self.buttonClose.config(state=NORMAL)
							self.textLog.config(state=DISABLED)
						except:
							self.progressState.config(mode='determinate')
							self.progressState.stop()
					elif self.comboDBMS.get() == 'MySQL / MariaDB':
						subprocess.check_output('mysql -h '+self.host+' -u '+self.user+' -P '+self.port+' -p '+self.database+' --password='+self.password+' < "'+sqlFile+'"', shell=True)
					elif self.comboDBMS.get() == 'MS-SQL':
						subprocess.check_output('sqlcmd -S '+self.host+','+self.port+' -i "'+sqlFile+'" -U '+self.user+' -P '+self.password+' -d '+self.database)
					with open(os.getcwd()+'\\log\\log.txt', 'a') as f:
						f.write(self.datetime.strftime('[ %Y-%m-%d %H:%M:%S ]\t\t') + "%-40s" % ('[' + sqlFile.split('\\')[-1] + ']') + "%-20s" % 'DB스크립트 실행.' + '\n')
				self.progressState.config(mode='determinate')
				self.progressState.stop()
				self.Percent.config(text='DB 스크립트 실행 완료')
		except subprocess.CalledProcessError as e:
			if self.checkFrame == 3:
				self.progressState.config(mode='determinate')
				self.progressState.stop()
				messagebox.showerror('실패', '스크립트 파일 실행을 정상적으로 완료하지 못했습니다.\n다시 실행하려면 실행버튼을 눌러주세요.')
				with open(os.getcwd()+'\\log\\log.txt', 'a') as f:
					f.write(self.datetime.strftime('[ %Y-%m-%d %H:%M:%S ]\t\t') + "%-40s" % ('[' + sqlFile.split('\\')[-1] + ']') + "%-20s" % 'DB스크립트 실행 실패.' + '\n')
			else:
				messagebox.showerror('실패', '설치를 정상적으로 완료하지 못했습니다.\n다시 설치하려면 설치버튼을 눌러주세요.')
				if self.checkFrame == 0:
					with open(os.getcwd()+'\\log\\log.txt', 'a') as f:
						f.write(self.datetime.strftime('[ %Y-%m-%d %H:%M:%S ]\t\t') + "%-40s" % ('[' + javaName.split('\\')[-1] + ']') + "%-20s" % '자바 설치 실패.' + '\n')
				elif self.checkFrame == 1:
					with open(os.getcwd()+'\\log\\log.txt', 'a') as f:
						f.write(self.datetime.strftime('[ %Y-%m-%d %H:%M:%S ]\t\t') + "%-40s" % ('[' + tomcatName.split('\\')[-1] + ']') + "%-20s" % '톰캣 설치 실패.' + '\n')

	def logWindow(self):
		self.logWindowFrame = Toplevel()
		self.logWindowFrame.title('DataBase')
		self.logWindowFrame.geometry('600x400+200+200')
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
		logWindow.geometry('700x400+200+200')
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
		# exit()

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