import subprocess, os, shutil, threading
class Execute:
	def __init__(self, data):
		self.data = data

	def sortFilename(self, dirname):
		filenames = os.listdir(dirname)
		self.sortedList = list()
		for item in filenames:
		    if 'jdk' in item:
		        self.sortedList.append((0, os.path.join(dirname, item)))
		    elif 'apache-tomcat' in item:
		        self.sortedList.append((1, os.path.join(dirname, item)))
		    elif '.war' in item:
		        self.sortedList.append((2, os.path.join(dirname, item)))
		    else:
		    	self.sortedList.append((3, os.path.join(dirname, item)))
		self.sortedList.sort(key = lambda element : element[0])

	def installFunction(self, intVar, keys, labelProgress):
		self.labelProgress = labelProgress
		for path in self.sortedList:
			baseName = os.path.basename(path[1])
			if intVar[baseName].get():
				self.exeThread(path)

	def exeThread(self, path):
		self.path = path
		self.colorCheck = True
		try:
			if path[0] == 0:
				self.checkJAVA()
				if self.javaColorCheck:
					self.labelProgress[os.path.basename(path[1])].config(bg='SpringGreen4', fg='WHITE')
				else:
					self.labelProgress[os.path.basename(path[1])].config(bg='STEEL BLUE', fg='WHITE')
			elif path[0] == 1:
				self.checkTomCat()
				if self.tomcatColorCheck:
					self.labelProgress[os.path.basename(path[1])].config(bg='SpringGreen4', fg='WHITE')
				else:
					self.labelProgress[os.path.basename(path[1])].config(bg='STEEL BLUE', fg='WHITE')
			elif path[0] == 2:
				self.checkTomCat()
				check = False
				for root, dirs, files in os.walk('C:\\Program Files'):
					for dir in dirs:
						if 'webapps' in dir:
							shutil.copy(path[1], root+'\\'+dir)
							check = True
							self.labelProgress[os.path.basename(path[1])].config(bg='STEEL BLUE', fg='WHITE')
				if not check:
					raise subprocess.CalledProcessError(1602, path[1])
			else:
				subprocess.check_call(path[1], shell=True)
				self.labelProgress[os.path.basename(path[1])].config(bg='STEEL BLUE', fg='WHITE')
		except subprocess.CalledProcessError as e:
			self.labelProgress[os.path.basename(path[1])].config(bg='INDIAN RED', fg='WHITE')

	def checkJAVA(self):
		if 'Java' in os.listdir('C:\\Program Files'):
			files = os.listdir('C:\\Program Files\\Java')
			if not files:
				subprocess.check_call(os.getcwd() + '\\pkg\\jdk-8u191-windows-x64.exe', shell=True)
				self.javaColorCheck = False
			else:
				for file in files:
					if 'jdk' not in file:
						subprocess.check_call(os.getcwd() + '\\pkg\\jdk-8u191-windows-x64.exe', shell=True)
						self.javaColorCheck = False
					else:
						if self.path[0] == 0:
							self.javaColorCheck = True
						break
		else:
			subprocess.check_call(os.getcwd() + '\\pkg\\jdk-8u191-windows-x64.exe', shell=True)
			self.javaColorCheck = False

	def checkTomCat(self):
		self.checkJAVA()
		if 'Apache Software Foundation' in os.listdir('C:\\Program Files'):
			files = os.listdir('C:\\Program Files\\Apache Software Foundation')
			if not files:
				subprocess.check_call(os.getcwd() + '\\pkg\\apache-tomcat-7.0.91.exe', shell=True)
				self.tomcatColorCheck = False
			else:
				for file in files:
					if 'Tomcat' not in file:
						subprocess.check_call(os.getcwd() + '\\pkg\\apache-tomcat-7.0.91.exe', shell=True)
						self.tomcatColorCheck = False
					else:
						if self.path[0] == 1:
							self.tomcatColorCheck = True
						break
		else:
			subprocess.check_call(os.getcwd() + '\\pkg\\apache-tomcat-7.0.91.exe', shell=True)
			self.tomcatColorCheck = False