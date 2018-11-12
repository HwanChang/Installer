from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog

import threading, collections, Execute, subprocess, os, sys

class MainFrame(Frame):
	def __init__(self, master):
		Frame.__init__(self, master)
		self.master = master
		self.master.title('New Project')
		self.pack(fill=BOTH, expand=True)

		self.data = collections.OrderedDict()
		self.failList = list()

		self.data['status'] = Label(self, text='', bd=1, relief=SUNKEN, anchor=E)
		self.data['status'].pack(side=BOTTOM, fill=X)

		self.mainFrame = Frame(self)
		self.mainFrame.pack(fill=BOTH, expand=1, padx=10, pady=10)

		labelMain = Label(self.mainFrame, text='설치 목록')
		labelMain.pack(anchor=NW)

		self.contentsFrame = Frame(self.mainFrame, relief=SUNKEN, border=2, bg='gray99')
		self.contentsFrame.pack(fill=BOTH, expand=True, padx=10, pady=10)

		self.execute = Execute.Execute(self.data)
		self.execute.sortFilename(os.getcwd() + '\\pkg')

		fileName = collections.OrderedDict()
		self.intVar = collections.OrderedDict()
		for file in self.execute.sortedList:
			baseName = os.path.basename(file[1])
			self.intVar[baseName] = IntVar()
			fileName[baseName] = Checkbutton(self.contentsFrame, text=baseName, variable=self.intVar[baseName], bg='gray99')
			fileName[baseName].pack(anchor=W, padx=10)

		buttonCancel = ttk.Button(self.mainFrame, text='취소', command=self.cancelFunction)
		buttonCancel.pack(side=RIGHT, padx=(5,10), pady=10)
		buttonNext = ttk.Button(self.mainFrame, text='다음', command=self.installFrame)
		buttonNext.pack(side=RIGHT, padx=5, pady=10)

	def installFrame(self):
		check = False
		for install in self.execute.sortedList:
			baseName = os.path.basename(install[1])
			if self.intVar[baseName].get():
				check = True
		if check:
			self.installFrame = Toplevel()
			self.installFrame.title('Install')
			self.installFrame.geometry('350x300+200+200')
			self.installFrame.resizable(False, False)

			frame = Frame(self.installFrame)
			frame.pack(fill=BOTH, padx=10, pady=5, expand=True)
			self.labelProgress = collections.OrderedDict()
			for install in self.execute.sortedList:
				baseName = os.path.basename(install[1])
				if self.intVar[baseName].get():
					self.labelProgress[baseName] = Label(frame, text=baseName, height=2, relief=RAISED, bg='LIGHT GREY')
					self.labelProgress[baseName].pack(fill=X, pady=10)
			buttonNext = ttk.Button(frame, text='설치', command=self.installThread)
			buttonNext.pack(side=BOTTOM, anchor=E, padx=5, pady=10)
		else:
			pass

	def installThread(self):
		installTh = threading.Thread(target=self.execute.installFunction, args=(self.intVar, list(self.labelProgress.keys()), self.labelProgress))
		installTh.start()

	def cancelFunction(self):
		check = messagebox.askokcancel('종료', '프로그램을 종료하시겠습니까?')
		if check:
			self.master.destroy()

def main():
# Create window.
	window = Tk()
	window.geometry('500x300+100+100')
	window.resizable(False, False)
	MainFrame(window)
	window.mainloop()

if __name__ == '__main__':
	main()