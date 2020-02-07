from tkinter import *
import tkinter as tk
import subprocess
import time
import os
import nmap
import sys


def menuselect():
    for x in lb.curselection():
        if x == 0:
            popup0 = Toplevel()
            lis0 = Listbox(popup0, selectmode=SINGLE, height=5, width=20)
            for x in machineip():
                n = 0
                lis0.insert(n, x)
                n+=1
            lis0.pack()
            popup0.mainloop()
            
        if x == 1:
            n = 0
            popup1 = Toplevel()
            listbox1frame = Frame(popup1)
            pscroll1 = Scrollbar(popup1)
            pscroll1.pack(side=RIGHT, fill=Y)
            lis1 = Listbox(listbox1frame, selectmode=SINGLE, yscrollcommand=pscroll1.set, height=10, width=20)
            for x in enumnetwork():
                lis1.insert(n, x)
                n+=1
            lis1.pack()
            listbox1frame.pack()
            pscroll1.configure(command=lis1.yview)
            popup1.mainloop()   
            
        if x == 2:            
            popup2 = Toplevel()
            pscroll2 = Scrollbar(popup2)
            pscroll2.pack(side=RIGHT, fill=Y)
            textbox2frame = Frame(popup2)
            text2 = Text(textbox2frame, wrap=NONE, yscrollcommand=pscroll2.set, height=40, width=100)
            pscroll2.configure(command=text2.yview)
            for x in enumnetwork():
               result = scanip(x)
               text2.insert("1.0", result)
            text2.pack(side="left")
            textbox2frame.pack()
            pscroll2.configure(command=text2.yview)
            popup2.mainloop()
        
        if x == 3:
            popup3 = Toplevel()    
            lbl3 = Label(popup3, text="Select an IP to scan")
            listbox3frame = Frame(popup3)
            textbox3frame = Frame(popup3)
            pscroll3 = Scrollbar(listbox3frame)
            pscroll32 = Scrollbar(textbox3frame)
            pscroll3.pack(side=RIGHT, fill=Y)
            pscroll32.pack(side=RIGHT, fill=Y)
            listbox3 = Listbox(listbox3frame, selectmode=SINGLE, yscrollcommand=pscroll3.set, height=10, width=20)
            text3 = Text(textbox3frame, wrap=NONE, yscrollcommand=pscroll32.set, height=20, width=60)
            n = 0
            for x in enumnetwork():                
                listbox3.insert(n, x)
                n+=1
            btn3 = Button(popup3, text="Submit", command=lambda : scanselectip(text3, listbox3))
            pscroll3.configure(command=listbox3.yview)
            pscroll32.configure(command=text3.yview)
            lbl3.pack()
            listbox3frame.pack()
            textbox3frame.pack()
            listbox3.pack()
            text3.pack()
            btn3.pack()
            popup3.mainloop()
                            
        if x == 4:
            window.destroy()
            sys.exit(1)
            

def discover(text, listname):
    start = -1
    locs = []
    while True:
        try:
            loc = listname.index(text, start+1)
        except ValueError:
            break
        else:
            locs.append(loc)
            start = loc
    return locs


def enumnetwork():
    nm = nmap.PortScanner()
    for x in machineip():
        nm.scan(x, arguments="-sP")
        hosts = nm.all_hosts()
    return hosts
        

def verifyconnection():
    cmd = "ip addr | grep 'state UP' -A2"
    status = os.system(cmd)
    if status < 256:
        lbl2.config(fg='black')
        constat.set("Connected")
        return True
    else:
        lbl2.config(fg='red')
        constat.set("Not Connected")
        return False


def machineip():
    process = subprocess.Popen(['ip', 'addr'], stdout=subprocess.PIPE, universal_newlines=True)
    l = str(process.communicate())
    ls = l.split()    
    srch = "inet"
    iploc = discover(srch, ls)    
    i = []
    for x in iploc:
        i.append(ls[int(x+1)])
        if "127.0.0.1/8" in i:
            i.remove("127.0.0.1/8")        
    return i


def scanip(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, '1-65535')
    scanip = nm.csv().replace(";", " ")
    return scanip
        

def scanselectip(textwidget, listbox):
    lbsel = str()
    for x in listbox.curselection():
        lbsel = listbox.get(x)
    nm = nmap.PortScanner()
    nm.scan(lbsel, '1-65535')
    result = nm.csv().replace(";", " ")
    textwidget.insert("1.0", result) 
    

def findscripts():
    scriptlist = []
    for root, dirs, files in os.walk('/usr/share/nmap/scripts/'):
        for name in files:
            scriptlist.append(name)
    return sorted(scriptlist)    
    

def scriptscan(listbox1, listbox2, textwidget):
    for x in listbox1.curselection():
        lbsel1 = listbox1.get(x)
    for y in listbox2.curselection():
        lbsel2 = listbox2.get(y)
    nm = nmap.PortScanner()
    nm.scan(lbsel1, '1-65535', arguments='--script=%s' % lbsel2)
    result = nm.csv().replace(";", " ")
    textwidget.insert("1.0", result)    
    

def nmapcheck():
    try:
        import nmap
        return True
    except ImportError:
        return False


def buttoncheck():
    if nmapcheck() and verifyconnection():
        btn['state'] = NORMAL
    else:
        btn['state'] = DISABLED
        

#Main Loop


window = Tk()
window.title("pyScan")
window.geometry('%sx%s' % (window.winfo_screenwidth(), window.winfo_screenheight()))

constat = StringVar()
syscheck = StringVar()

lbl = Label(window, text="Select an Action")
lbl2 = Label(window, textvariable=constat)
lbl3 = Label(window, textvariable=syscheck)
lb = Listbox(window, selectmode=SINGLE, height=7, width=55)
lb.insert(0, "Display current machine's IP")
lb.insert(1, "Enumerate all IPs on local subnet")
lb.insert(2, "Scan ports & enumerate OS/services on entire local subnet")
lb.insert(3, "Scan ports & enumerate OS/services on local device IP")
lb.insert(4, "Exit")
btn = Button(window, text="Submit", command=menuselect, state=DISABLED)
btn2 = Button(window, text="Verify Connection & nmap", command=buttoncheck)

if verifyconnection():
    lbl2.config(fg='black')
    constat.set("Connected")
else:
    lbl2.config(fg='red')
    constat.set("Not Connected")
if nmapcheck():
    lbl3.config(fg='black')
    syscheck.set("Nmap Module Found")
    btn['state'] = NORMAL
else:
    lbl3.config(fg='red')
    syscheck.set("Nmap Module NOT Found. Install with 'pip install python3-nmap'")
    btn['state'] = DISABLED
  
lbl2.pack()
lbl3.pack()
lbl.pack()
lb.pack()
btn.pack()
btn2.pack()
window.mainloop()
