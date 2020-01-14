from tkinter import *
import subprocess
import time
import os
import nmap
import sys

def menuselect():
    for x in lb.curselection():
        if x == 0:
            popup0 = Toplevel()
            lis0 = Listbox(popup0, selectmode=SINGLE, height=len(machineip()), width=20)
            for x in machineip():
                n = 0
                lis0.insert(n, x)
                n+=1
            lis0.pack()
            popup0.mainloop()
            
        if x == 1:
            popup1 = Toplevel()
            lis1 = Listbox(popup1, selectmode=SINGLE, height=10, width=20)
            for x in enumnetwork():
                n = 0
                lis1.insert(n, x)
                n+=1
            lis1.pack()
            popup1.mainloop()     
            
        if x == 2:            
            popup2 = Toplevel()
            pscroll2 = Scrollbar(popup2)
            pscroll2.pack(side=RIGHT, fill=Y)
            text2 = Text(popup2, wrap=NONE, yscrollcommand=pscroll2.set, height=40, width=100)
            for x2 in enumnetwork():
               result = scanip(x2)
               text2.insert("1.0", result)
            text2.pack(side="left")
            popup2.mainloop()
        
        if x == 3:
            popup3 = Toplevel()            
            pscroll3 = Scrollbar(popup3)
            pscroll3.pack(side=RIGHT, fill=Y)
            lbl3 = Label(popup3, text="Enter manual IP to scan")
            ipentry = Entry(popup3)
            btn3 = Button(popup3, text="Submit", command=lambda : scanselectip(ipentry, text3))
            text3 = Text(popup3, wrap=NONE, yscrollcommand=pscroll3.set, height=20, width=60)
            lbl3.pack()
            ipentry.pack()
            btn3.pack()  
            text3.pack()
            popup3.mainloop()
        
        if x == 4:
            print("Coming Soon")
            
        if x == 5:
            window.destroy()
            sys.exit(1)
            
def discover(text, listname):
    start = -1
    locs = []
    
    text
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
    if status == 0:
        constat.set("Connected")
        btn['state'] = NORMAL
    else:
        constat.set("Not Connected")
        btn['state'] = DISABLED
    return status

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
    
def test(ln):
    ip = str()
    for x in ln.curselection():
        ip = str(x)
    print(ip)
    return ip
    
def scanselectip(entry, textwidget):
    x = entry.get()
    nm = nmap.PortScanner()
    nm.scan(x, '1-65535')
    result = nm.csv().replace(";", " ")
    textwidget.insert("1.0", result) 
       
        
window = Tk()

window.title("pyScan")
window.geometry('470x270')

constat = StringVar()

lbl = Label(window, text="Select an Action")
lbl2 = Label(window, textvariable=constat)

lb = Listbox(window, selectmode=SINGLE, height=7, width=55)
lb.insert(0, "Display current machine's IP")
lb.insert(1, "Enumerate all IPs on network")
lb.insert(2, "Discover ports & enumerate OS/services on all IPs")
lb.insert(3, "Scan ports & enumerate on manual IP")
lb.insert(4, "Vulnerability scan all devices on network")
lb.insert(5, "Exit")

btn = Button(window, text="Submit", command=menuselect, state=DISABLED)
btn2 = Button(window, text="Connection Retry", command=verifyconnection)

if verifyconnection() == 0:
    constat.set("Connected")
else:
    constat.set("Not Connected")
  
lbl2.pack()
lbl.pack()
lb.pack()
btn.pack()
btn2.pack()
mainloop()

