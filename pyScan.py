from tkinter import *
import subprocess
import time
import os
import nmap

def curselect():
    if 0 in lb.curselection():
        popup = Toplevel()
        tv = StringVar()
        popupmsg = Label(popup, textvariable=tv)
        tv.set(str(machineip()))
        popupmsg.pack()
        popup.mainloop()
        
    if 2 in lb.curselection():
        popup = Toplevel()
        lis = Listbox(popup, selectmode=SINGLE, height=len(enumnetwork()), width=20)
        for x in enumnetwork():
            n = 0
            lis.insert(n, x)
            n+=1
        lis.pack()
        popup.mainloop()        
        
def discover(text, lname):
    start = -1
    locs = []
    
    text
    while True:
        try:
            loc = lname.index(text, start+1)
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

window = Tk()

window.title("pyScan")
window.geometry('470x270')

constat = StringVar()

lbl = Label(window, text="Select an Action")
lbl2 = Label(window, textvariable=constat)

lb = Listbox(window, selectmode=SINGLE, height=7, width=40)
lb.insert(0, "Display current machine's IP")
lb.insert(1, "Manual nmap command")
lb.insert(2, "Enumerate all IPs on network")
lb.insert(3, "Discover ports & enumerate OS/services on all IPs")
lb.insert(4, "Vulnerability scan all devices on network")
lb.insert(5, "Exit")

btn = Button(window, text="Submit", command=curselect, state=DISABLED)
btn2 = Button(window, text="Connection Retry", command=verifyconnection)

if verifyconnection() == 0:
    constat.set("Connected")
else:
    constat.set("Not Connected")
  
lbl.pack()
lbl2.pack()
lb.pack()
btn.pack()
btn2.pack()
mainloop()

