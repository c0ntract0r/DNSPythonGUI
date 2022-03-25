import tkinter as tk
from tkinter import ttk
from pypsrp.client import Client
from cryptography.fernet import Fernet
import os
import pypsrp


# BACKEND


# Generating the key
def KeyGen(password):
    key = Fernet.generate_key()
    keyObj = Fernet(key)
    keyFile = open("KEY", "wb")
    token = keyObj.encrypt(password)
    fooVar = open("PASSWORD", "wb")
    varToken = fooVar.write(token)
    keyFile.write(key)
    keyFile.close()
    fooVar.close()

# Sending the dummy connection
def GetChildButton():
    thePassword = passwordEntry.get()
    client = Client(SERVERNAME, ssl = False, username = USERNAME, password = thePassword)
    power = """"""
    boolVal = False
    try:
        client.execute_ps(power)
        boolVal = True
        KeyGen(bytes(thePassword, 'UTF-8'))
        childWindow.destroy()
        winMain.deiconify()
    except pypsrp.exceptions.AuthenticationError as e:
        boolVal = False
    if boolVal == False:
        failureWindow = tk.Toplevel(winMain)
        failureWindow.geometry("200x200")
        failureWindow.resizable(False, False)
        tk.Label(failureWindow, text = "Password is incorrect", anchor = "center").grid()
        ttk.Button(failureWindow, text = 'Okay', command = failureWindow.destroy).grid()
        childWindow.protocol("WM_DELETE_WINDOW", winMain.destroy)
        failureWindow.protocol("WM_DELETE_WINDOW", winMain.destroy)

# Deleting a record from the default $zone
def DelRecFunction(InputName, inputIp, zoneName):
    keyFile = open("KEY", "rb")
    passFile = open("PASSWORD", "rb")
    keyObj = Fernet(keyFile.read())
    passDec = (keyObj.decrypt(passFile.read())).decode("utf-8")
    with Client(SERVERNAME, ssl = False, username = USERNAME, password = passDec) as client:
        powershell_script = """Remove-DnsServerResourceRecord -ZoneName "{}" -RRtype "A" -Name "{}" -RecordData "{}" -PassThru -Force""".format(zoneName, InputName.strip(), inputIp.strip())
        output, stream, had_errors = client.execute_ps(powershell_script)
    passFile.close()
    keyFile.close()

# Adding a record to the default $zone
def AddRecFunction(InputName, inputIp, zoneName):
    keyFile = open("KEY", "rb")
    passFile = open("PASSWORD", "rb")
    keyObj = Fernet(keyFile.read())
    passDec = (keyObj.decrypt(passFile.read())).decode("utf-8")
    with Client(SERVERNAME, ssl = False, username = USERNAME, password = passDec) as client:
        powershell_script = """Add-DnsServerResourceRecordA -Name "{}" -ZoneName "{}" -AllowUpdateAny -IPv4Address "{}" -PassThru""".format(InputName.strip(), zoneName, inputIp.strip())
        output, stream, had_errors = client.execute_ps(powershell_script)
    passFile.close()
    keyFile.close()

# Adding a PTR record to the default $zone
def AddPTRFunction(inputIp, revZoneName, inputName):
    keyFile = open("KEY", "rb")
    passFile = open("PASSWORD", "rb")
    keyObj = Fernet(keyFile.read())
    passDec = (keyObj.decrypt(passFile.read())).decode("utf-8")
    with Client(SERVERNAME, ssl = False, username = USERNAME, password= passDec) as client:
        inputIp = inputIp.split(".")[3]
        powershell_script = """Add-DnsServerResourceRecordPtr -Name "{}" -ZoneName "{}" -PtrDomainName "{}.testzone.com" -AllowUpdateAny""".format(inputIp, revZoneName, inputName)
        output, stream, had_errors = client.execute_ps(powershell_script)
    passFile.close()
    keyFile.close()

def DelPTRFunction(inputIp, revZoneName):
    keyFile = open("KEY", "rb")
    passFile = open("PASSWORD", "rb")
    keyObj = Fernet(keyFile.read())
    passDec = (keyObj.decrypt(passFile.read())).decode("utf-8")
    with Client(SERVERNAME, ssl = False, username = USERNAME, password= passDec) as client:
        inputIp = inputIp.split(".")[3]
        powershell_script = """Remove-DnsServerResourceRecord -ZoneName "{}" -RRType "Ptr" -Name "{}" -Force""".format(revZoneName, inputIp)
    passFile.close()
    keyFile.close()

# (Main) callback function, if the user has confirmed
def callbackFunc():
    if combo.get() == "Delete a record":
        userInputName = name.get()
        userInputIP = ipAddr.get()
        DelRecFunction(userInputName, userInputIP, zone)
        successWindow = tk.Toplevel(winMain)
        successWindow.geometry("250x250")
        successWindow.resizable(False, False)
        successLabel = tk.Label(successWindow, text = "Record Deleted")
        successLabel.grid()
        ttk.Button(successWindow, text = "okay", command = successWindow.destroy).grid()
    elif combo.get() == "Add a Record":
        userInputName = name.get()
        userInputIP = ipAddr.get()
        AddRecFunction(userInputName, userInputIP, zone)
        successWindow = tk.Toplevel(winMain)
        successWindow.geometry("250x250")
        successWindow.resizable(False, False)
        successLabel = tk.Label(successWindow, text = "Record Added")
        successLabel.grid()
        ttk.Button(successWindow, text = "okay", command = successWindow.destroy).grid()
    elif combo.get() == "Add a PTR record":
        userInputName = name.get()
        userInputIP = ipAddr.get()
        AddPTRFunction(userInputIP, revZone, userInputName)
        successWindow = tk.Toplevel(winMain)
        successWindow.geometry("250x250")
        successWindow.resizable(False, False)
        successLabel = tk.Label(successWindow, text = "PTR Record Added")
        successLabel.grid()
        ttk.Button(successWindow, text = "okay", command = successWindow.destroy).grid()
    elif combo.get() == "Delete a PTR Record":
        userInputIP = ipAddr.get()
        DelPTRFunction(userInputIP, revZone)
        successWindow = tk.Toplevel(winMain)
        successWindow.geometry("250x250")
        successWindow.resizable(False, False)
        successLabel = tk.Label(successWindow, text = "PTR Record Deleted")
        successLabel.grid()
        

# USER INTERFACE(FRONT END)




# Main Windows Creation
winMain = tk.Tk()
winMain.title('DNS Windows Server record manipulation tool')
initX = 520
initY = 600
winMain.geometry("{}x{}+700+100".format(initX, initY))
winMain.resizable(False, False)
userChoises = ("Add a Record", "Delete a record", "Add a PTR record", "Delete a PTR Record")
zone = "example.com"
# revZone = "200.168.192.in-addr.arpa"





# Label Widgets creation
desciption = tk.Label(winMain, text = 'DNS Manipulation program',
                      font = ('Arial', 30, 'bold'),
                      anchor = 'center'
                      )
creation = tk.Label(winMain, text = 'Created by c0ntract0r(Version 1.0.0, Open-Source Version)',
                      font = ('Arial', 15, 'italic')
)
comboChoice = tk.Label(winMain, text = 'Choose an option:')
DnsName = tk.Label(winMain, text = 'Hostname:')
ipAddrName = tk.Label(winMain, text = 'IP Address associated with DNS:')

# Entry Widget Creation
name = tk.Entry(winMain, width = 23)
ipAddr = tk.Entry(winMain, width = 23)

# Combobox Creation, readonly
combo = ttk.Combobox(winMain, values = userChoises, state = "readonly")
combo.current(0)

# confirmation button create
confirmButton = ttk.Button(winMain, text = 'Confirm', command = callbackFunc)

desciption.grid()
creation.grid()
DnsName.grid()
name.grid()
ipAddrName.grid()
ipAddr.grid()
comboChoice.grid()
combo.grid()
confirmButton.grid()

# Constructing the main logic of the program
if not os.path.exists("KEY"):
    if os.path.exists("PASSWORD"):
        keyFile = open("PASSWORD", "wb")
        keyFile.close()
    # Main Child Window definitions
    winMain.withdraw()
    childWindow = tk.Toplevel(winMain)
    childWindow.geometry("250x250")
    childWindow.resizable(False, False)
    childWindow.title("First time run")
    # Label widget creation
    greetingLabel = tk.Label(childWindow, text = "This is your first time running this program.")
    passwordLabel = tk.Label(childWindow, text = "Enter the correct password:")
    # Entry widget creation
    passwordEntry = tk.Entry(childWindow, show = "*", width = 20)
    # Confirmation button creation
    confirmChildButton = ttk.Button(childWindow, text = 'Confirm', command = GetChildButton)
    childWindow.bind('<Return>', lambda event: GetChildButton())
    # Grid all of the above things
    greetingLabel.grid()
    passwordLabel.grid()
    passwordEntry.grid()
    confirmChildButton.grid()

# EOP
winMain.mainloop()
