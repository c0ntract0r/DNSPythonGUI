# DNSPythonGUI Version 1.0.0
## Description
DNSPythonGUI is a simple tool that I created for helping my organization to automate everyday DNS tasks, such as:
* adding a record to forward lookup zone
* deleting a record from forward lookup zone
* Adding a PTR
* Deleting a PTR


On the first run the program asks the user to input the password of a user with required priveleges to connect to the DNS server. Upon submitting the password, a request is sent with "dummy" powershell script to check for authentication. If the password is true, then the password is encrypted with symmetric encryption, using the ```cryptography``` module. 2 byte files are created: one storing the password, the other one the key and the ```Toplevel``` This is not the best secure option, but for me it was sufficient. The key should be stored somewhere safe.
Every other time upon launching the program, the key is automatically read from a location and the password is decrypted.
For every operation a hostname and a IP address is needed, except when deleting the PTR record. You do not need to enter FQDN when adding a PTR, because it is already being automatically formatted in the cmdlet.

## Requirements
* cryptography
* pypsrp

## Discussion
This is one of my first projects ever. If you have run into a bug(which I am sure here is a lot), or you have suggestions, please let me know about it in the [issue tracker page.](https://github.com/c0ntract0r/DNSPythonGUI/issues)
