

# MalEvol: Multi-faceted malware infection characterization
MalEvol is an analysis pipeline that accepts a web-borne malware infection network capture and dissects the infection by analyzing HTTP conversations.
Given a PCAP of a malware infection (suspicious traffic), MalEvol leverages an HTTP replay engine to sift throught HTTP conversation transactions and extract:

- Enticement evidence (if the referrer field is non-empty)
- Redirection chain
- Fingerprinting evidence
- Exploitation evidence



## Requirements Installation

- Python 3: Used to run MalEvol.py
- `pip3 install -r requirements.txt`
- Python 2: Used to run CapTipper.py
- Make sure that the python2 command in your variable environment is "python2"


### Clone

- Clone this repo to your local machine using `https://github.com/um-dsp/MalEvol.git`

### Setup

> Create two folders "dumps" and "reports" and
> Drop your "PCAP" files in the floder "pcaps"
> run `python MalEvol.py <your-pcap-file>`  (python3)

### Note
MalEvol manages malicious files. In order to use it, you need to disable any real-time anti-malware protection your OS provides.
Please note that using MalEvol for a malicious pcap analysis might harm your machine.

### Example 1
> run `python MalEvol.py 2014-11-06-Nuclear-EK-traffic.pcap`
![picture1](https://github.com/um-dsp/MalEvol/blob/master/example.PNG)

### Example 2
This example shows the geographical analysis results of the redirection chain.
> run `python MalEvol.py pcap21.pcap`

![picture2](https://github.com/um-dsp/MalEvol/blob/master/gro.PNG)

