

# MalEvol: Multi-faceted malware infection characterization
MalEvol is an analysis pipeline that accepts a web-borne malware infection network capturein a form of PCAP/PCAPNG and dissects the infection by analyzing HTTP conversations.
Given a PCAP of a malware infection (suspicious traffic), MalEvol leverages [CapTipper](https://github.com/omriher/CapTipper) HTTP replay engine to sift through HTTP conversation transactions so as to enable security analysts identify potential threats in the infection capture. MalEvol has the following analysis components (which we call gadgets):

- Enticement Gadget
- Redirection Chain Gadget
- Fingerprinting Gadget
- Exploitation Gadget

For all potentially malicious artifacts, MalEvol leverages real-time detection results from [VirusTotal](https://www.virustotal.com/gui/) to score each artifact for maliciousness. In addition, MalEvol also exracts IOCs and searches for them in [APT reports](https://github.com/aptnotes/data) to correlate IOCs in the infection traffic under analysis and APT artifacts released over the years.





## Requirements Installation

- Python 3: Used to run MalEvol.py
- `pip3 install -r requirements.txt`
- Python 2: Used to run CapTipper.py
- Make sure that the python2 command in your variable environment is "python2"


### Clone

- Clone this repo to your local machine using `git clone https://github.com/um-dsp/MalEvol.git`

### Setup

> Under the MalEvol directory, create two directories named "dumps" and "reports"
> Drop your .pcap or .pcapng files in the floder "pcaps"
> run `python MalEvol.py <your-pcap-file>` (python3)

### Note
MalEvol manages malicious files. In order to use it, you need to disable any real-time anti-malware protection your OS provides.
Please note that using MalEvol for a malicious pcap analysis might is not intended for production/commercial purpose, but rather for educational and research only.

### Example 1
> run `python MalEvol.py 2014-11-06-Nuclear-EK-traffic.pcap`
![picture1](https://github.com/um-dsp/MalEvol/blob/master/example.PNG)

### Example 2
This example shows the geo-location analysis results of the redirection chain.
> run `python MalEvol.py pcap21.pcap`

![picture2](https://github.com/um-dsp/MalEvol/blob/master/gro.PNG)

