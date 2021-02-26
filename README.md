

# MalEvol: Multi-faceted Malware Infection Traffic Characterization

MalEvol is an analysis pipeline that accepts a web-borne malware infection network capture (.PCAP or .PCAPNG) and dissects it by analyzing HTTP conversations.
Given a PCAP of a malware infection (suspicious traffic), MalEvol leverages the [CapTipper](https://github.com/omriher/CapTipper) HTTP replay engine to sift through HTTP conversation transactions so as to enable security analysts quickly identify potential threats (e.g., exploit kits, ransomware) across multiple dimensions such as redirections, fingerpringing, and actual exploitation indicators and participants (e.g., malware payload servers). 

For potentially malicious artifacts it identifies, MalEvol leverages real-time detection results from [VirusTotal](https://www.virustotal.com/gui/) to score each artifact for maliciousness. In addition, MalEvol also automatically exracts IOCs from the given infection capture and searches for them in [APT reports](https://github.com/aptnotes/data) to correlate IOCs in the infection traffic under analysis and APT artifacts released over the years. 

MalEvol has the following major analysis components which we call gadgets:

- Enticement source identification
- Redirection chain extraction
- Fingerprinting
- Exploitation details
- Geo-location of participating hosts/IP addresses


## Installation Requirements 

- Python 3: Used to run MalEvol.py
- `pip3 install -r requirements.txt`
- Python 2: Used to invoke CapTipper.py from within MalEvol
- Make sure that the python2 command in your variable environment is "python2"


### Clone

- Clone this repo to your local machine using `git clone https://github.com/um-dsp/MalEvol.git`

### Setup

- Under the MalEvol directory, create two directories named "dumps" and "reports"
- Drop your .pcap or .pcapng files in the "pcaps" directory
- Execute `python MalEvol.py <path/to/your-pcap-file>` (python3)

### Notes
- Please note that MalEvol is not intended for production/commercial purpose, but rather for educational and research only.

- Since MalEvol analyzes potential malicious objects, in order to smoothly run it, you need to disable any real-time anti-malware protection you have installed or your OS provides.


### Example 1
> run `python MalEvol.py 2014-11-06-Nuclear-EK-traffic.pcap`
![picture1](https://github.com/um-dsp/MalEvol/blob/master/example.PNG)

### Example 2
This example shows the geo-location analysis results of the redirection chain.
> run `python MalEvol.py pcap21.pcap`

![picture2](https://github.com/um-dsp/MalEvol/blob/master/gro.PNG)


### Contact
MalEvol was developed at the [Data-Driven Security & Privacy Lab (DSPLab)](http://www-personal.umd.umich.edu/~birhanu/dsplab/) at the [University of Michigan, Dearborn](https://umdearborn.edu/cecs/departments/computer-and-information-science). 
May you have questions, please contact the Lead Developer, Abderrahmen Amich (aamich@umich.edu).

