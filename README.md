# How to run
1) Install requirements (mainly selenium and pyshark)p:
    * pip install -r requirements.txt
2) Launch sniff.py
    * python sniff.py textfile timeout
    * A .cap file will be generated
3) Launch analyze.py
    * python analyze.py capfile textfile
    * The script will print out the number of HTTPS requests, the number of third party websites and the script run time