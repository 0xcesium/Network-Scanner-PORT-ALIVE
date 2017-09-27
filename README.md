# Network-Scanner-PORT-ALIVE
Network scanner in Python 2.7 with Scapy using ARP for optimization.

Is able to test MS17-010 vulnerability if 445 is found opened.

            usage: neighbors_parser.py.py [-h] [-v] [-b] [-i IP] [-w WORDLIST] [-u USERNAME] [-m MODE]
                        [-l LONGUEUR]

            Discovery and attack only, made by Cesium133.

            optional arguments:
              -h, --help            show this help message and exit
              -v, --version         show program's version number and exit
              -b, --bruteforce      Argument optionnel pour déclencher le mode attaque.
              -i IP, --ip IP        Machine cible.
              -w WORDLIST, --wordlist WORDLIST
                                    Ajout d'un dictionnaire.
              -u USERNAME, --username USERNAME
                                    Username distant à BF.
              -m MODE, --mode MODE  Alphabet de bruteforce [lower | upper | digits |
                                    letters+digits | hex | all].
              -l LONGUEUR, --longueur LONGUEUR
                                    Longueur des mots de passe souhaitée.
