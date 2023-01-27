# LIB 
import argparse
import cryptography
import OpenSSL.crypto
import sys
import json
import re
from enum import Enum
from pyasn1.codec.ber import decoder
from OpenSSL.crypto import load_certificate_request, FILETYPE_PEM, FILETYPE_ASN1
from colorama import just_fix_windows_console

# DNS autortises 
ALLOWED_DNS = None
ALLOWED_EKU = None
DN_FORMAT = None
KEY_PROPERTIES = None

# EKU connus
EKU = {
    "1.3.6.1.5.5.7.3.1": "SSL/TLS Web Server Authentication",
    "1.3.6.1.5.5.7.3.2": "SSL/TLS Web Client Authentication",
    "1.3.6.1.5.5.7.3.3": "Code signing",
    "1.3.6.1.5.5.7.3.4": "E-mail Protection (S/MIME)",
    "1.3.6.1.5.5.7.3.5": "IP security end system",
    "1.3.6.1.5.5.7.3.6": "IP security tunnel termination",
    "1.3.6.1.5.5.7.3.7": "IP security user",
    "1.3.6.1.5.5.7.3.8": "Trusted Timestamping",
    "1.3.6.1.5.5.7.3.9": "OCSPstamping",
    "1.3.6.1.4.1.311.2.1.21": "Microsoft Individual Code Signing",
    "1.3.6.1.4.1.311.2.1.22": "Microsoft Commercial Code Signing",
    "1.3.6.1.4.1.311.10.3.1": "Microsoft Trust List Signing",
    "1.3.6.1.4.1.311.10.3.3": "Microsoft Server Gated Crypto",
    "1.3.6.1.4.1.311.10.3.4": "Microsoft Encrypted File System",
    "2.16.840.1.113730.4.1": "Netscape Server Gated Crypto"
}

class output:
    """
    Modification des données de sortie affichées sur le terminal
    """
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    TICK = u'\u2713'

class Utils:
    """
    Classe permettant de creer des methodes outils. Elles sont utiles pour la verification d'adresse IP par exemple
    """
    @staticmethod
    def is_ip(ip: str):
        """
        Verification is la chaine de caracteres est une adresse IP ou non
        """
        # verification du nombre de point
        if s.count('.') != 3:
            return False
     
        l = list(map(str, s.split('.')))
     
        # verification des octets
        for ele in l:
            if int(ele) < 0 or int(ele) > 255 or (ele[0]=='0' and len(ele)!=1):
                return False
     
        return True 

if __name__ == '__main__':
    just_fix_windows_console()
    conforme = True

    # Arguments du script
    parser = argparse.ArgumentParser()
    parser.add_argument("--csr", help="Chemin de la CSR a verifier", required=True)
    parser.add_argument("--format", help="Format de la CSR (B64 ou ASN1)", required=True)
    parser.add_argument("--config", help="Fichier de format a respecter", required=True)
    args = parser.parse_args()
    
    # Parsing de la CSR et verification
    try:
        if args.format.upper() == 'B64' or args.format.upper() == 'BASE64' or args.format.upper() == 'PEM':
            csr = open(args.csr, 'r').read()
            req = load_certificate_request(FILETYPE_PEM, csr)
        elif args.format.upper() == 'ASN1' or args.format.upper() == 'BYTES':
            csr = open(args.csr, 'rb').read()
            req = load_certificate_request(FILETYPE_ASN1, csr)
        else:
            print(f"{output.FAIL}Mauvaise valeur pour --format. Attendu : Base64 ou ASN1{output.ENDC}")
            sys.exit()
    except Exception as e:
        print(f"{output.FAIL}Impossible d'ouvrir le fichier CSR pour la raison suivante : {e}{output.ENDC}")
        sys.exit()
        
    # Parsing du fichier de configuration pour le DN
    try:
        json = json.loads(open(args.config, 'r').read())
        ALLOWED_DNS = json["DNS"]
        ALLOWED_EKU = json["EKU"]
        DN_FORMAT = json["DN"]
        KEY_PROPERTIES = json["KEY"]
    except Exception as e:
        print(f"{output.FAIL}Impossible d'ouvrir le fichier JSON avec le contenu de a la configuration : {e}{output.ENDC}")
        sys.exit()
    
    # Verification de la presence des clés dans le fichier JSON
    if not 'C' in DN_FORMAT and not 'O' in DN_FORMAT and not 'L' in DN_FORMAT and not 'ST' in DN_FORMAT:
        print(f"{output.FAIL}Il doit y avoir les clés et valeurs pour les clés suivantes : C, O, L et ST{output.ENDC}")
        sys.exit()
        
    print("\n##################################")
    print("## Verification cryptographique ##")
    print("##################################\n")
    # Verification de la taille de clé
    if req.get_pubkey().bits() != KEY_PROPERTIES["length"]:
        print(f"Taille de clé : {output.FAIL}ERREUR ({req.get_pubkey().bits()} bits){output.ENDC}")
        conforme = False
    else:
         print(f"Taille de clé : {output.OKGREEN}OK ({req.get_pubkey().bits()} bits){output.ENDC}")
    
    # Verification de l'algorithme de clé    
    if not isinstance(req.get_pubkey().to_cryptography_key(), cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey):
        print(f"Algorithme de clé : {output.FAIL}ERREUR ({type(req.get_pubkey().to_cryptography_key()).__name__}){output.ENDC}")
        conforme = False
    else:
        print(f"Algorithme de clé : {output.OKGREEN}OK ({type(req.get_pubkey().to_cryptography_key()).__name__}){output.ENDC}")
    
    # Verification signature
    if not req.verify(req.get_pubkey()):
        print(f"Signature : {output.FAIL}ERREUR {output.ENDC}")
        conforme = False
    else:
        print(f"Signature : {output.OKGREEN}OK{output.ENDC}")
        
    
    print("\n##################################")
    print("## Verification du Sujet DN     ##")
    print("##################################\n")
    
    list_of_dn_label = [dn[0].decode() for dn in req.get_subject().get_components()]
    if not all(item in list_of_dn_label for item in list(DN_FORMAT.keys())) or not 'CN' in list_of_dn_label:
        print(f"Champs obligatoires du DN : {output.FAIL}ERREUR ({', '.join(list(DN_FORMAT.keys()))} et/ou CN manquant(s)){output.ENDC}")
        conforme = False
    else:
        print(f"Champs obligatoires du DN : {output.OKGREEN}OK ({', '.join(list(DN_FORMAT.keys()))} présents){output.ENDC}")

    # Verification du DN
    print("Vérification des champs :")
    for dn_label, dn_value in req.get_subject().get_components():
        if dn_label.decode() in DN_FORMAT and not dn_value.decode() == DN_FORMAT[dn_label.decode()]:
            print(f"\t{dn_label.decode()}={dn_value.decode()} : {output.FAIL}ERREUR (attendu {dn_label.decode()}={DN_FORMAT[dn_label.decode()]}){output.ENDC}")
            conforme = False
        elif dn_label.decode() == 'CN' and not dn_value.decode().endswith(tuple(ALLOWED_DNS)):
            print(f"\t{dn_label.decode()}={dn_value.decode()} : {output.FAIL}ERREUR (Doit se terminer par {', '.join(ALLOWED_DNS)}){output.ENDC}")
            conforme = False
        # Verification wildcard
        elif dn_label.decode() == 'CN' and dn_value.decode().startswith('*'):
            print(f"\t{dn_label.decode()}={dn_value.decode()} : {output.WARNING}ATTENTION (Wildcard){output.ENDC}")
            conforme = False
        elif dn_label.decode() == 'E' or dn_label.decode() == 'chalengePassword':
            print(f"\t{dn_label.decode()}={dn_value.decode()} : {output.FAIL}ERREUR (Le champ {dn_label} n'est pas autorisé{output.ENDC})")
            conforme = False
        else:
            print(f"\t{dn_label.decode()}={dn_value.decode()} : {output.OKGREEN}OK {output.ENDC}")
            
    # Verification des Extensions
    print("\n##################################")
    print("## Verification des extensions  ##")
    print("##################################\n")
    extensions = [ext.get_short_name().decode() for ext in req.get_extensions()] # Mise en liste des noms des extensions
    if not 'subjectAltName':
        print(f"Presence de SAN : {output.FAIL} NON {output.ENDC}")
        conforme = False
    else:
        print(f"Presence de SAN : {output.OKGREEN} OUI {output.ENDC}")
    if not 'extendedKeyUsage' in extensions:
        print(f"Presence d'EKU : {output.FAIL} NON {output.ENDC}")
        conforme = False
    else:
        print(f"Presence d'EKU : {output.OKGREEN} OUI {output.ENDC}\n")
    
    for ext in req.get_extensions():
        # Verification des SAN (avec la presence du CN dans les SAN)
        if ext.get_short_name().decode() == 'subjectAltName':
            # Mise en place des SAN dans un array pour l'analyse
            san = str(ext).replace(',','').replace(' ','')
            array_san = [x for x in re.split(r'DNS:|IP Address:', san) if x != '']
            print(f"Verification des SAN : ({len(array_san)})")
            # Recuperation du CN
            try:
                cn = dict(req.get_subject().get_components())[b'CN'].decode()
            except Exception:
                cn = None
            if not cn in array_san:
                print(f"\tCN present dans les SAN : {output.FAIL}ERREUR ({cn}){output.ENDC}")
                conforme = False
            else:
                print(f"\tCN present les SAN : {output.OKGREEN}OK ({cn}){output.ENDC}")
            # Analyse de tout les SAN
            for s in array_san:
                if not Utils.is_ip(s) and not s.endswith(tuple(ALLOWED_DNS)):
                    print(f"\t{s} : {output.FAIL} ERREUR (doit se terminer par {', '.join(ALLOWED_DNS)}){output.ENDC}")
                    conforme = False
                elif s.startswith('*'):
                    print(f"\t{s} : {output.WARNING} ATTENTION (Wildcard){output.ENDC}")
                else:
                    print(f"\t{s} : {output.OKGREEN} OK {output.ENDC}")
        # Verification des EKU
        if ext.get_short_name().decode() == 'extendedKeyUsage':
            print("Verification des EKU:")
            # Decode de l'ASN1 pour sortir les OID des EKU
            for eku in decoder.decode(ext.get_data())[0]:
                if str(eku) in ALLOWED_EKU:
                    print(f"\t{eku} ({EKU[str(eku)]}): {output.OKGREEN} OK {output.ENDC}")
                else:
                    try:
                        print(f"\t{eku} ({EKU[str(eku)]}): {output.FAIL} Non autorisé {output.ENDC}")
                        conforme = False
                    except Exception:
                        print(f"\t{eku} (Unknown): {output.FAIL} Non autorisé {output.ENDC}")
                        conforme = False
    
    # Affichage si la CSR est conforme
    if not conforme:
        print(f"\n{output.FAIL}La CSR n'est pas conforme et ne doit pas être envoyée à la PKI{output.ENDC}")
    else:
        print(f"\n{output.OKCYAN}La CSR est conforme et peut être envoyée à la PKI{output.ENDC}")
    
    