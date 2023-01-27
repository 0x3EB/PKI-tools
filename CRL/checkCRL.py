# LIB 
import requests
import datetime
import cryptography
import OpenSSL.crypto
from OpenSSL.crypto import load_crl, FILETYPE_PEM, FILETYPE_ASN1
import time

OID_CRL_NEXT_PUBLISH = "1.3.6.1.4.1.311.21.4"

urls = [
    # ARRAY OF URL
]

def convert_timedelta(duration):
    days, seconds = duration.days, duration.seconds
    hours = days * 24 + seconds // 3600
    minutes = (seconds % 3600) // 60
    seconds = (seconds % 60)
    return hours, minutes, seconds
    
def check_crl_url(crl_url):    
    r = requests.get(crl)
    ac = crl.split('/')[-1] # Obtention du nom de l'AC
    print(f"Vérification pour {ac}")
    # load CRL
    if r.status_code == 200:
        try:
            # Chargement de la CRL en DER sinon en PEM
            crl_loaded = load_crl(FILETYPE_ASN1, r.content).to_cryptography()
        except OpenSSL.crypto.Error:
            crl_loaded = load_crl(FILETYPE_PEM, r.content).to_cryptography()
        except Exception as e:
            print(f"!!! / ! \\ ERREUR : IMPOSSIBLE DE CHARGER LA CRL ({e}) / ! \\ \n")
        if crl_loaded is not None:
            if ac not in ['TEST.crl']:
                for i in crl_loaded.extensions:
                    if isinstance(i.value, cryptography.x509.UnrecognizedExtension):
                        if i.value.oid.dotted_string == OID_CRL_NEXT_PUBLISH:
                            # Verification de la valeur OID_CRL_NEXT_PUBLISH fournit par l'ADCS 
                            # Permettant de savoir la prochaine date de publication de la CRL.
                            # Puis conversion du format de la date YYMMDDHHMMSSZ en datetime pour
                            # pouvoir faire des operations dessus
                            date_str = i.value.value.decode().replace("\x17\r","")
                            time_obj = time.strptime("20" + date_str[:-1] + "GMT", "%Y%m%d%H%M%S%Z")
                            next_publish = datetime.datetime.fromtimestamp(time.mktime(time_obj))
                            delta = next_publish - datetime.datetime.now()
                            hours, minutes, secondes = convert_timedelta(delta)
                            if delta.days > 0:
                                print(f"CRL A JOUR. La prochaine CRL sera publiée dans {delta.days} jours.\n")
                            elif hours > 0:
                                print(f"CRL A JOUR. La prochaine CRL sera publiée dans {hours} heures.\n")
                            else:
                                print(f"!!! / ! \\ CRL NON A JOUR / ! \\ !!!. La CRL n'est plus à jour depuis {abs(delta.days)} jours.\n")
            else:
                # Calcul de la date d'expiration des CRL IDNomic
                delta = crl_loaded.next_update - datetime.datetime.now()
                hours, minutes, secondes = convert_timedelta(delta)
                if delta.days > 0:
                    print(f"CRL A JOUR. La  CRL expire dans {delta.days} jours. \n")
                elif hours > 0:
                    print(f"CRL A JOUR. La CRL expire dans {hours} heures. \n")
                else:
                    print(f"!!! / ! \\ CRL NON A JOUR / ! \\ !!!. La CRL n'est plus à jour depuis {abs(delta.days)} jours.\n")
    else:
        # Si pas de code 200
        print(f"!!! / ! \\ ERREUR : IMPOSSIBLE DE TELECHARGER LA CRL ({r.status_code} error) / ! \\ \n") 

if __name__ == '__main__':
    for crl in urls:
        check_crl_url(crl)