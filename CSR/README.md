# Verification automatique de CSR (Certificate Signing Request)

Outil permettant la verification et la conformité de la demande de certificat utilisateur (CSR). Le fichier JSON doit être mis à jour dans le cadre de l'amélioration continue.

Le fichier setup.json contient les informations obligatoires et les points de contrôles pour les etapes de validation de la CSR. Dedans nous retrouvons, Les OID des Extended Key Usage (EKU), la liste blanche des contrôles de format de DNS et les élements obligatoire du Distinguisged Name (DN). 

le fichier CSR peut être au format ASN.1 (binaire) ou en base64 (PEM). Les modes de lecture doivent être précisés lors de l'execution du script.

Le script permet de verifier les élements suivants :

- taille de la clé
- algorithme de clé
- signature correspond à la clé publique de la CSR
- champs obligatoire du DN
- élements du DN
- présence de SAN
- présence d'EKU
- OID des EKU
- format des SAN
- presence du CN dans les SAN

## Usages

Pour simplifier la portabilité de script il a été packagé en EXE. Il n'est pas nécessaire d'avoir les bibliothèques ni d'avoir python.

- Avec l'utilisation de l'EXE dans le cadre où la CSR est au format PEM (Base64)
```sh
verification_csr.exe --csr FILE --format b64 --config setup.json
```
- Avec l'utilisation de l'EXE dans le cadre où la CSR est au format DER (ASN.1)
```sh
verification_csr.exe --csr FILE --format asn1 --config setup.json
```

- Sans l'utilisation de l'EXE vous devez installer Python (>=3.7) et les bibliothèques suivantes :
```sh
cd packages
pip install asn1-2.6.0-py2.py3-none-any.whl
pip install cffi-1.15.1-cp310-cp310-win_amd64.whl
pip install colorama-0.4.6-py2.py3-none-any.whl
pip install cryptography-38.0.4-cp36-abi3-win_amd64.whl
pip install enum_compat-0.0.3-py3-none-any.whl
pip install pyasn1-0.4.8-py2.py3-none-any.whl
pip install pycparser-2.21-py2.py3-none-any.whl
pip install pyOpenSSL-22.1.0-py3-none-any.whl
cd ..
```

ou (si vous avez une connexion au serveur PyPi)
```sh
pip install pyOpenSSL
pip install pyasn1
```

Ensuite en fonction du format de la CSR vous devez utiliser la commande suivante : 
```sh
python3 verification_csr.py --csr FILE --format (b64/asn1) --config setup.json
```


## Configuration

La configuration est realisée grâce au fichier setup.json.

L'objectif de ce fichier est de pouvoir faire de la vérification modulaire sans avoir a modifier le code. Dans ce sens pas besoin d'éditier le script pour rajouter des informations de contrôle.

Dans ce fichier nous pouvons retrouver les informations suivantes :

- KEY
	- Contient les propriétés de la clé a respecter
- DNS
	- Contient la liste des formats de DNS (terminaison) à respecter obligatoirement
- EKU
	- Contient la liste des Extended Key Usage autorisés 
- DN 
	- Contient chaque champs obligatoire du DN avec la valeur associée