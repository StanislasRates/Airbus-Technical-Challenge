# URL Checker

Cet outil permet de vérifier la sécurité d'une URL en utilisant l'API VirusTotal. Il dispose d'une interface graphique simple basée sur Tkinter.

## Fonctionnalités

- Saisie d'une URL au format JSON :  
  `{"url": "http://example.com"}`
- Analyse de l'URL via l'API VirusTotal.
- Affichage des résultats :  
  - Malicious  
  - Suspicious  
  - Harmless  
  - Undetected

## Prérequis

- Python 3.x
- Les modules suivants :
  - `requests`
  - `tkinter` 
  - `base64`
  - `json`

## Utilisation

1. Lancez le script :
   ```sh
   python urlChecker.py
   ```
2. Entrez une URL au format JSON dans la zone de texte :
   ```
   {"url": "http://example.com"}
   ```
3. Cliquez sur "Check URL" pour obtenir le résultat de l'analyse.

## Remarques

- Une clé API VirusTotal est nécessaire. 

## Fichier principal

- [urlChecker.py](urlChecker.py)