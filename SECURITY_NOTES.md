# Notes securite ZennComp

ZennComp est concu pour l'analyse statique.
Il ne charge pas les binaires cibles en memoire executable, ne les lance pas et ne leur donne aucun privilege.

Bonnes pratiques:

- analyser les binaires suspects dans une VM isolee;
- ne pas double-cliquer les echantillons;
- conserver les hashes des fichiers analyses;
- ne pas envoyer de binaires suspects sur une machine de production;
- conserver les rapports ZennComp avec date, hash et origine du fichier.

ZennComp v1 ne contourne pas les protections commerciales et ne fournit pas de mecanisme de desactivation DRM/licence.
