# Architecture ZennComp v1

## Objectif

ZennComp est une base native C++/Win32 pour construire un decompilateur AVHIRAL.
La version v1 pose le socle:

```text
GUI Win32
├── ouverture binaire
├── parsing PE
├── sections + entropie
├── imports
├── chaines ASCII/UTF-16
├── heuristiques comportementales
├── pseudo-code C-like
└── export rapport
```

## Modules logiques

### 1. Interface graphique

Le fichier `src/main.cpp` contient une GUI Win32 sans dependance externe:

- fenetre principale;
- bouton `Ouvrir EXE`;
- bouton `Analyser PE`;
- bouton `Pseudo-decompiler`;
- bouton `Extraire chaines`;
- bouton `Exporter rapport`;
- controle EDIT multiline pour les logs.

### 2. Parseur PE

La classe `PeParser` analyse:

- `IMAGE_DOS_HEADER`;
- `IMAGE_NT_HEADERS32/64`;
- `IMAGE_SECTION_HEADER`;
- data directories;
- import descriptors;
- thunk tables 32/64.

### 3. Heuristiques

Les heuristiques sont basees sur les imports:

- `CreateProcess`, `ShellExecute`, `WinExec` -> execution processus;
- `RegOpenKey`, `RegSetValue`, `RegDelete*` -> registre;
- `OpenSCManager`, `CreateService`, `DeleteService` -> services;
- `VirtualAlloc`, `VirtualProtect` -> memoire executable;
- `LoadLibrary`, `GetProcAddress` -> resolution dynamique.

### 4. Pseudo-decompilation

La pseudo-decompilation v1 ne decompile pas les instructions machine.
Elle reconstruit une vue C-like a partir:

- des headers PE;
- de l'entry point;
- des imports;
- des familles d'API detectees.

## Evolution vers un vrai moteur de decompilation

Pour passer a ZennComp v2/v3:

1. Ajouter un decodeur x86/x64.
2. Creer une representation Instruction.
3. Reperer fonctions, prologues/epilogues, appels et branches.
4. Construire basic blocks + CFG.
5. Convertir en IR AVHIRAL.
6. Simplifier l'IR.
7. Generer pseudo-C.
8. Ajouter un mode graphe.
