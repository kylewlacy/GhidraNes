# GhidraNes

A Ghidra extension to support disassembling and analyzing NES ROMs.

![NES game disassembly](.github/screenshots/ghidra-nes.png)

## Features

- Import NES ROMs in the iNES format. The following mappers are supported:
    - NROM (mapper 0)
- Add labels and memory blocks in disassembly, making it easier to jump around a disassembled ROM!

## Installation

1. Install a Compatible version of Java and Ghidra (Java 11+, tested with Ghidra 9.1.2).
2. Download the latest [GhidraNes release](https://github.com/kylewlacy/GhidraNes/releases).
3. Go to "File" > "Install Extensions...". Click "+" in the top-right corner and choose the GhidraNes Zip. Click "OK" to install the extension.
4. Restart Ghidra.

## Usage

1. In Ghidra, create a new project by following the wizard under "File" > "New Project...".
2. Drag-and-drop an iNES `.nes` ROM onto the project. Set the format to "NES ROM" and click "OK".
3. Double-click the ROM in the project to open Ghidra's CodeBrowser.
4. Analyze the file when prompted (or go to "Analysis" > "Auto Analyze..."). Leave the settings as default and click "Analyze".
5. Done, the game will be disassembled! On the left-hand side, under "Symbol Tree" > "Functions", open `reset` to jump to the reset vector (where execution starts), or `vblank` to jump to the NMI vector (where execution goes during VBlank).

## Developing

1. Install Java and Ghidra.
2. install Eclipse.
3. Install the GhidraDev Eclipse plugin. Instructions can be found in your Ghidra install directory, under `Extensions/Eclipse/GhidraDev/GhidraDev_README.html`.
4. In Eclipse, open the GhidraNes repo by going to "File" > "Open Projects from File System...".
5. Open "GhidraDev" > "Link Ghidra...". Add your Ghidra installation, click "Next >", then select the "GhidraNes" as the Java project. Click "Finish".
6. Run the project in Eclipse to start Ghidra and the GhidraNes extension.

### Building a release from Eclipse

**NOTE:** Ensure the GhidraNes Eclipse project is set up with the _earliest_ version of Java that should be targeted. Using a later version of Java can cause compatibility issues!

1. Install Gradle (with [SDKMAN](https://sdkman.io/), this can be done with `sdk install gradle`).
2. In Eclipse, open "GhidraDev" > "Export" > "Ghidra Module Extension...". Choose "GhidraNes" as the project, click "Next >", then choose "Local installation directory:" and browse to your Gradle installation dir (with SDKMAN, this will be at `~/.sdkman/candidates/gradle/$GRADLE_VERSION`). Click "Finish".
3. The built zip file will be saved in the `dist/` directory.
