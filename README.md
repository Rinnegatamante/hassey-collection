# Hassey Collection

<p align="center"><img src="./screenshots/game.png"></p>

This is a wrapper/port of <b>Galcon 2: Galactic Conquest</b> and <b>BREAKFINITY</b> for the *PS Vita*.

The port works by loading the official Android ARMv7 executables in memory, resolving their imports with native functions and patching them in order to properly run.
By doing so, it's basically as if we emulate a minimalist Android environment in which we run natively the executables as they are.

## Changelog

### v0.9

- Initial release.

## Known Issues

- Galcon 2 has issues with online at the moment (game can connect to servers but updates aren't properly received) so can be played solely offline (Practice mode).
- Galcon 2 menus can be quite laggy but in game framerate is solid.

## Setup Instructions (For End Users)

This port supports Galcon 2: Galactic Conquest and BREAKFINITY. <b>The instructions reported here will follow how to install Galcon 2: Galactic Conquest</b>.

In order to install BREAKFINITY, just follow the same instructions but, when in the guide the folder `game1` is referred, change it to `game2`.

- Install [kubridge](https://github.com/bythos14/kubridge/releases/) and [FdFix](https://github.com/TheOfficialFloW/FdFix/releases/) by copying `kubridge.skprx` and `fd_fix.skprx` to your taiHEN plugins folder (usually `ux0:tai`) and adding two entries to your `config.txt` under `*KERNEL`:
  
```
  *KERNEL
  ux0:tai/kubridge.skprx
  ux0:tai/fd_fix.skprx
```

**Note** Don't install fd_fix.skprx if you're using rePatch plugin

- **Optional**: Install [PSVshell](https://github.com/Electry/PSVshell/releases) to overclock your device to 500Mhz.
- Install `libshacccg.suprx`, if you don't have it already, by running [this homebrew](https://vitadb.rinnegatamante.it/#/info/997).
- Obtain your copy of *Galcon 2: Galactic Conquest* legally for Android in form of an `.apk` file. [You can get all the required files directly from your phone](https://stackoverflow.com/questions/11012976/how-do-i-get-the-apk-of-an-installed-app-without-root-access) or by using an apk extractor you can find in the play store. The apk can be extracted with whatever Zip extractor you prefer (eg: WinZip, WinRar, etc...) since apk is basically a zip file. You can rename `.apk` to `.zip` to open them with your default zip extractor.
- Open the apk with your zip explorer and extract the files `libmain.so` from the `lib/armeabi-v7a` folder to `ux0:data/hassey/game1`.
- Extract the `assets` folder inside `ux0:data/hassey/game1`.

## Build Instructions (For Developers)

In order to build the loader, you'll need a [vitasdk](https://github.com/vitasdk) build fully compiled with softfp usage.  
You can find a precompiled version here: https://github.com/vitasdk/buildscripts/actions/runs/1102643776.  
Additionally, you'll need these libraries to be compiled as well with `-mfloat-abi=softfp` added to their CFLAGS:

- [SDL2_vitagl](https://github.com/Northfear/SDL/tree/vitagl)

- [vitaGL](https://github.com/Rinnegatamante/vitaGL)

  - ````bash
    make SOFTFP_ABI=1 NO_DEBUG=1 SINGLE_THREADED_GC=1 HAVE_CUSTOM_HEAP=1 install
    ````

After all these requirements are met, you can compile the loader with the following commands:

```bash
mkdir build && cd build
cmake .. && make
```

## Credits

- TheFloW for the original .so loader.
- CatoTheYounger for the screenshots and for testing the homebrew.
- Once13one for the Livearea assets.
- Northfear for the SDL2 fork with vitaGL as backend.
