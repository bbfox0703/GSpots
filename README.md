# ![Droplets](https://github.com/user-attachments/assets/b78ae8fe-da35-414b-a720-cf7c7241ddd0) GSpots

**Personal Fork Notice**  
This fork will not be written back to the original repository; it exists purely for personal interest.

Simple way of getting GWorld, GNames, and GObjects of an Unreal Engine game.

![GSpots](https://github.com/user-attachments/assets/b089c37f-1c2d-4845-9296-65cadc30c672)

## Demo Videos
<details>
  <summary>Show videos</summary>

  https://github.com/user-attachments/assets/09385216-2965-4023-9e87-830c1a8e0818

  https://github.com/user-attachments/assets/dba9ca71-98ce-4fb8-af61-86e96e7cb997

</details>

## Need Help?
Join Do0ks' <a href="https://discord.gg/7nGkqwdJhn">Discord</a>!

Looking for a new memory editor? - https://github.com/Do0ks/MemRE

## How to Use

- Download the precompiled release, or build in x64-release with Multi-Byte Character Set.
- Drag and drop the game's executable onto `GSpots.exe` (the executable located in **..\\Binaries\\Win64**, typically includes "Win64-Shipping.exe" in the name).
- Running the game in the background improves scanning results. GSpots will automatically attach to the process and, if file scanning fails to find offsets, it will try to locate them in memory.

## Compatibility

**This will not work on EVERY Unreal Engine game...**

If the game's exe is encrypted, the memory scan may bypass it, but if they took the time to encrypt the exe, chances are they also obfuscated other things too. But it should get you close!

**As time goes on I will add more signatures!**  
If you have a game that is unsupported, feel free to post in the [Game Compatibility Request](https://github.com/Do0ks/GSpots/issues/1) thread.

## Planned Features
<details>
  <summary>Soon</summary>

  - Add automatic fetching of the Unreal Engine Version the game is built with. :white_check_mark:
  - Add XOR encryption calculations with padding if applicable.
  - Added memory scan if the game's running in the background to try finding the offsets file scanning failed at. :white_check_mark:

</details>

<details>
  <summary>Later</summary>

  - Try to pre-calculate point of interest pointer chains such as the player class while the game is running. This should function like before (you'll just need the game running before dropping the game's exe onto `GSpots.exe`).

</details>

## Updates
<details>
  <summary>Recent changes</summary>

  - Added the ability to attach to the game if it's running. This is in preparation for future updates.
  - Added functions from my other GitHub repository to detect the Unreal version number.
  - Added memory scan if the game's running in the background to try finding the offsets file scanning failed at. Memory scanning is in beta.. It worked for every game I tried, and the one that didn't work has obfuscation. This update should help compatibility greatly!
  - Added the ability to detect and handle encrypted exes.

</details>

## Disclosure
<details>
  <summary>Read before using</summary>

  - If you choose to use this tool with an online game and you get banned, that's on you. I put no effort into making this tool evade anti cheat detection. While I don't expect anyone to be banned (I haven't yet) for using GSpots, it's always a risk.

</details>

## Some Other Awesome Tools!
<details>
  <summary>Links</summary>

  - Injectable Memory Scanner - https://github.com/Do0ks/B2D-Scanner
  - DLL Injector - https://github.com/Do0ks/Injector

</details>

