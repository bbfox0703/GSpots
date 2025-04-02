# ![Droplets](https://github.com/user-attachments/assets/b78ae8fe-da35-414b-a720-cf7c7241ddd0) GSpots

Simple way of getting GWorld, GNames, and GObjects of an Unreal Engine Game.

![GSpots](https://github.com/user-attachments/assets/b089c37f-1c2d-4845-9296-65cadc30c672)

<details>
 
   <summary>Demo Videos</summary>
 
   https://github.com/user-attachments/assets/09385216-2965-4023-9e87-830c1a8e0818

   https://github.com/user-attachments/assets/dba9ca71-98ce-4fb8-af61-86e96e7cb997

 </details>

# How to use

- Download the precompiled release, or build in x64-release with Multi-Byte Character Set.  
- Drag and drop the games executable onto GSpots.exe

### This will not work on EVERY Unreal Engine game...

If the games exe is encrypted, this will not bypass it. 

As time goes on I will add more signatures!  
If you have a game that is unsupported, feel free to post in the [Game Compatibility Request](https://github.com/Do0ks/GSpots/issues/1) thread. 

# Planned Fetures:
<details>
  
  ## Soon:  
  
  - Add automatic fetching of the Unreal Engine Version the game is built with (though this will work better with the "later" update listed below).
  
  - Add XOR encryption calculations with padding if applicable.

  ## Later:  

  - Try to pre calculate point of interest pointer chains such as the player class while the games running. This should function like before (you'll just need the game running before dropping the games exe onto G Spots.exe)
  
</details>

# Updates:
<details>

- Added the ability to attach to the game IF its running. This is in preperation for future updates.

- Added functions from my other github repository to detect the Unreal Version number. 

</details>
