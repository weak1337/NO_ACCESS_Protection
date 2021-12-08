# NO_ACCESS_Protection
This is a technique that I found while reversing Halos anticheat. They encrypt the text section and set the protection to NO_ACCESS. The pages will be decrypted on first access. If the RIP, that referenced the memory, is outside of a valid module it will fail and will crash the process after some time. 
With this they can prevent:
- basic signature scanning (access violation + rip check)
- cheat engine veh debugger
- full process dumping (since you can encrypt the pages again)
