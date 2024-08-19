# Binary injection demo

## What is this thing?
this program injects a binary payload into a given process, identified by its (you guessed it) Process ID which needs to be passed to the program as an argument. quick rundown of how the program functions:

1. open a handle to the provided process using the PID (with all_access, i know it's a huge red flag but i thought it was good enough for a demonstration)
2. open a handle to wininet
3. open a handle with the URL of the specified payload
4. allocate memory for a temporary buffer (1024 bytes)
5. read the payload
    1. save read data to the temporary buffer (max of 1024 bytes)
    2. record the amount of bytes read
6. set size value for the final buffer
7. allocate memory for the final buffer, the amount of memory allocated to the final buffer is determined by the amount of bytes read by InternetReadFile()
8. Decrypt the downloaded payload
9. write contents of the temporary buffer to the final buffer
10. copy the final payload buffer to a new variable *
11. copy the size of the payload buffer to a new variable as well *
    1. clean up
12. allocate memory in the memory space of the specified process
13. write the payload to the previously allocated memory
14. create a thread to run the payload
15. wait until created thread completes execution
16. clean up and exit

###### note, this execution structure has changed a bit, but I am too lazy to correct this

# Info
to be able to compile this you will need to add wininet.lib to your build configuration:

1. open your solution's properties
2. go to Linker -> input
3. append this ```;wininet.lib``` to the end of the ```Additional Dependencies``` field

this lets the application build properly, though who knows maybe it's included in the .sln file and this works as long as you clone this repo. Visual Studio is weird.
```wininet.lib``` also needs to be imported if you are using CLion, however if you use CLion I assume I don't need to tell you how to do this.


### Contact
*discord: notsido*\
*telegram: notsido*

*you can shit on my programming skills here*
