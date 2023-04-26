# About
ETWHash is a C# POC that is able to extract NetNTLMv2 hashes of incoming authentications via SMB, by consuming ETW events from the Microsoft-Windows-SMBServer provider `{D48CE617-33A2-4BC3-A5C7-11AA4F29619E}`

## Notes

* Administrative privileges required

## Usage

```
Usage:
EtwHash.exe [time_in_seconds]

Example:
C:\Temp\>EtwHash.exe 60

[*] Started monitoring ETW provider for 60 seconds.
nessus::LAB:D27DD3110B795705:25669980911E6CE0693E01796FA34B6E:01010000000000004C6B85AE6178D901EB33D5D6CF85093A00000000020008005700500041004400010008005700500041004400040008007700700061006400030008007700700061006400070008004C6B85AE6178D901060004000200000008003000300000000000000001000000002000003E77D791FEFF45C00D86B0D8744093A2F75712A53AC94F62AD16FF5B4AB54BAE0A0010000000000000000000000000000000000009001C0063006900660073002F003100320037002E0030002E0030002E0031000000000000000000

```

## Useful References:

https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63

https://github.com/zodiacon/EtwExplorer 

https://github.com/0xeb/WinTools/tree/master/WEPExplorer 

https://github.com/mandiant/SilkETW 

Code is based on the following repos:
  * https://github.com/CyberPoint/Ruxcon2016ETW
  * https://github.com/X-C3LL/SharpNTLMRawUnHide


## Credits
  Lefty @lefterispan - Nettitude Red Team - 2022 / 2023 

## Shouts to: 
Nettitude RT