## Malware Analysis (WannaCry)

### Static analysis

**VirusTotal Report:**
<img src="https://i.imgur.com/IHnNOWa.png">
- Hashes:
  - MD5: 84C82835A5D21BBCF75A61706D8AB549
  - SHA1: 5FF465AFAABCBF0150D1A3AB2C2E74F3A4426467
  - SHA256: ED01EBFBC9EB5BBEA545AF4D01BF5F1071661840480439C6E5BABE8E080E41AA
- Filesize: 3481600 bytes
- File Type: PE32
- Presented Filename: diskpart.exe
- File Name: wannacrypt.exe
- DLLs:
  - ntdll.dll
  - kernel32.dll
  - kernelbase.dll
  - user32.dll
  - gdi32.dll
  - lpk.dll
  - usp10.dll
  - msvcrt.dll
  - advapi32.dll

**Dynamic Analysis:**

**Processes:**
- C:\Users\admin\AppData\Local\Temp\wannacrypt.exe
- C:\Windows\System32\attrib.exe
- C:\Windows\System32\icacls.exe
- C:\Users\admin\AppData\Local\Temp\taskdl.exe
- C:\Windows\System32\cmd.exe
- C:\Windows\System32\cscript.exe
- C:\Users\admin\Downloads\@WanaDecryptor@.exe
- C:\Windows\System32\cmd.exe
- C:\Users\admin\AppData\Local\Temp\@WanaDecryptor@.exe
- C:\Windows\System32\cmd.exe
- C:\Windows\System32\reg.exe

**Notable Registry Keys Modified:**
- HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

**Tools used:**
- Any.Run

**Overview:**
Based on the analysis, the file appears to be malicious. When the file hash is searched on VirusTotal, it was flagged 68 times. During the dynamic analysis, the file created multiple files that are associated with the WannaCry ransomware, such as wannacrypt.exe and @WanaDecryptor@.exe. When the file was executed, a message appeared that requested Bitcoin in exchange for the safe retrieval of the computer’s files.
