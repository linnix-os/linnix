// src/bin/ipc_test_client.rs

use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::process::exit;

const DEVICE_PATH: &str = "/dev/cognito_ipc"; // Must match the device created by mknod

fn main() {
    println!("[ipc_test_client] Attempting to open device: {DEVICE_PATH}");

    // Open the device file for writing
    // We use OpenOptions to explicitly open for writing only.
    let file_result = OpenOptions::new()
        .write(true) // We only need write access
        .open(DEVICE_PATH);

    let mut file = match file_result {
        Ok(f) => {
            println!("[ipc_test_client] Successfully opened {DEVICE_PATH}");
            f
        }
        Err(e) => {
            eprintln!("[ipc_test_client] ERROR: Failed to open {DEVICE_PATH}: {e}");
            eprintln!("[ipc_test_client] Hints:");
            eprintln!(" - Did you load the kernel module ('insmod hello_cognito.ko')?");
            eprintln!(
                " - Did you create the device node ('sudo mknod /dev/cognito_ipc c MAJOR 0')?"
            );
            eprintln!(
                " - Does the device node have write permissions ('sudo chmod 666 /dev/cognito_ipc')?"
            );
            exit(1); // Exit with an error code
        }
    };

    // Message to send
    let message = b"Hello from user space via Rust!"; // Send as bytes

    println!("[ipc_test_client] Writing message to device...");

    // Write the message to the device file
    match file.write_all(message) {
        Ok(_) => {
            let bytes = message.len();
            println!("[ipc_test_client] Successfully wrote {bytes} bytes.");
            println!("[ipc_test_client] Check kernel log ('dmesg') for message from module.");
        }
        Err(e) => {
            eprintln!("[ipc_test_client] ERROR: Failed to write to {DEVICE_PATH}: {e}");
            // Provide specific hints for common write errors if possible
            if e.kind() == ErrorKind::PermissionDenied {
                eprintln!("[ipc_test_client] Hint: Check write permissions on {DEVICE_PATH}");
            }
            exit(1);
        }
    }

    // file is automatically closed when it goes out of scope here
    println!("[ipc_test_client] Finished.");
}
