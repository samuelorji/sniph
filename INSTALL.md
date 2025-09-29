# Install OS Specific Dependencies

Before building and running `sniph`, ensure that you have the necessary OS-specific dependencies installed. These dependencies are crucial for packet capturing and other functionalities of `sniph`.

## Linux

 - **libpcap**: This is a system-independent interface for user-level packet capture. Install it using your package manager, the package is usually named `libpcap-dev` or `libpcap-devel`.

> If you're not running as root, you will need to set capabilities like so: ```sudo setcap cap_net_raw,cap_net_admin=eip path/to/bin```, where `path/to/bin` is where sniff is installed

[Here's another possible error you might encounter](https://github.com/samuelorji/sniph?tab=readme-ov-file#pcap-permission-denied-error)

## Windows

You'll need to install Npcap, which is a packet capture library for Windows.

- Download and install Npcap installer and Npcap SDK from the [official Npcap website](https://npcap.com/#download). 

- Extract the Npcap SDK to a known location on your system.

- Add the path to the Npcap SDK's `Lib` directory to your system's `LIB` environment variable. This allows the Rust compiler to find the necessary libraries during the build process.

> If you run into an error similar to this:
> ```Library machine type 'x86' conflicts with target machine type 'x64'```
> then you'll need to your `LIB` environment variable to point to the `x64` directory inside the Npcap SDK's `Lib` directory. So your `LIB` environment variable should contain `C:\Path\To\Npcap-SDK\Lib` or `C:\Path\To\Npcap-SDK\Lib\x64` depending on your system architecture.



## MacOS

Macos comes with all the dependencies you need to run sniph

[Here's another possible error you might encounter](https://github.com/samuelorji/sniph?tab=readme-ov-file#pcap-permission-denied-error)