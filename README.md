# StringRemover

Tool for finding and erasing strings from process memory (ANSI & UTF-16), including string removal from protected regions.  
**Will be very useful for cleaning up traces of cheats from Process Hacker and System Informer.**

---

## 🧾 How to Use

1. **Run the program as Administrator**  
   Required to access the full memory space of the target process.

2. **Enter the PID of the target process**  
   You can find the PID in Task Manager (`Details` tab).

3. **Enter the contents of the strings you want to delete**  
   One per line.

4. **Press the `Delete All` button**

---

📌 *Supports both ANSI and UTF-16 strings. Advanced mode temporarily changes memory protections to ensure deletion.*

---

## 🛠️ Source Code & Compilation

This application is written in modern C++ using the WinAPI.  
It was successfully compiled and tested on **MinGW-w64 (64-bit)** using the `g++` compiler.

### 🔧 Compile using:
```bash
g++ SourceCode.cpp -o StringRemover.exe -m64 -std=c++17 -O2 -static -static-libgcc -static-libstdc++ -mwindows -ladvapi32 -lpsapi
