# StringRemover

Tool for finding and erasing strings from process memory (ANSI & UTF-16), including string removal from protected regions.  
**Will be very useful for cleaning up traces of cheats.**

---

## 🧾 How to Use

1. **Run the program as Administrator**  
   Required to access the full memory space of the target process.

2. **Enter the PID of the target process**  
   You can find the PID in Task Manager (`Details` tab).

3. **Enter the contents of the strings you want to delete**  
   One per line.

4. **Configure the checkbox**

   ✅ **Advanced deletion**  
   – Slower, but deletes any string reliably  
   – Without it, some strings might not be removed due to memory protection

5. **Press the `Delete All` button**

---

📌 *Supports both ANSI and UTF-16 strings. Advanced mode temporarily changes memory protections to ensure deletion.*
