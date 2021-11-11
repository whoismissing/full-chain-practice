**How to debug chrome?**
* create an infinite loop performing a benign function containing pointers to interested memory.
* leave magic values in memory and search via the debugger

---

**In the renderer, what happens when we spawn execve()?**

---

**In the sandbox escape, why is the array-length overwrite primitive not used?**
My guess is because the data structures and related code for the array-length overwrite primitive used in the renderer exploit are located in the renderer process and thus cannot be directly accessed in the sandbox escape.

---

**Does mojo have a different heap memory than the renderer process?**
Yes, mojo code is executing in the main chrome process rather than the renderer.

---

**Is mojo code executed in a different process than the renderer?**
Yes, mojo code is executing in the main chrome process rather than the renderer.

