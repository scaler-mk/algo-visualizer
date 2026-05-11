Final mini project code

```python
import time
from collections import Counter, defaultdict

start_time = time.time()
troublemaker_ips = Counter()
ip_examples = defaultdict(list)
error_count = 0
warning_count = 0


def extract_ip_from_line(line: str) -> str | None:
    """Extract an IP address from an Apache log line. Returns None if not found."""

    # Format 1: IP inside brackets -> [client 172.16.0.89]
    client_start = line.find("[client ")
    if client_start != -1:
        ip_start = client_start + 8         # skip past the 8 characters "[client "
        ip_end = line.find("]", ip_start)
        if ip_end != -1:
            candidate = line[ip_start:ip_end]
            if candidate.count(".") == 3 and all(c.isdigit() or c == "." for c in candidate):
                return candidate

    # Format 2: IP at the start of the line -> 192.168.1.10 - - [date]
    first_space = line.find(" ")
    if first_space != -1:
        candidate = line[:first_space]
        if candidate.count(".") == 3 and all(c.isdigit() or c == "." for c in candidate):
            return candidate

    return None


# --- File Processing ---
try:
    with open("apache_access_error.log", "r", encoding="utf-8", errors="ignore") as file:

        for line_num, line in enumerate(file, 1):
            lower_line = line.lower()

            if "[error]" in lower_line or "[warn]" in lower_line:

                if "[error]" in lower_line:
                    error_count += 1
                else:
                    warning_count += 1

                ip = extract_ip_from_line(line)

                if ip:
                    troublemaker_ips[ip] += 1
                    if len(ip_examples[ip]) < 3:
                        snippet = line.strip()[:120]
                        ip_examples[ip].append((line_num, snippet))

except FileNotFoundError:
    print("Error: The file 'apache_access_error.log' was not found. Check your path.")

except PermissionError:
    print("Error: You do not have read permission for this file. Try running with sudo.")

except Exception as e:
    print(f"Error: An unexpected error occurred: {e}")


# --- Report (runs only if no errors occurred) ---
else:
    print("\n--- Summary ---")
    print(f"  Total Errors   : {error_count}")
    print(f"  Total Warnings : {warning_count}")
    print(f"  Unique IPs     : {len(troublemaker_ips)}")

    print("\n--- Top 5 Troublemaker IPs ---")
    for ip, count in troublemaker_ips.most_common(5):
        print(f"\n  {ip}  ({count} events)")
        for line_num, snippet in ip_examples.get(ip, []):
            print(f"    Line {line_num}: {snippet}")

    print(f"\n  Time taken: {time.time() - start_time:.2f} seconds")
```

Scripts

# **Teaching Script: Apache Log Forensics (Regex-Free, Memory-Efficient)**

**Target Audience:** Beginner-to-intermediate Python students
 **Duration:** ~90 minutes
 **Materials:** Projector, live code editor, sample log file

## **Structure Overview**

| **Chapter** | **What it covers** |
| --- | --- |
| 1 | Server crashed — reading the log file, all file I/O basics, 50 GB reveal, streaming |
| 2 | Manager wants top offending IPs — Counter, defaultdict, string parsing, full script |
| 3 | Running the script and reading the output |
| 4 | Key takeaways and homework |

## **CHAPTER 1: The Server Crashed — Let's Read the Log File**

### **1.1 — Setting the Scene**

**Instructor:**

"It is Friday evening. You are on call for the backend team. An alert comes in: the production web server has started throwing errors and some users are seeing failure pages.

You SSH into the server. A colleague tells you: 'Everything Apache does gets written to a log file. Start there.'

You find the file:

apache_access_error.log

Apache is the web server software. Every time a request fails, a page is missing, or the server itself hits an internal problem — Apache writes a line into this file with a timestamp, the type of event, and details about what happened.

You open a Python script. Your first question is: how do I open this file and look inside?"

### **1.2 — Opening a File with open()**

**Instructor:**

"Python gives us a built-in function called open(). You pass it the file name and it returns a file object — a connection to that file that you can then use to read from."

file = open("apache_access_error.log")

"That one line asks the operating system to give your Python program access to the file. The result is stored in file. Now let's read from it."

### **1.3 — File Modes**

**Instructor:**

"Before we read, let's understand the mode argument. It tells Python what you intend to do with the file."

Write this on the board:

| **Mode** | **Meaning** | **File must exist?** |
| --- | --- | --- |
| "r" | Read only (text) | Yes |
| "r+" | Read and write (text) | Yes |
| "rb" | Read only (raw bytes) | Yes |
| "w" | Write — creates or wipes the file | No |
| "a" | Append — adds to the end | No |

"For reading a log file, 'r' is correct and is actually the default. A few things worth understanding:

'r+' lets you both read and write. You would use this if you wanted to scan a file and patch something in it. We only need to read today.

'rb' reads raw bytes instead of text. Use this for images, zip files, compiled programs — anything not meant to be read as plain text. Log files are text, so 'rb' is wrong for us.

'w' is dangerous to confuse with 'r'. It wipes the file clean immediately on open. If you accidentally open your log file with 'w', your evidence is gone before you read a single line.

Let's always be explicit:"

file = open("apache_access_error.log", "r")


![File Modes — what each one does](https://d2beiqkhq929f0.cloudfront.net/public_assets/assets/000/196/013/original/Image_1_FileModes.png?1778539024)

### **1.4 — Three Ways to Read a File**

**Instructor:**

"Once a file is open, Python gives you three methods to read from it. Each gives you a different result. Let's go through all three."

**Method 1: .read()**

".read() reads the entire file and returns it as one single string."

file = open("apache_access_error.log", "r")

content = file.read()

print(content)

"If the log file contains these lines:"

172.16.0.89 - - [24/Apr/2026:02:14:33 +0000] [error] [client 172.16.0.89] File not found: /admin

192.168.1.10 - - [24/Apr/2026:02:15:01 +0000] [error] [client 192.168.1.10] Segfault at instruction

172.16.0.89 - - [24/Apr/2026:02:15:22 +0000] [warn]  [client 172.16.0.89] ModSecurity: Access denied

"After .read(), content holds all of that as one big string. The entire file — every line — in one variable."

**Method 2: .readline()**

".readline() reads exactly one line at a time. Every time you call it, it advances to the next line."

file = open("apache_access_error.log", "r")

line1 = file.readline()

line2 = file.readline()

line3 = file.readline()

print(line1)   # '172.16.0.89 - - ... [error] ...\n'

print(line2)   # '192.168.1.10 - - ... [error] ...\n'

print(line3)   # '172.16.0.89 - - ... [warn] ...\n'

"Notice the \n at the end — that is the newline character separating lines in the file. When you want clean output, strip it:

print(line1.strip())

.readline() gives you precise, controlled access one line at a time."

**Method 3: .readlines()**

".readlines() reads the entire file and returns a list where each element is one line."

file = open("apache_access_error.log", "r")

lines = file.readlines()

print(lines)

# ['172.16.0.89 - - ... [error] ...\n',

#  '192.168.1.10 - - ... [error] ...\n',

#  '172.16.0.89 - - ... [warn] ...\n']

"You can then loop over the list or access lines by index:"

for line in lines:

    print(line.strip())

print(lines[0])   # First line

print(lines[1])   # Second line

**Instructor — pause and compare:**

"So we have three reading methods. What is the difference?

- .read() — the whole file as one string

- .readline() — one line fetched on demand

- .readlines() — the whole file as a list of lines

For our small sample log file, all three work perfectly fine. We can see the errors. Good."


<iframe src="https://scaler-mk.github.io/algo-visualizer/IPR/Beginner Python/Lec 11 - File & Exception Handling/Animation_1_ThreeReadMethods.html" width="100%" height="820" frameborder="0" style="border:1px solid #3a3f4b;border-radius:8px;"></iframe>

### **1.5 — Closing the File: The Right Way**

**Instructor:**

"Every file you open, you must close when you are done. The operating system gives your program a limited number of file connections. If you open files and never close them, you eventually run out. This is called a resource leak.

The manual way:"

file = open("apache_access_error.log", "r")

content = file.read()

print(content)

file.close()

"That works. But what if an error happens between open() and close()?"

file = open("apache_access_error.log", "r")

content = file.read()

# A bug in our code crashes here

result = int("this is not a number")   # ValueError!

file.close()   # This line is never reached. File stays open.

"The close never runs. The file handle is leaked.

Python solves this with the with statement. It guarantees the file is closed when the block exits — whether it finished normally or crashed midway."

with open("apache_access_error.log", "r") as file:

    content = file.read()

    print(content)

# File is automatically closed here — no matter what happened above

"The with block creates a protected zone. When Python leaves it, .close() is called automatically. You cannot forget it. You cannot accidentally skip it.

From here on, we always open files with with. Make it a reflex."


<iframe src="https://scaler-mk.github.io/algo-visualizer/IPR/Beginner Python/Lec 11 - File & Exception Handling/Animation_2_WithVsManualClose.html" width="100%" height="820" frameborder="0" style="border:1px solid #3a3f4b;border-radius:8px;"></iframe>

### **1.6 — Handling Errors with try/except**

**Instructor:**

"File operations fail in the real world. Files get moved, renamed, deleted. On shared servers you might not have permission to read certain files. We need to handle these failures gracefully instead of crashing with a traceback.

The tool for this is try...except."

try:

    with open("apache_access_error.log", "r") as file:

        content = file.read()

        print(content)

except FileNotFoundError:

    print("The log file was not found. Check the file name and path.")

except PermissionError:

    print("You do not have read permission. Try running with sudo.")

except Exception as e:

    print(f"An unexpected error occurred: {e}")

"Python checks the except blocks top to bottom and runs the first one that matches the error.

There is also an else clause — it runs only if the try block completed with no errors. A clean way to separate success logic from error handling:"

try:

    with open("apache_access_error.log", "r") as file:

        content = file.read()

except FileNotFoundError:

    print("File not found.")

except PermissionError:

    print("Permission denied.")

else:

    # Only runs if try completed successfully — no exceptions

    print("File read successfully.")

    print(content)

"Think of else as saying: if everything went fine, now do this. We will use this pattern in our final script."


<iframe src="https://scaler-mk.github.io/algo-visualizer/IPR/Beginner Python/Lec 11 - File & Exception Handling/Animation_3_TryExceptElse.html" width="100%" height="820" frameborder="0" style="border:1px solid #3a3f4b;border-radius:8px;"></iframe>

### **1.7 — The Manager Calls: The File Is 50 GB**

**Instructor:**

"We have our reading working well on the sample file. Then your manager calls.

'By the way — this server has been running for six months without a log rotation. That file is about 50 gigabytes.'

Your laptop has 16 GB of RAM.

Let's think about what happens when our current code runs on that file."

with open("apache_access_error.log", "r") as file:

    content = file.read()   # Tries to load 50 GB into one string

"Python tries to allocate 50 GB of memory for the string content. The operating system refuses. You get a MemoryError and the script dies with no output at all.

What about .readlines()?"

with open("apache_access_error.log", "r") as file:

    lines = file.readlines()   # A list with hundreds of millions of strings

"Same problem. Every line of the 50 GB file is still loaded into memory — just organised into a list instead of a single string. The list might take even more memory than the raw string because of Python object overhead.

The problem with both .read() and .readlines() is the same: they load everything before handing control back to you. We need to process the file while reading it — one line at a time, throwing each one away before fetching the next."

### **1.8 — Streaming: The Right Way for Large Files**

**Instructor:**

"Here is something that might surprise you. A file object in Python is an iterator. You can loop over it directly with a for loop and Python fetches exactly one line per iteration."

with open("apache_access_error.log", "r") as file:

    for line in file:            # One line enters memory per loop cycle

        print(line.strip())      # Process it — next iteration discards it

"At any given moment, only one line is in memory. Python fetches it, you process it, the next iteration fetches the next one and the previous is discarded.

This is called streaming. Your RAM usage stays flat — a few kilobytes — whether the file is 1 MB or 500 GB. Let's compare all three approaches side by side:"

# .read() — everything loads first, then you work with it

with open("apache_access_error.log", "r") as file:

    content = file.read()

    # RAM at this point: entire file (50 GB) — crashes

# .readlines() — everything loads as a list first

with open("apache_access_error.log", "r") as file:

    lines = file.readlines()

    # RAM at this point: entire file in a list (50+ GB) — crashes

# Streaming — one line at a time, always

with open("apache_access_error.log", "r") as file:

    for line in file:

        # RAM at this point: one line (a few hundred bytes) — works fine

        print(line.strip())

"The streaming loop also starts producing output immediately. You do not wait for the file to finish loading. On a 50 GB file, .read() crashes before showing you anything. The streaming loop prints the first error line within milliseconds."


<iframe src="https://scaler-mk.github.io/algo-visualizer/IPR/Beginner Python/Lec 11 - File & Exception Handling/Animation_4_MemoryComparison.html" width="100%" height="820" frameborder="0" style="border:1px solid #3a3f4b;border-radius:8px;"></iframe>

### **1.9 — One More Problem: Corrupt Bytes**

**Instructor:**

"Real production log files can contain corrupt bytes — invalid characters written during a memory fault or an attack. When Python tries to decode them as text, it raises a UnicodeDecodeError and your script dies, potentially halfway through a 50 GB file.

We fix this with the errors parameter in open():"

with open("apache_access_error.log", "r", encoding="utf-8", errors="ignore") as file:

    for line in file:

        print(line.strip())

"errors='ignore' tells Python: if you encounter a byte you cannot decode, skip it and keep going. You lose that one corrupt character but you do not lose the entire analysis.

Now let's put everything from this chapter together in one clean block:"

try:

    with open("apache_access_error.log", "r", encoding="utf-8", errors="ignore") as file:

        for line in file:

            print(line.strip())

except FileNotFoundError:

    print("The log file was not found.")

except PermissionError:

    print("You do not have read permission for this file.")

except Exception as e:

    print(f"An unexpected error occurred: {e}")

else:

    print("Done reading the file.")

"This handles any file size, survives corrupt data, closes the file automatically, and reports failures cleanly. This is our foundation. Everything in Chapter 2 builds on top of this."

## **CHAPTER 2: Manager Wants Names — Find the Top Offending IPs**

### **2.1 — The New Requirement**

**Instructor:**

"Your manager looks at the output streaming by and says: 'This is useful, but I need something more specific. Can you tell me which IP addresses are generating the most errors? I want the top troublemakers so we can block them.'

Now we need to do three things while streaming:

- Filter to only error and warning lines

- Extract the IP address from each of those lines

- Count how many error lines each IP appears in and store examples as evidence

Let's build each piece."

### **2.2 — Filtering Lines**

**Instructor:**

"Our log lines look like this:"

172.16.0.89 - - [24/Apr/2026:02:14:33] [error] [client 172.16.0.89] File not found: /admin

192.168.1.5  - - [24/Apr/2026:02:14:40] [info]  Server restarting normally

172.16.0.89 - - [24/Apr/2026:02:15:22] [warn]  [client 172.16.0.89] ModSecurity: Access denied


![Anatomy of an Apache Log Line](https://d2beiqkhq929f0.cloudfront.net/public_assets/assets/000/196/014/original/Image_2_ApacheLogAnatomy.png?1778539065)

"We only care about lines containing [error] or [warn]. A simple if check inside the loop handles this:"

with open("apache_access_error.log", "r", encoding="utf-8", errors="ignore") as file:

    for line in file:

        lower_line = line.lower()    # Lowercase once — makes comparisons case-insensitive

        if "[error]" in lower_line or "[warn]" in lower_line:

            print(line.strip())

"We lowercase the line once at the top of the loop and store it as lower_line. This handles [ERROR], [Error], and [error] all the same way without repeating the .lower() call on every comparison."

### **2.3 — Counting with Counter**

**Instructor:**

"For every error line we see, we want to increment the count for whatever IP caused it.

Python's collections module gives us Counter, which is built exactly for this:"

from collections import Counter

troublemaker_ips = Counter()

troublemaker_ips["172.16.0.89"] += 1   # New key — starts at 0, becomes 1

troublemaker_ips["172.16.0.89"] += 1   # Same key — becomes 2

troublemaker_ips["192.168.1.10"] += 1  # Different key — starts at 0, becomes 1

print(troublemaker_ips)

# Counter({'172.16.0.89': 2, '192.168.1.10': 1})

"With a plain dictionary, accessing a key that does not exist raises KeyError. Counter treats missing keys as zero automatically — no crash, no extra checks.

Counter also gives us .most_common(n) which returns the top n entries sorted by count:"

print(troublemaker_ips.most_common(3))

# [('172.16.0.89', 2), ('192.168.1.10', 1)]

"No sorting code needed. Built in."

### **2.4 — Storing Examples with defaultdict**

**Instructor:**

"Counts tell us who the top offenders are. We also want to store a few example lines per IP as actual evidence.

We need a dictionary that maps each IP to a list of examples. With a plain dict, you have to check whether the key exists before appending:"

# With a plain dict — tedious

if ip not in examples:

    examples[ip] = []

examples[ip].append(line)

"defaultdict removes that entirely:"

from collections import defaultdict

ip_examples = defaultdict(list)

ip_examples["172.16.0.89"].append("Line 2: File not found: /admin")

ip_examples["172.16.0.89"].append("Line 9: ModSecurity: Access denied")

print(ip_examples["172.16.0.89"])

# ['Line 2: File not found: /admin', 'Line 9: ModSecurity: Access denied']

"The list argument to defaultdict means: whenever a new key is first accessed, automatically create an empty list for it. No KeyError. No manual if check. Just append directly."


<iframe src="https://scaler-mk.github.io/algo-visualizer/IPR/Beginner Python/Lec 11 - File & Exception Handling/Animation_5_CounterDefaultdict.html" width="100%" height="820" frameborder="0" style="border:1px solid #3a3f4b;border-radius:8px;"></iframe>

### **2.5 — Extracting the IP: Safe String Parsing**

**Instructor:**

"Now we need to pull the IP address out of each line. Apache logs show an IP in two places:"

Format 1 — IP at start of line:    172.16.0.89 - - [24/Apr/2026] [error] ...

Format 2 — IP inside brackets:     ... [client 172.16.0.89] File not found

"We will write a helper function. For Format 1, the IP is the first word — everything before the first space.

Your first instinct might be:"

ip = line.split()[0]

"This works almost always. But what if line is a completely empty string? A blank line written during a crash?"

line = ""

parts = line.split()   # Returns an empty list []

ip = parts[0]          # IndexError: list index out of range — script crashes

"Your script dies on one blank line in a 50 GB file. We use .find() instead. It returns the index of the first match, and returns -1 if nothing is found — never raises an exception:"

line = ""

first_space = line.find(" ")   # Returns -1 — no crash

if first_space != -1:

    ip = line[:first_space]    # Only slice if we found a space

"Here is the full extraction function handling both formats:"

def extract_ip_from_line(line: str) -> str | None:

    """Return the IP address from an Apache log line, or None if not found."""

    # Format 1: IP inside brackets -> [client 172.16.0.89]

    client_start = line.find("[client ")

    if client_start != -1:

        ip_start = client_start + 8           # Skip past the 8 characters "[client "

        ip_end = line.find("]", ip_start)     # Find the closing bracket

        if ip_end != -1:

            candidate = line[ip_start:ip_end]

            # Validate: real IPv4 has exactly 3 dots and only digits/dots

            if candidate.count(".") == 3 and all(c.isdigit() or c == "." for c in candidate):

                return candidate

    # Format 2: IP at start of line -> 192.168.1.10 - - [date]

    first_space = line.find(" ")

    if first_space != -1:

        candidate = line[:first_space]

        if candidate.count(".") == 3 and all(c.isdigit() or c == "." for c in candidate):

            return candidate

    return None

"We check Format 1 first since it is more specific. We validate the candidate before returning — a real IPv4 address always has exactly three dots and only digits and dots. If neither format yields a valid result, we return None.

In the main loop, if ip: safely skips None returns without crashing."


<iframe src="https://scaler-mk.github.io/algo-visualizer/IPR/Beginner Python/Lec 11 - File & Exception Handling/Animation_6_SafeIPExtract.html" width="100%" height="820" frameborder="0" style="border:1px solid #3a3f4b;border-radius:8px;"></iframe>

### **2.6 — The Complete Script**

**Instructor:**

"Every piece is ready. Here is the full script assembled."

import time

from collections import Counter, defaultdict

def extract_ip_from_line(line: str) -> str | None:

    """Return the IP address from an Apache log line, or None if not found."""

    # Format 1: IP inside brackets -> [client 172.16.0.89]

    client_start = line.find("[client ")

    if client_start != -1:

        ip_start = client_start + 8

        ip_end = line.find("]", ip_start)

        if ip_end != -1:

            candidate = line[ip_start:ip_end]

            if candidate.count(".") == 3 and all(c.isdigit() or c == "." for c in candidate):

                return candidate

    # Format 2: IP at start of line -> 192.168.1.10 - - [date]

    first_space = line.find(" ")

    if first_space != -1:

        candidate = line[:first_space]

        if candidate.count(".") == 3 and all(c.isdigit() or c == "." for c in candidate):

            return candidate

    return None

# Setup

start_time = time.time()

troublemaker_ips = Counter()

ip_examples = defaultdict(list)

error_count = 0

warning_count = 0

# Main analysis

try:

    with open("apache_access_error.log", "r", encoding="utf-8", errors="ignore") as file:

        for line_num, line in enumerate(file, 1):

            lower_line = line.lower()

            if "[error]" in lower_line or "[warn]" in lower_line:

                if "[error]" in lower_line:

                    error_count += 1

                else:

                    warning_count += 1

                ip = extract_ip_from_line(line)

                if ip:

                    troublemaker_ips[ip] += 1

                    if len(ip_examples[ip]) < 3:

                        snippet = line.strip()[:120]

                        ip_examples[ip].append((line_num, snippet))

except FileNotFoundError:

    print("FATAL: The file 'apache_access_error.log' was not found.")

    print("Check that the file name and path are correct.")

except PermissionError:

    print("FATAL: You do not have read permission for this file.")

    print("On Linux, try: sudo python3 analyzer.py")

except Exception as e:

    print(f"FATAL: An unexpected error occurred: {e}")

else:

    elapsed = time.time() - start_time

    print("\n--- SUMMARY REPORT ---")

    print(f"  Total error lines:    {error_count}")

    print(f"  Total warning lines:  {warning_count}")

    print(f"  Unique IPs flagged:   {len(troublemaker_ips)}")

    print("\n--- TOP 5 TROUBLEMAKER IPs ---")

    for ip, count in troublemaker_ips.most_common(5):

        print(f"\n  {ip}  ({count} events)")

        for line_num, snippet in ip_examples.get(ip, []):

            print(f"    Line {line_num}: {snippet}")

    print(f"\n  Time taken: {elapsed:.2f} seconds")

## **CHAPTER 3: Running the Script and Reading the Output (10 minutes)**

### **3.1 — Live Run**

**Instructor:**

"Let's run this on the sample file."

(Run the script live.)

**Expected output:**

--- SUMMARY REPORT ---

  Total error lines:    47

  Total warning lines:  12

  Unique IPs flagged:   3

--- TOP 5 TROUBLEMAKER IPs ---

  172.16.0.89  (18 events)

    Line 2:  172.16.0.89 - - [24/Apr/2026:02:15:01] [error] [client 172.16.0.89] Segfault at instruction

    Line 5:  172.16.0.89 - - [24/Apr/2026:02:16:44] [error] [client 172.16.0.89] File not found: /admin

    Line 9:  172.16.0.89 - - [24/Apr/2026:02:18:02] [warn]  [client 172.16.0.89] ModSecurity: Access denied

  192.168.1.10  (11 events)

    Line 3:  192.168.1.10 - - [24/Apr/2026:02:15:22] [error] [client 192.168.1.10] Disk quota exceeded

  Time taken: 0.03 seconds

"IP 172.16.0.89 caused 18 events including segfaults. We have exact line numbers and the actual log text. That is actionable — hand this to your manager and the IP gets blocked within minutes.

Now let's rename the file to trigger a failure."

(Rename the file.)

FATAL: The file 'apache_access_error.log' was not found.

Check that the file name and path are correct.

"A clean, readable message instead of a six-line Python traceback."

## **CHAPTER 4: Key Takeaways and Homework (10 minutes)**

### **4.1 — Tracing Back Through the Problem**

**Instructor:**

"Every concept we learned today came from a real need in the problem.

'How do I read the log file?' gave us open(), file modes, .read(), .readline(), .readlines(), the with statement, and try/except/else.

'The file is 50 GB' showed us why .read() and .readlines() fail at scale and introduced streaming with for line in file: — plus errors='ignore' for corrupt data.

'Find the top offending IPs' gave us Counter for safe counting, defaultdict for building lists without manual checks, and .find() for parsing that never crashes on blank or malformed lines.

The pattern: understand the constraint first, then reach for the right tool."

### **4.2 — Homework Assignment (Optional)**

**Instructor:**

"Extend the script to also report the top broken endpoints — the URL paths that appear most often in error lines, things like /api/v1/user/profile or /admin/login.

Your tasks:

- Write a function extract_endpoint_from_line(line) that returns the URL path as a string, or None if it cannot find one. Use .find() throughout — not .split()[n] indexing.

- Handle the case where the URL is missing, with no crash.

- Add an endpoint_errors Counter to the main loop alongside troublemaker_ips.

- Add a 'Top 3 Broken Endpoints' section to the report in the else block.

Before plugging your function into the main loop, test it on two inputs: a normal log line and a blank string. Confirm both behave correctly before trusting it with 50 GB of data."

*End of Teaching Script*

Cue Cards

# **Cue Card — Apache Log Forensics Lecture**

Keep this beside you while teaching. Short phrases only — expand in your own words.

## **CHAPTER 1 — Reading the Log File (~45 min)**

### **Hook**

- Friday evening, on-call engineer, server throwing errors

- One clue: apache_access_error.log

- First question to class: "How do we open a file in Python?"

### **open()**

- file = open("apache_access_error.log")

- OS hands program a file object — a connection to the file

- **[DEMO]** open and show the variable type

### **File Modes**

- Write the table on board

| **Mode** | **What it does** |
| --- | --- |
| "r" | Read text (default) |
| "r+" | Read + write |
| "rb" | Read raw bytes |
| "w" | Write — WIPES existing file |
| "a" | Append to end |

- Stress "w" danger — wipes evidence before you read it

- "rb" — for images, zips, not text logs

- We use "r" — always be explicit

### **Three Reading Methods**

**.read()**

- Entire file → one big string

- **[DEMO]** content = file.read() → print it

- Show the \n characters between lines

**.readline()**

- One line per call, advances each time

- **[DEMO]** call it three times, show output

- Point out \n at end → use .strip()

**.readlines()**

- Entire file → list of line strings

- **[DEMO]** show list output, index access, loop over it

**[ASK CLASS]** "Which method loads the most data into memory?"

Answer: .read() and .readlines() both load everything. .readline() is the most conservative.

### **Closing Files — with statement**

- Every open() needs a close() — OS resource leak if skipped

**[DEMO]** manual close first:
 file = open(...)content = file.read()file.close()

**[DEMO]** show the bug — crash between open and close:
 file = open(...)int("not a number")   # crash herefile.close()          # never runs

**[DEMO]** with as the fix:
 with open(...) as file:    content = file.read()# auto-closed here, always

- **KEY LINE:** "You cannot forget it. You cannot accidentally skip it."

### **try / except / else**

- Files go missing, permissions change — need graceful handling

- **[DEMO]** misspell filename → show raw FileNotFoundError traceback

**[DEMO]** add try/except:
 try:    with open(...) as file:        content = file.read()except FileNotFoundError:    print("File not found.")except PermissionError:    print("No permission. Try sudo.")except Exception as e:    print(f"Unexpected: {e}")else:    print("Success!")    print(content)

- else — only runs if NO exception occurred

- Python checks except blocks top to bottom, runs first match

**[CHECKPOINT]** "So far: open, modes, three reading methods, with, try/except. Everyone good before we continue?"

### **50 GB Reveal — Manager Calls**

- "Server running six months, no log rotation. File is 50 GB."

- **[ASK CLASS]** "What happens when .read() runs on 50 GB? Your laptop has 16 GB RAM."

- .read() → MemoryError — entire file into one string → OS refuses

- .readlines() → same problem — entire file into a list → same crash

**[ASK CLASS]** "How do we read a file without loading it all?"

### **Streaming — for line in file**

- File object is an iterator — loop directly over it

**[DEMO]**:
 with open(..., "r", encoding="utf-8", errors="ignore") as file:    for line in file:        print(line.strip())

- One line per iteration — previous line discarded before next loads

- RAM stays flat — few KB — regardless of file size

- errors="ignore" — corrupt bytes in real logs cause UnicodeDecodeError → ignore skips them silently

- **[DEMO]** side-by-side comparison showing RAM behaviour of all three approaches

**[CHECKPOINT]** End of Chapter 1 — "We can handle any file size, survive corrupt data, close properly, handle failures cleanly. This is our foundation."

## **CHAPTER 2 — Finding the Top Offending IPs (~25 min)**

### **New Requirement**

- Manager: "Tell me which IPs appear most in error lines. I want to block them."

- Three things needed: filter lines → extract IP → count + store examples

### **Filtering Lines**

- Only want [error] and [warn] lines — ignore [info]

**[DEMO]**:
 lower_line = line.lower()   # lowercase onceif "[error]" in lower_line or "[warn]" in lower_line:    ...

- Lowercase once at top of loop — handles ERROR / Error / error all the same

### **Counter**

- Need to count IPs — plain dict raises KeyError on new keys

- Counter auto-initialises new keys to zero

**[DEMO]**:
 from collections import Countertroublemaker_ips = Counter()troublemaker_ips["172.16.0.89"] += 1   # works even first timetroublemaker_ips.most_common(5)         # built-in sorted top 5

### **defaultdict**

- Need a list of examples per IP — plain dict needs if key not in dict check

- defaultdict(list) auto-creates empty list on first access

**[DEMO]**:
 from collections import defaultdictip_examples = defaultdict(list)ip_examples["172.16.0.89"].append("some line")   # no KeyError

### **IP Extraction — Safe Parsing**

- Two formats in Apache logs:

- [client 172.16.0.89] — IP inside brackets

- 172.16.0.89 - - [date] — IP at start of line

- **[ASK CLASS]** "How do we get the first word of a line?"

 Common answer: line.split()[0]

**[DEMO]** the crash:

 line = ""

line.split()[0]   # IndexError — empty list

**[DEMO]** the safe fix:

 first_space = line.find(" ")   # returns -1 if not found — never crashes

if first_space != -1:

    candidate = line[:first_space]

- Walk through extract_ip_from_line() function:

- Check Format 1 first (more specific)

- Validate: .count(".") == 3 and all chars are digits or dots

- Return None if nothing found

- In loop: if ip: safely skips None

### **Full Script Walkthrough**

- **[DEMO]** show complete script assembled

- Point out: enumerate(file, 1) gives line numbers starting at 1

- Point out: len(ip_examples[ip]) < 3 — cap examples at 3 per IP

- Point out: line.strip()[:120] — trim for clean terminal output

- Point out: else block for the report — only runs on success

- Point out: .most_common(5) and .get(ip, []) in the report

## **CHAPTER 3 — Live Demo (~10 min)**

- Run on sample file → walk through output

- Point out: IP, count, line numbers, actual log text

- **[DEMO]** rename the file → trigger FileNotFoundError

- Show clean message vs raw traceback — "this is what production-grade looks like"

## **CHAPTER 4 — Wrap Up (~10 min)**

### **Trace back through the problem**

- "How to read the file?" → open, modes, read/readline/readlines, with, try/except

- "File is 50 GB" → why read/readlines fail, streaming, errors=ignore

- "Find top IPs" → Counter, defaultdict, .find() over .split()

**KEY MESSAGE:** "We never learned a concept until the problem demanded it. That is how real engineering decisions are made."

### **Homework Reminder**

- Add extract_endpoint_from_line() function

- Use .find() — not .split()[n]

- Test on blank string AND normal line before plugging into main loop

- Add endpoint_errors Counter

- Add Top 3 Broken Endpoints to report

## **Quick Reference — Things to Remember Mid-Lecture**

| **Moment** | **What to do** |
| --- | --- |
| After modes table | Ask: "Which mode would destroy our log file?" (answer: w) |
| After three reading methods | Ask: "Which loads most into memory?" |
| Before with statement | Demo the close() bug first — makes with feel necessary |
| Before 50 GB reveal | Pause — let students realise the problem before naming it |
| Before .find() | Demo the IndexError on empty string first |
| End of each section | Check faces — ask if anyone wants a recap before moving on |

Quick Homework Questions

# **MCQ Assessment — Apache Log Forensics Lecture**

**15 Questions | 5 Easy · 5 Medium · 5 Hard**

## **EASY**

**Q1.** Your team stores six months of server logs in apache_access_error.log. A new engineer writes the following line to start analyzing it:

file = open("apache_access_error.log", "w")

What happens the moment this line executes?

- A) The file opens in write mode and waits for content to be written

- B) Python raises a FileNotFoundError because the file already exists

- C) The file is wiped completely clean before a single line is read

- D) The file opens successfully and existing content is preserved

**Answer: C** *"**w**"** mode truncates the file to zero bytes immediately on open, regardless of existing content. The file does not need to be written to for the damage to occur.*

**Q2.** A student calls file.readline() once on a log file. The line in the file is:

192.168.1.10 - - [24/Apr/2026] [error] disk full

Which of the following shows exactly what the variable holds?

- A) '192.168.1.10 - - [24/Apr/2026] [error] disk full'

- B) '192.168.1.10 - - [24/Apr/2026] [error] disk full\n'

- C) ['192.168.1.10', '-', '-', '[24/Apr/2026]', '[error]', 'disk', 'full']

- D) 192.168.1.10

**Answer: B** *.readline()** includes the newline character **\n** at the end. Use **.strip()** to remove it when you need clean output.*

**Q3.** What is the primary reason to open a file using with open(...) as file: instead of calling file.close() manually?

- A) It makes the file read faster

- B) It automatically catches FileNotFoundError without a try/except block

- C) It guarantees the file is closed even if an error occurs inside the block

- D) It allows the same file to be opened from multiple places in the code

**Answer: C** *The **with** block runs cleanup code on exit no matter how the block exits — normal completion or exception. A manual **close()** can be skipped entirely if an exception fires between **open()** and **close()**.*

**Q4.** In a try...except...else block used for file reading, when does the else block execute?

- A) Every time, right after the try block finishes regardless of outcome

- B) Only when a FileNotFoundError is raised

- C) Only when the try block completes without raising any exception

- D) Only when all except blocks have been checked and none matched

**Answer: C** *The **else** block is the **"**success path.**"** If any exception is raised inside **try**, Python jumps to the matching **except** and the **else** block is skipped entirely.*

**Q5.** A log file has exactly 4 lines. After running lines = file.readlines(), what does print(lines[2]) output?

- A) The second line of the file, stripped of whitespace

- B) The third line of the file, including the newline character at the end

- C) The second line of the file, including the newline character at the end

- D) A list containing the words of the third line

**Answer: B** *List indexing starts at 0, so index 2 is the third line. **.readlines()** preserves the **\n** character at the end of each line.*

## **MEDIUM**

**Q6.** A student writes a helper function to extract the first word from each log line:

def get_first_word(line):

    return line.split()[0]

This works on every line during testing but crashes midway through a real 50 GB log file in production. What is the most likely cause?

- A) .split() does not work correctly on strings longer than 1000 characters

- B) The log file contains a blank line and calling .split() on an empty string returns an empty list, making [0] raise an IndexError

- C) .split() without an argument only splits on spaces, not tabs, so some lines are returned as one unsplit chunk

- D) Production log files use a different line ending format that confuses .split()

**Answer: B** *.split()** on an empty string or a string with only whitespace returns **[]**. Accessing index **[0]** on an empty list always raises **IndexError**. Use **.find(**"** **"**)** and check for **-1** instead.*

**Q7.** A student needs to process a 40 GB log file on a machine with 16 GB of RAM. They write four versions. Which one will not crash with a MemoryError?

- A)

with open("log.txt", "r") as f:

    content = f.read()

    for line in content.split("\n"):

        process(line)

- B)

with open("log.txt", "r") as f:

    lines = f.readlines()

    for line in lines:

        process(line)

- C)

with open("log.txt", "r") as f:

    for line in f:

        process(line)

- D) Both A and B are fine — Python internally optimises large string and list operations to avoid loading everything into memory

**Answer: C** *A and B both load the entire file into memory before processing begins. C iterates the file object directly — Python fetches one line per iteration and discards it before fetching the next, keeping RAM usage flat regardless of file size. D is false.*

**Q8.** A script streams through a large log file without errors='ignore'. Partway through the file, a line contains a byte that cannot be decoded as UTF-8. What happens?

- A) Python skips that line and continues processing the rest of the file

- B) Python replaces the unreadable byte with a ? character and continues

- C) Python raises a UnicodeDecodeError and the script stops at that line

- D) Python automatically retries the line using the latin-1 encoding

**Answer: C** *Without **errors='ignore'**, a single corrupt byte kills the entire script. On a 50 GB file, you could lose hours of analysis to one bad character written during a memory fault.*

**Q9.** A student writes the following code to count IP addresses:

counts = {}

counts["192.168.1.1"] += 1

The very first time "192.168.1.1" appears, what happens?

- A) counts["192.168.1.1"] is set to 1 successfully

- B) A KeyError is raised because the key does not exist yet

- C) counts["192.168.1.1"] is initialised to 0 and then incremented to 1

- D) Python creates the key and sets its value to None

**Answer: B** *A plain dictionary raises **KeyError** when you try to access or modify a key that does not exist. **Counter** solves this by treating missing keys as 0, making **counter[key] += 1** safe on first access.*

**Q10.** A student replaces ip_examples = {} with ip_examples = defaultdict(list). What happens when they access ip_examples["new_ip"] for the very first time?

- A) A KeyError is raised, same as a plain dict

- B) None is returned and nothing is stored

- C) An empty list is returned and that empty list is also stored under the key

- D) An empty list is returned but nothing is stored until .append() is explicitly called

**Answer: C** *defaultdict** creates and stores the default value immediately on first access, not just on modification. After **ip_examples[**"**new_ip**"**]**, the key exists in the dictionary with value **[]**.*

## **HARD**

**Q11.** A student writes this code to process a log file:

try:

    with open("log.txt", "r") as file:

        for line in file:

            if "[error]" in line:

                error_count += 1

except FileNotFoundError:

    print("File missing")

except Exception as e:

    print(f"Error: {e}")

else:

    print(f"Done. {error_count} errors found.")

The file exists and is readable. It contains 200 error lines in the first 846 lines, then on line 847 a corrupt byte causes a UnicodeDecodeError. What gets printed?

- A) Done. 200 errors found.

- B) File missing

- C) Error: 'utf-8' codec can't decode byte 0xff in position 3

- D) Nothing — the script exits silently after the exception

**Answer: C** *UnicodeDecodeError** is not a **FileNotFoundError**. It is caught by **except Exception as e**. Because an exception was raised, the **else** block does not run. 200 errors were counted but never reported.*

**Q12.** Which of the following code snippets has a file handle leak?

- A)

with open("log.txt") as f:

    data = f.read()

- B)

f = open("log.txt")

data = f.read()

f.close()

- C)

f = open("log.txt")

data = f.read()

process(data)   # this line raises a ValueError

f.close()

- D)

with open("log.txt") as f:

    for line in f:

        if "error" in line:

            raise ValueError("found error")

**Answer: C** *In C, if **process(data)** raises an exception, execution jumps out of the current scope and **f.close()** is never reached. The file handle stays open. In D, the **with** statement guarantees closure even when an exception is raised inside the block — so D has no leak.*

**Q13.** Given this function and this input line, what does it return?

def extract_ip_from_line(line):

    client_start = line.find("[client ")

    if client_start != -1:

        ip_start = client_start + 8

        ip_end = line.find("]", ip_start)

        if ip_end != -1:

            candidate = line[ip_start:ip_end]

            if candidate.count(".") == 3 and all(c.isdigit() or c == "." for c in candidate):

                return candidate

    first_space = line.find(" ")

    if first_space != -1:

        candidate = line[:first_space]

        if candidate.count(".") == 3 and all(c.isdigit() or c == "." for c in candidate):

            return candidate

    return None

line = "10.0.0.1 - - [24/Apr/2026] [error] [client 172.16.0.89] disk full"

- A) "10.0.0.1" — Format 2 is checked first and matches immediately

- B) "172.16.0.89" — Format 1 is checked first and finds the IP in the bracket

- C) None — both IPs are found so the function cannot decide which to return

- D) "10.0.0.1" — Format 1 fails validation because the IP is inside a bracket

**Answer: B** *The function checks Format 1 (**[client ...]**) before Format 2 (start of line). This line contains **[client 172.16.0.89]**, which passes validation and is returned immediately. Format 2 is never reached. The function returns the more specific IP — the one actually identified as the client.*

**Q14.** A student wants to read through a log file and then append a summary line at the end. They write:

with open("log.txt", "r") as file:

    for line in file:

        process(line)

with open("log.txt", "w") as file:

    file.write("--- Analysis complete ---")

What is the actual outcome when this script runs?

- A) The summary line is appended to the end of the log file as intended

- B) Python raises an error because the same file cannot be opened twice in one script

- C) The second open() with "w" erases the entire log file and the only content remaining is the summary line

- D) The "r" block holds a lock on the file so the second open() fails silently

**Answer: C** *"**w**"** mode wipes the file on open, not on write. The student needed **"**a**"** (append) mode. The entire six months of log data is now gone, replaced by one line.*

**Q15.** A student writes this script to count errors per IP:

from collections import Counter, defaultdict

ip_counts = Counter()

ip_lines = defaultdict(list)

try:

    with open("log.txt", "r") as f:

        for line_num, line in enumerate(f):

            if "[error]" in line:

                ip = line.split()[0]

                ip_counts[ip] += 1

                ip_lines[ip].append(line_num)

except Exception as e:

    print(f"Error: {e}")

else:

    print(ip_counts.most_common(3))

The file is readable and line 500 is completely blank (just a newline character \n). What happens when the script reaches line 500?

- A) The script crashes at line 500 with an IndexError because line.split()[0] fails on a blank line

- B) The blank line is processed and an empty string "" is added to ip_counts

- C) The blank line is skipped safely and the script continues without any error

- D) enumerate(f) skips blank lines automatically so line 500 is never seen

**Answer: C** *The **if **"**[error]**"** in line:** check runs before **line.split()[0]**. A blank line does not contain **"**[error]**"**, so the **if** block never executes and **split()[0]** is never called on the blank line. The dangerous code is never reached. The filter acts as an unintentional but effective guard.*

*End of Assessment*