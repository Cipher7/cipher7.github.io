---
title: 'Code-in-the-Middle : An Introduction to IR'
author: cipher007
date: 2025-10-18 12:00:00 -0400
categories: [Red Teaming]
tags: [redteam, Intermediate Representation, EDR] 
media-subpath: /assets/img/citm/
---


# The EDR Wall

## EDR Evasion landscape

EDR evasion followed a post-compilation approach, these were characterized by :

1. **Run time packers** : Tools like UPX, Enigma Protector, and custom packers encrypted or compressed compiled binaries. These operated entirely after compilation, wrapping executables in protective layers. They had high shannon entropy which made them suspicious and prone to further investigations by the EDRs.
2. **Manual Binary modifications** : Attackers used hex editors and disassemblers (IDA Pro, Hopper) to directly patch compiled binaries, modifying jump opcodes and instruction sequences
3. **Reflective DLL loading** : Stephen Fewer's technique became foundational, allowing manual DLL loading without Windows loaders to bypass API hooks. Still used today by many red teams & attackers around the world.
4. **Custom loaders** : These were programs which had the core job of loading and executing a malicious shellcode, the shellcode was either remotely fetched or it was present in the loader in an encrypted form and was decrypted in run-time. 

These had a few issues which made them non-effective against defenders:

1. **Maintenance Overhead**: Each binary required individual treatment, complicating update cycles
2. **Limited Semantic Integration**: Binary-level changes couldn't leverage program semantics effectively
3. **Signature Vulnerability**: Post-compilation modifications created recognizable patterns detectable by static analysis.


A new and innovative approach was released by :
**Pascal Junod, Julien Rinaldini, Johan Wehrli and Julie Michielin**

This was a research initiated by the Information security group of the University of Applied Sciences and Arts Western Switzerland of Yverdon-les-Bains.

They created an Obfuscated-LLVM where software could be obfuscated while compilation is being done. This was a breakthrough for software protection where reversing binaries would become hard and complicated. 

[https://github.com/obfuscator-llvm/obfuscator/wiki](https://github.com/obfuscator-llvm/obfuscator/wiki)

The featured supported by this were :

- Control Flow Flattening
- Bogus Control Flow
- Functions annotations
- Instructions substitutions

These were all really cool concepts where source code could be obfuscated during compilation, this meant that the main source code did not have to come with extra code for obfuscations.

![image.png](/assets/img/citm/image.png)

Here are some research findings done which clearly states how binaries obfuscated during compilation survived reversing and other analysis better than obfuscations applied directly at source level.

1. **Madou et al. (2006)**: First empirical demonstration that source-level protections don't survive compilation—compilers optimize away many obfuscations.
[link](https://www.researchgate.net/publication/221610193_On_the_Effectiveness_of_Source_Code_Transformations_for_Binary_Obfuscation)
2. **Obfuscator-LLVM Study (2015)**: Demonstrated compile-time protection feasibility by applying obfuscations *after* optimization passes but *within* compilation pipeline
[link](https://crypto.junod.info/spro15.pdf)
3. **Tigress vs. OLLVM Analysis**: Source-to-source transformations (Tigress) vs. IR-level transformations (OLLVM) showed IR-level techniques survive better.
[link](https://eprints.cs.univie.ac.at/7811/1/camera_ready.pdf) &
[Tigress C obfuscator](https://tigress.wtf/index.html)

But our primary goal is bypassing EDRs and security solutions.

All of these techniques applied by LLVM does seem very fun and it has been integrated into many tools - AdaptixC2, Covenant C2, multiple reflective loaders, OffensiveRust etc. All these are popular and widely used, but there is still something lacking in this type of implementation.

The current implementation focuses on obfuscating the malware itself, although this sounds like exactly what is intended of LLVM, the detection rates are still high. [Research](https://trustedsec.com/blog/behind-the-code-assessing-public-compile-time-obfuscators-for-enhanced-opsec) by **Christopher Paschen of TrustedSec** does an in-depth comparison of how conventional payloads and llvm compiled payloads perform in evading detections. 

This is what he says -
> ”I do not feel that adding LLVM obfuscation passes meaningfully impacts the detection ratio of native executables when considering disk scanning. It is entirely possible that when attempting to avoid a known signature use of LLVM obfuscation, passes could be effectively deployed to modify the machine code in such a way that either disk or memory-based scans would be defeated. I’m now of the opinion that if you want/need to use a technique and you know there are specific detections in place, then modifying the bad code manually is largely effective.”
>
> <p style="text-align:right">-Christopher Paschen</p>

<br>
<br>

## Core Idea : Evasion using IR

![image.png](/assets/img/citm/image%202.png)

In the above procedure, LLVM IR is something that has immense potential and is often overlooked. It has really good documentation and `almost` stable.

Now, we can sit and write LLVM IR code directly. This would be feasible for relatively simple programs.

```
; A simple program to print Hello World in LLVM IR

@msg = constant [14 x i8] c"Hello, world!\00"

declare i32 @puts(i8*)

define i32 @main() {
entry:
  %ptr = getelementptr [14 x i8], [14 x i8]* @msg, i32 0, i32 0
  call i32 @puts(i8* %ptr)
  ret i32 0
}
```

 

It would get complicated very fast when you’re dealing with a rather complex code base……And here comes : **`IRvana`**

[GitHub - m3rcer/IRvana](https://github.com/m3rcer/IRvana)

We’ll be exploring the usage and how effective it is in evasion soon, but first let us focus on some basic concepts.

## Agenda

- Detection Landscape and Code Compilation
    1. How EDRs see the world?
    2. Core Telemetry Sources
    3. Intermediate Repesentation
- The power of IR for offensive tooling
- Evasions at IR level
- Demo of IRvana

# Primer : Detection Landscape and Code Compilation

## How EDRs see the world?

### AV → EDR

Early Antivirus solutions worked primarily on signature based detections. This meant that it would scan the process and files for known malware signatures. This meant that if a malware existed on the system who’s signature was not known by the AV, it would not be detected. Although AV solutions integrated more features like real time scanning where suspicious files and software samples along with hashes were sent to the Cloud for scanning, it did not guarantee protection and the effectiveness was only slightly better. This also was heavily reliant on the cloud based detection solutions and were totally useless for attacks which were carried out with fileless malware, Living-off-the-Land binaries, in-memory malware, custom loaders which acted as stagers to the actual remotely hosted and encrypted malicious shellcode.

As threats became more sophisticated, EDR solutions emerged to address the shortcomings of AV. EDR continuously monitors endpoint activity, collecting telemetry and analyzing behaviors in real time.

EDRs get their vision from a variety of data sources. Essentially these are Data Lakes where telemetry is collected and the EDR analyzes this to detect any malicious activities in the endpoint. The way it classifies generally follows a common template system where suppose :

![image.png](/assets/img/citm/image%203.png)

This is just one very simple example. It basically checks for common Indicators-of-Compromise (IOCs), these determine if the actions performed by a process is malicious or not. Suppose this scenario

![image.png](/assets/img/citm/image%204.png)

This would set off alarms in the EDRs system because an RWX memory region calls for deeper inspection. It would create a trace of events that created this alarm and analyze the chain. If anything malicious is found it will create an alert on the SoC dashboard.

EDR not only detects but also enables rapid investigation and automated or manual response, such as isolating endpoints or killing malicious processes.

### The EDR Architecture

Core architecture components :

1. Endpoint agents: These are installed on every device where protection is needed. This would generally be all digital assets of a company. The EDR agent works on a kernel level where it collects all data and sends it to a central hub which continuously processes and sieves thorough this data for malware.
2. Centralized server : This is where all the workers send their data. It is integrated with an interactive web based dashboard where the SoC team can monitor all the data coming in along with having the power to isolate hosts, block malicious process and perform remote analysis for each and every system through the EDR agent. 

In real life, this is how it would look like when it is integrated with multiple different Threat Intelligence and other third party integrations.

![image.png](/assets/img/citm/image%205.png)
Image Credit: Palo Alto Networks 

![image.png](/assets/img/citm/image%206.png)
Image Credits : Broadcom

## Core Telemetry Sources

### Userland API Hooking

User-land API hooking represents one of the most fundamental and widely deployed techniques used by Endpoint Detection and Response (EDR) solutions to monitor process behavior. By intercepting function calls in critical system DLLs—particularly **ntdll.dll**

Before Microsoft introduced **Kernel Patch Protection (PatchGuard)** in Windows XP x64 and Windows Server 2003 x64, security products monitored system calls by hooking the **System Service Dispatch Table (SSDT)** directly in kernel mode. This approach provided comprehensive visibility since all user-mode system calls must pass through the SSDT.

PatchGuard was introduced because Microsoft did not want other vendors from patching their kernel. According to Microsoft, it made the system less secure, less reliable and slower performance. PatchGuard basically works by checking the core kernel components regularly and ensures that it is not modified, if any modification is detected then Windows will either reboot, issue a shutdown or initiate a crowd favourite - BSOD. 

This forced EDR vendors to move their monitoring capabilities from kernel mode to user mode, where hooks now reside **alongside the application** in the same address space.

![image.png](/assets/img/citm/image%207.png)
Image Credit : Anthony J - Xsec 

Now this means that these hooks can essentially be removed, and also the EDR must hook every new process and also inject its own DLL into every new process so that it can get an insight into what the process is even doing. 

[ Image of Elastic Security injected DLL in a process ]

### Kernel callbacks

EDR can subscribe to kernel-level notifications for process creation, thread spawning, image loading, and other operations, EDR drivers gain a privileged vantage point that is significantly more difficult to evade than user-mode hooks. Kernel callbacks are **notification subscription mechanisms** that allow kernel-mode drivers to register functions that the Windows kernel automatically invokes when specific system events occur.

This concept has the best metaphorical understanding given by : [Uday Mittal](https://www.100daysofredteam.com/p/quick-introduction-to-kernel-callbacks-red-team)

> “Think of kernel callbacks as subscribers to system events—just like how people subscribe to notifications from a YouTube channel. When an event occurs (such as a new video being uploaded), the subscribers (kernel callbacks) are notified and can take action.”
> <p style="text-align:right">-Uday Mittal</p>

Characteristics : 

- Pre and Post-Operation Notifications
- Multiple Subscribers
- High-Integrity Context

![image.png](/assets/img/citm/image%208.png)

Credit : [https://xsec.fr/posts/evasion/edr-internals/](https://xsec.fr/posts/evasion/edr-internals/)

![image.png](/assets/img/citm/image%209.png)

Credit : [https://xsec.fr/posts/evasion/edr-internals/](https://xsec.fr/posts/evasion/edr-internals/)

### Event Tracing for Windows (ETW)

ETW is built into the Windows Operating System and offers a high traceblity and visibility of actions performed by processes. Since it is implemented into the OS by Microsoft, it has minimal performance impact.

The ETW context typically includes, but not limited to -

- Call stacks
- Payload specific fields
- timestamps
- process ID
- thread ID
- command line arguments

EDRs can subscribe to provider called **`Microsoft-Windows-DotNETRuntime`** to capture JIT compilation events, assembly loads, and P/Invoke calls, revealing in-memory code execution and reflective loading even when user-mode hooks are bypassed.

This provides a deeper coverage and more logs for defenders and EDR to work with and make decisions on, which would help in the overall protection of the endpoint

![image.png](/assets/img/citm/image%2010.png)

## Intermediate Representation (IR)

Intermediate representation is defied as the code used internally by the compiler to define the source code. 

![image.png](/assets/img/citm/image%2011.png)

This is the most well defined diagram of where IR comes into picture. The source code is first parsed into an Abstract Syntax Tree (AST), consider this like a tree of sorts where all different conditions and cases are mapped out. This is then converted into the LLVM IR itself. It’s more like the way the compiler sees the source code and understands it. Now a bunch of optimizations can be added at this stage to make our IR much better. Things like dead argument deletion, dead loop deletions, loop unrolling, memory to registers etc. 

A full list of all the different passes available for the LLVM IR optimizations are available here:

[https://llvm.org/docs/Passes.html](https://llvm.org/docs/Passes.html)

The LLVM compiler then takes this Intermediate representation and converts that into assembly code. The whole idea of the process is that programmers can write code any way they want, and then make it better during compilation. Clang also makes softwares secure during compilation phase by checking for various issues and throwing better outputs than the regular gcc. Although gcc can be very effective when used well.

### Creating IR file from a source file

Let’s take a simple example C code:

`example.c`

```c
#include <stdio.h>

int test(int a) 
{
    int x;
    if (a > 10) 
        x = 20;
    else 
        x = 30;
    return x;
}

int main()
{
    test(5);
    return 0;
}
```

We can compile this into IR using `clang` and `opt`. We will emit the optimizations applied by 

```bash
# -S:           Output in assembly (LLVM IR)
# -emit-llvm:   Emit LLVM IR instead of machine assembly
# -O0:          Compile with no optimizations
# -Xclang -disable-O0-optnone:
#               This is super important because by default, 
#						  	-O0 adds an "optnone" attribute to functions, 
#								which prevents 'opt' from running any passes.
# -fno-discard-value-names:
#               Makes the IR more readable by keeping variable names

clang -S -emit-llvm -O0 -Xclang -disable-O0-optnone -fno-discard-value-names example.c -o example.ll
```

The output is a `.ll` file extension, we get an `example.ll` file

`example.ll`

```
; ModuleID = 'example.c'
source_filename = "example.c"
target datalayout = "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128-Fn32"
target triple = "aarch64-unknown-linux-gnu"

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @test(i32 noundef %a) #0 {
entry:
  %a.addr = alloca i32, align 4
  %x = alloca i32, align 4
  store i32 %a, ptr %a.addr, align 4
  %0 = load i32, ptr %a.addr, align 4
  %cmp = icmp sgt i32 %0, 10
  br i1 %cmp, label %if.then, label %if.else

if.then:                                          ; preds = %entry
  store i32 20, ptr %x, align 4
  br label %if.end

if.else:                                          ; preds = %entry
  store i32 30, ptr %x, align 4
  br label %if.end

if.end:                                           ; preds = %if.else, %if.then
  %1 = load i32, ptr %x, align 4
  ret i32 %1
}

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @main() #0 {
entry:
  %retval = alloca i32, align 4
  store i32 0, ptr %retval, align 4
  %call = call i32 @test(i32 noundef 5)
  ret i32 0
}

attributes #0 = { noinline nounwind uwtable "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fp-armv8,+neon,+outline-atomics,+v8a,-fmv" }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{i32 7, !"frame-pointer", i32 1}                                                                                                                                                      !5 = !{!"Debian clang version 19.1.7 (7)"}
```

Now let’s apply an optimization, since its a simple program i’ll use the mem2reg to tell the optimizer to put as many variables present in the memory to the registers.

```bash
# -S:               Output human-readable LLVM IR
# -passes=mem2reg:  Run the "Promote Memory to Register" pass
#	-o:               Specify the output file

opt -S -passes=mem2reg example.ll -o optimized.ll
```

`optimized.ll`

```
; ModuleID = 'example.ll'
source_filename = "example.c"
target datalayout = "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128-Fn32"
target triple = "aarch64-unknown-linux-gnu"

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @test(i32 noundef %a) #0 {
entry:
  %cmp = icmp sgt i32 %a, 10
  br i1 %cmp, label %if.then, label %if.else

if.then:                                          ; preds = %entry
  br label %if.end

if.else:                                          ; preds = %entry
  br label %if.end

if.end:                                           ; preds = %if.else, %if.then
  %x.0 = phi i32 [ 20, %if.then ], [ 30, %if.else ]
  ret i32 %x.0
}

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @main() #0 {                                                                                                                                                           entry:                                                                                                                                                                                        %call = call i32 @test(i32 noundef 5)
  ret i32 0                                                                                                                                                                                 }
attributes #0 = { noinline nounwind uwtable "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fp-armv8,+neon,+outline-atomics,+v8a,-fmv" }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}
                                                                                                                                                                                            !0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{i32 7, !"frame-pointer", i32 1}
!5 = !{!"Debian clang version 19.1.7 (7)"}
```

The difference in IR code after applying the optimizations are quite significant

![image.png](/assets/img/citm/image%2012.png)

Lets look at each of the files individually and make sense of what the IR performs.

### Analyzing example.ll

First, lets dive into the unoptimized LLVM IR produced by clang `example.ll`

```
; ModuleID = 'example.c'
source_filename = "example.c"
target datalayout = "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128-Fn32"
target triple = "aarch64-unknown-linux-gnu"
```

This part of the IR specifies what the source file is and also specified a ModuleID which is just a reference to the current module. The `target data layout` specifies content which define the endianness, little endian in this code, the architecture, which is 64-bit. The `i8:8:32-i16:16:32-i64:64-i128:128` specifies the alignment for different integer types. The `target triple` tells LLVM critical data about what the ABI (Application Binary Interface) to use along with the operating system and the architecture. This affects how to code is ultimately generated.


>semicolon is used to define comments in IR. The ModuleID is a comment from the above block of code.
{: .prompt-info}

```
; Function Attrs: noinline nounwind uwtable
define dso_local i32 @test(i32 noundef %a) #0 {
```

The `define` keyword is used to specify the start of a function . `dso_local` is a linkage type, it tells the optimizer that this is a shared local object and should not be overwritten. `i32`specifies the return type and `@test` is the function name. `i32 noundef %a` specifies that the argument is a 32-bit integer which is defined using `%a`where `%`is used to specify local variables. The `#0`is used to tell the compiler not to inline this function.

```
entry:
  %a.addr = alloca i32, align 4
  %x = alloca i32, align 4
  store i32 %a, ptr %a.addr, align 4
  %0 = load i32, ptr %a.addr, align 4
  %cmp = icmp sgt i32 %0, 10
  br i1 %cmp, label %if.then, label %if.else
```

We allocate `%a` variable in the memory using `alloca` where `i32` is used to specify an integer and a space of 4 bytes is allocated on the stack frame. The same thing is done for `%x` where a space for 4 bytes is allocated in the stack frame. We store the variable `%a`into the stack frame address we just allocated for the variable. This is followed by loading the variable into the register `%0`.

We then perform the first comparison where we compare this value with 10. This is done using the `icmp` instruction which performs an integer comparison of `%0` with 10. The `sgt` is the shorthand of `set greater than` where `%cmp` is set to 1 if `%0` is greater than 10.

The branch instruction is specified using `br` where a check for 1-bit boolean is performed specified by `i1` . If `%cmp` is set to 1, then it jumps to `%if.then` or else it jumps to the label `%if.else`


>LLVM register names are temporary names, in this case %0 is a temporary register name.
{: .prompt-info}


```
if.then:                                          ; preds = %entry
  store i32 20, ptr %x, align 4
  br label %if.end

if.else:                                          ; preds = %entry
  store i32 30, ptr %x, align 4
  br label %if.end

if.end:                                           ; preds = %if.else, %if.then
  %1 = load i32, ptr %x, align 4
  ret i32 %1
}
```

The `%if.then` label contains the instructions where it sets the value of `%x` to 20 using the `store` instruction. It then jumps to the `%if.end`  label.

The `%if.else`  label sets the value of `%x` to 30 and then jumps to `%if.end` 

The `%if.end` label contains instructions where it loads the value of `%x` from memory to the register `%1` . It then returns that value as a 32-bit integer.

```
; Function Attrs: noinline nounwind uwtable
define dso_local i32 @main() #0 {
entry:
  %retval = alloca i32, align 4
  store i32 0, ptr %retval, align 4
  %call = call i32 @test(i32 noundef 5)
  ret i32 0
}
```

This is the main function where we create a variable called `%retval` and allocate a space of 4 bytes on the stack frame for it. This is essentially going to store our return value. We then set this variable to 0 using the `store` instruction. The `call` instruction is used to call a function with some arguments. We do a function call to test with the argument 5. The function then ends with a return of 0.


>noundef stands for “not undefined”. It basically promises the compiler that this value will never have an “undefined” value. Better for aggressive optimizations.
{: .prompt-info}


> %retval is defined but never used, initially this was intended with the hope that the return value from test would be stored somewhere, but in our code we do not store the return value. When optimizations like dead code eliminations are implemented , these instructions would be removed.
{: .prompt-info}

```
attributes #0 = { noinline nounwind uwtable "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fp-armv8,+neon,+outline-atomics,+v8a,-fmv" }
!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{i32 7, !"frame-pointer", i32 1}
!5 = !{!"Debian clang version 19.1.7 (7)"}
```

The group of attributes for the `#0` flag are set using the `attributes`instruction. This is what the values mean :-

- `noinline` : tells the compiler not to inline the function
- `nounwind` : It promises the compiler that the function will *never* throw an exception or unwind the stack.
- `uwtable` : This attribute *requires* the compiler to generate an unwind table for this function. This is essential for debuggers and exception handlers to be able to "unwind" the stack.
- `"frame-pointer"="non-leaf"` : This controls the use of frame pointers (like ebp) but only when there is a function call
- `"no-trapping-math"="true"` : This tells the compiler that the function does not rely on floating-point operations "trapping" (generating a hardware exception) on error conditions like division by zero or overflow.
- `"stack-protector-buffer-size"="8"` : This enables stack-smashing protection (SSP). It tells the compiler to add a security check (stack canary) for any stack buffer that is 8 bytes or larger, helping to detect and mitigate buffer overflow attacks.
- `"target-cpu"="generic"` : specifies the cpu to tune for. generic means that it will run reasonably well on all CPUs
- `"target-features"="+fp-armv8,+neon,+outline-atomics,+v8a,-fmv"` : Explicitly enables CPU features (this program has been compiled on a Apple M4 and hence the arm flags

The last part is the module metadata and specifies different module flags.

### Analyzing optimized.ll

We will look into only the things that have changed after the program has been optimized.

```
define dso_local i32 @test(i32 noundef %a) #0 {
entry:
  %cmp = icmp sgt i32 %a, 10
  br i1 %cmp, label %if.then, label %if.else
```

The function seems to be a lot more lighter and simpler. We directly compare the variable `%a` with 10 and set our `$cmp` flag. We then create a branch statement based on the value of `%cmp` 

```
if.then:                                          ; preds = %entry
  br label %if.end

if.else:                                          ; preds = %entry
  br label %if.end

if.end:                                           ; preds = %if.else, %if.then
  %x.0 = phi i32 [ 20, %if.then ], [ 30, %if.else ]
  ret i32 %x.0
```

Both `if.then` and `if.else` call `if.end` . `%x.0` is a virtual register here and the instruction `phi` is used to tell that the value of this `%x.0` register will be taken from the list specified. The way `phi` works is that the value is assigned based on where the jump was taken from. If the jump was from `%if.then`, then the value is set to 20 and if the jump was from `%if.else` then the value of `%x.0` is set to 30. We then return the value of `%x.0` 

```
define dso_local i32 @main() #0 {
entry:
  %call = call i32 @test(i32 noundef 5)
  ret i32 0
}
```

We can see that most of the dead code is eliminated as compared to what was there in `example.ll` . The call to the function is made as before and then 0 is returned from the main function.


# The power of IR for Offensive Tooling

### Language and Target Agnostic

- Using an intermediate representation (IR) gives you a way to abstract away from specific source languages or target architectures.
- You can build payloads, exploit chains, obfuscation or analysis that work across different compiled languages, OS, architectures. This increases reuse, flexibility and reduces bespoke work for each environment.
- Drawbacks :
    1. Although IR abstracts away many differences, it often still carries architecture or compiler-specific artifacts (register counts, memory model differences, calling conventions).
    2. Using IR may add overhead and complexity; operators still need tooling/libraries to lift binaries, transform IR, re-compile or generate payloads.
    3. Defenders may also begin to leverage IR-based detection and analysis on executables which makes it more difficult.

### Born-Obfuscated Binaries

- “Born-obfuscated binaries” likely refers to binaries that, from the moment of compilation or generation, are already obfuscated—rather than starting from a clean compile and then obfuscating later. That can make detection and reverse-engineering harder.
- If you do this at the IR level, you can embed obfuscation and evasive behavior early in the pipeline.
- Drawbacks :
    1. Defenders increasingly lift binaries to IR and then apply graph/feature-based detection (e.g., CFG matching, IR token sequence). 
    2. Heavily obfuscated binaries may raise suspicion by themselves.

### LOTL execution

- Living‑Off‑the‑Land (LOTL) techniques refer to adversaries using legitimate system binaries and tools to carry out malicious actions—reducing use of custom malware, making detection harder.
- For offensive tooling, combining IR-based payloads with obfuscation with LOTL execution can make attacks highly stealthy: minimal new binaries dropped, or the binary behaves like a trusted system tool, or you load payload in memory via existing binary.
- This is what the crux of this blog is about! Using `lli.exe` to directly execute payloads which are in IR format rather than executables.


# Evasion at IR level

## API call Obfuscation

API call hashing is a technique used to hide the Windows API functions a program calls, thereby evading static analysis and signature-based detection. Instead of storing the names of imported functions like `CreateThread` in the binary's Import Address Table (IAT), the malware stores a numerical hash for each required function. At runtime, the program dynamically resolves the memory address of each function. It does this by iterating through the functions exported by system libraries (like `kernel32.dll`), calculating the hash of each function name, and comparing it to its stored list of target hashes. Once a match is found, it retrieves the function's address for later use. This process leaves the IAT empty of suspicious imports, making it difficult for analysts to quickly determine the malware's capabilities.

#### **Implementation at the IR Level**

This dynamic resolution process can be automated at compile time using an LLVM pass. The pass transforms direct, easily identifiable API calls into indirect, resolved-at-runtime calls.

1. **Identify External Calls:** The pass traverses the LLVM IR to find all `call` instructions that target external function declarations (e.g., `@CreateRemoteThread`).
2. **Pre-calculate Hashes:** At compile time, the pass applies a chosen hashing algorithm to the names of these functions and embeds the resulting hash values as constants within the program.
3. **Inject Resolver Logic:** A resolver function, which contains the logic to parse the Process Environment Block (PEB) and the Export Address Table (EAT) of loaded DLLs, is injected into the module as new IR code.
4. **Replace Direct Calls:** The original `call` instruction is replaced with a new sequence of IR. This new code first calls the injected resolver, passing it the pre-calculated hash. The resolver returns a function pointer, which is then used to make an indirect `call` to the API with the original arguments.

## Control Flow Flattening

Control-Flow Flattening is an obfuscation technique that dismantles a function's natural control-flow graph (CFG). It transforms the code's structure using logical loops and branches, into a large, flat state machine. All of the original basic blocks of the function are placed at the same hierarchical level inside a single loop containing a large `switch` statement. A "state variable" is used to control which block is executed next, effectively hiding the original program logic. This makes the code extremely difficult for reverse engineers to analyze and for automated tools like decompilers to reconstruct.

#### **Implementation at the IR Level**

This transformation is implemented as an LLVM `FunctionPass` that operates on one function at a time. The pass algorithmically rebuilds the function's structure:

1. **Block Collection:** The pass first iterates through the function and collects all of its basic blocks.
2. **Create Dispatcher:** A new entry block (the "dispatcher") is created. This block contains a `switch` instruction that acts as the central hub for the state machine. A state variable is allocated on the stack (using an `alloca` instruction) to control the flow.
3. **Encapsulate in Loop:** The dispatcher and all original blocks are placed inside an infinite loop to ensure control always returns to the central `switch` statement.
4. **Rewrite Blocks:** Each original basic block is moved into a `case` of the `switch` statement. The block's original terminator instruction (e.g., a conditional branch) is removed and replaced with IR instructions that update the state variable to the value corresponding to the next logical block. After the state variable is updated, an unconditional branch directs execution back to the dispatcher. The result is a function where all logical blocks are disconnected from each other and are only reachable through the central dispatcher, effectively "flattening" the CFG.

## Data obfuscation

String encryption is a data obfuscation technique that hides string literals (e.g., C2 domains, file paths, debug messages) within a binary. Instead of storing plaintext strings, which are easily discovered during static analysis, the strings are encrypted at compile time. At runtime, a small decryption routine is executed just before the string is needed, decoding it in memory for immediate use. By decrypting strings onto the stack only when required, the plaintext data exists in memory for a minimal amount of time.

#### **Implementation at the IR Level**

An LLVM transformation pass can automate this process entirely.

1. **Identify Global Strings:** The pass iterates through the module's `GlobalVariable` instances to find constant strings eligible for encryption.
2. **Encrypt and Replace:** For each string, the pass encrypts its content (e.g., with a simple XOR cipher) and replaces the original global variable with a new one containing the ciphertext.
3. **Inject Decryption Stubs:** The pass finds every instruction that uses the original string. At each point of use, it injects a "decryption stub" right before the instruction. This stub consists of IR code that allocates a buffer on the stack (`alloca`), copies the encrypted string into it, and then executes a loop to decrypt the string in-place.
4. **Update Operands:** The original instruction is then modified to reference the newly decrypted string on the stack instead of the global variable.
5. **Cleanup:** After all references have been replaced, the original global variable is deleted from the module.

## Direct syscall invocation

Direct syscall invocation is a technique to bypass user-land API hooks, which are a primary monitoring mechanism for EDRs. Instead of calling high-level functions in libraries like `kernel32.dll`, the malware communicates directly with the operating system kernel. This is done by using a low-level assembly instruction (`syscall` or `sysenter`) to trigger a transition from user mode to kernel mode, rendering any user-land monitoring ineffective. 

#### **Implementation at the IR Level**

LLVM IR is platform-independent and does not have a native instruction for system calls. Therefore, this technique is implemented using inline assembly within the source code (e.g., C/C++).

1. **Inline Assembly in Source:** The developer writes a function containing an `asm volatile` block. This block includes the specific assembly instructions required to set up CPU registers with the correct arguments and the appropriate System Service Number (SSN) in the `EAX` register, followed by the `syscall` instruction.
2. **Encapsulation by Clang:** When the Clang front-end processes this code, it does not interpret the assembly. Instead, it encapsulates the entire assembly block as a string literal within a special `call` instruction in the LLVM IR.
3. **Opaque Treatment:** This `call` instruction is treated as an opaque, black-box operation by the LLVM middle-end optimizer passes. It is passed directly to the back-end, which then integrates the raw assembly into the final machine code output. This allows the malware to retain precise, low-level control over CPU operations while still benefiting from other IR-level obfuscations.

## The JIT Execution model

This is a fileless execution strategy that avoids writing the primary malicious payload to disk, thus evading filesystem-based scanners. The attack is split into two parts: a lightweight loader and the main payload, which is stored as LLVM bitcode (`.bc` format) rather than a native executable. At runtime, the loader uses a Just-In-Time (JIT) compilation engine to compile and execute the bitcode payload directly from memory. 

#### **Implementation at the IR Level**

This model leverages the LLVM toolchain's flexibility to separate compilation and execution.

1. **Compile to Bitcode:** The adversary's main tool, already obfuscated with other IR-level passes, is compiled not to a native executable but to a platform-independent LLVM bitcode file (`.bc`). This bitcode is then embedded (often encrypted) within a simple loader program.
2. **In-Memory JIT Compilation:** When the loader runs, it decrypts the bitcode into a memory buffer. It then uses an embedded LLVM JIT engine, such as MCJIT or the more modern ORC JIT APIs, to function as an in-memory compiler. The JIT engine takes the LLVM IR from the memory buffer and compiles it into native, executable machine code for the host's architecture.
3. **Execution via Function Pointer:** The JIT engine allocates an executable memory region for the newly compiled code and returns a function pointer to its entry point. The loader then simply calls this function pointer to start the main payload, achieving fileless execution.

# Demo of IRvana

We store the source code in the “c\src” directory and then run IRvana. I am using the default POC but have changed a few things where I perform process injection on `msedge.exe` rather than `notepad.exe` . Also the shellcode used is the `Adaptix C2`beacon shellcode.

![image.png](/assets/img/citm/image%2013.png)

![image.png](/assets/img/citm/image%2014.png)

![image.png](/assets/img/citm/image%2015.png)

![image.png](/assets/img/citm/image%2016.png)

![image.png](/assets/img/citm/image%2017.png)

We can see we get a callback without any issues and everything seems to be working fine.

![image.png](/assets/img/citm/image%2018.png)

Okay something you should **DEFINETELY NOT** do in a red team assessment (horrible opsec), I just ran it to show the agent is working.

![image.png](/assets/img/citm/image%2019.png)

## Detections and Verdict

In terms of bypassing Windows Defender, it does it beautifully. But an EDR like elastic? That is highly unlikey to occur. Main reason is that regardless of how obfuscated the binary is, the actions it performs play a major role. You can have the most sophisticated encrypted binary, but if it just performs a basic process injection that beats the purpose of Opsec.

With respect to static detection bypasses, making detections for IR files is really hard, the sigatures change between generation of the same payload, reversing of the binary becomes hard due to LLVM doing its thing and all this is good in terms of not getting your binary detected. But sadly the actions performed by the IR file will be detected for sure, so the **verdict** is amazing static detection bypass and not a very good dynamic detection bypass.

![image.png](/assets/img/citm/image%2020.png)

![image.png](/assets/img/citm/image%201.png)

## But why use IR?

The IR files dropped onto the disk were not flagged regardless of it being malicious. This observation has been consistent with different EDR products. Even after executing, it treats `lli.exe`  and the whichever process gets injected as malicious but not the IR file itself, although it is shown in the artifacts of execution, there is no indication of the file being classified as inherently malicious. This is again because `lli.exe`is responsible for interpreting the file, so all actions are performed by `lli.exe` . 

The main point of looking into IR files for evasion pupose is that malware developers can focus more on evading dynamic detections by using sandbox evasions, sleep techniques, newer and lesser detected process injection techniques and being more vigilant on what the loader does without focusing on the static detection bypasses as that can easily be done with `IRvana`. You do not need to worry about plaintext strings or any other artifacts in your code which can easily be signatured, you can shift your focus towards building better malware in terms of what it does exactly.