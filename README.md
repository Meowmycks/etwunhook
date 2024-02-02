# etwunhook
Simple ETW unhook PoC. Overwrites `NtTraceEvent` opcode to disable ETW at Nt-function level.

## Disclaimer
Don't be evil with this. I created this tool to learn. I'm not responsible if the Feds knock on your door.

## What this does
- Obtains `NTDLL.dll` base address via walking PEB.
- Obtains all `Nt*` function SSN's by grabbing all `Zw*` functions and sorting by address in ascending order.
- Obtains address of unhooked `syscall; ret` opcode sequence for indirect syscalling.
- Performs unhooking via indirectly syscalling `NtProtectVirtualMemory` and `NtWriteVirtualMemory`.
- Unhooks/patches ETW by overwriting `NtTraceEvent` opcodes with `ret`.

## Negatives(?)
- Moneta (and probably other stuff) catches this (alerts on Modified Code in NTDLL).
- That's all it does.

## Credits
MDSec - Bypassing User-Mode Hooks and Direct Invocation of System Calls for Red Teams
https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/

Marcus Hutchins - An Introduction to Bypassing User Mode EDR Hooks
https://malwaretech.com/2023/12/an-introduction-to-bypassing-user-mode-edr-hooks.html

passthehashbrwn - Hiding Your Syscalls
https://passthehashbrowns.github.io/hiding-your-syscalls

jstigerwalt - Bypassing ETW For Fun and Profit
https://whiteknightlabs.com/2021/12/11/bypassing-etw-for-fun-and-profit/
