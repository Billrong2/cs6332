crash_payload = cyclic(300)
crash.sendline(crash_payload)  # to create a core dump
crash.wait()                  # wait for the process to terminate

core = crash.corefile

test = core.stack.start + core.stack.data.find(crash_payload)   #0x7ffffffddfff
