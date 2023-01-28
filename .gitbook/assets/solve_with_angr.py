# https://zeta-two.com/assets/other/nixucon18-slides.pdf
# https://research.kudelskisecurity.com/2016/08/08/angr-management-first-steps-and-limitations/
# https://flagbot.ch/lesson5.pdf <--- this one was by far the most useful.

import os, stat
import angr
import claripy
from pwn import ELF

# The is the library we are massaging.
e = ELF("./CrackThePassword")

target = e.sym.validatePassword

BASE = 0x0
ADDR_START = BASE + target
ADDR_GOOD = BASE + target + 0x490
# At this point, the checker function has decided to return 0
ADDR_BAD  = BASE + target + 0x497

# Start a new project with the modded binary and some magic options.
proj = angr.Project(
    e.path, main_opts={"base_addr": BASE}, 
    load_options={
        "auto_load_libs": False, 
        "use_system_libs": False,
    }
)

# We know what the flag has a certain size, so we can create a bitvector of precisely the right 
# length. No worries if you dont, some bytes will just get resolved to 0x00 by angr.
flag_size = 32
flag = claripy.BVS("flag", 8*flag_size)

# Create a new project, and disable some of the unconstraint/uninitialized memory settings.
# The binary we're targetting isn't quite "normal", so angr gets a bit confused here.
#
# The cool thing here is thay the call_state allows us to call into a specific piece of memory
# with an argument, like a pointer to the symbolic flag.
state = proj.factory.call_state(
    ADDR_START,
    flag,
    add_options = {
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
})

# Adding constraints to the solver to obtain values that are in the printable range
for i in flag.chop(8):
    state.solver.add(i >= 0x20)
    state.solver.add(i <= 0x7f)

# Start a simulation
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=ADDR_GOOD, avoid=ADDR_BAD)

if len(simgr.found) > 0:
    found = simgr.found[0]

    val_flag = found.solver.eval(flag, cast_to=bytes)
    val_flag = val_flag.strip(b"\0")

    print("flag: {}".format(val_flag.decode()))
else:
    print("No solution... :(")

