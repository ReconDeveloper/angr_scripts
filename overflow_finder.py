import angr
import claripy
import sys
sys.set_int_max_str_digits(0)
import logging
l = logging.getLogger("overflow")


def check_buffer_overflow(simgr, sym):
    if len(simgr.unconstrained):
        for path in simgr.unconstrained:
            if path.satisfiable(extra_constraints=[path.regs.pc == 0x43434343]):
                original_pc = path.history.bbl_addrs.hardcopy[-2]
                path.add_constraints(path.regs.pc == 0x43434343)
                if path.satisfiable():
                    stdin_payload = path.solver.eval(sym, cast_to=bytes)
                    print(f"Found overflow at address: {hex(original_pc)} with stdin input: {stdin_payload}")
    return simgr


def main(args):

    # Set up the Angr project
    project = angr.Project(args.binary, load_options={'auto_load_libs': False})

    # Specify the starting point for analysis
    start_address = int(args.start_address, 16)

    # Set up the initial state with a symbolic stdin
    sym = claripy.BVS("stdin", 900*8)
    initial_state = project.factory.entry_state(addr=start_address, stdin=sym)

    # Create a SimulationManager that keeps unconstrained states
    simgr = project.factory.simulation_manager(initial_state, save_unconstrained=True)

    # Analyze the control flow graph of the binary
    cfg = project.analyses.CFGFast()

    # Define condition to stop the simulation
    def stop_condition(simgr):
        return len(simgr.active) == 0 and len(simgr.unconstrained) > 0

    # Run the binary until a potential overflow occurs or simualtion manager no longer active
    simgr.run(until=stop_condition)

    # Check for buffer overflow and restore program counter
    simgr = check_buffer_overflow(simgr, sym)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Angr script')
    parser.add_argument('binary', type=str, help='Path to the binary to analyze')
    parser.add_argument('start_address', type=str, help='Starting point for analysis as a hex address')
    args = parser.parse_args()
    #logging.getLogger("angr").setLevel(logging.DEBUG)
    l.setLevel("INFO")
    l.setLevel("WARNING")
    main(args)


