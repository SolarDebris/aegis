import angr
import claripy
import argparse
import logging

from rage.log import aegis_log


class rAEG:
    """Class that utilizes all angr analysis."""

    def __init__(self, binary):
        self.binary = binary
        self.project = angr.Project(self.binary, load_options={"auto_load_libs":"false"})
        self.has_format = False
        self.solution = None

    def stack_smash(self):
        """Analyze the buffer overflow."""
        aegis_log.info("Starting symbolic analysis for buffer overflow")
        stack_smash = self.project.analyses.BufferOverflow(self.binary)
        self.symbolic_padding = stack_smash.symbolic_padding
        self.has_format = stack_smash.has_format
        if self.symbolic_padding is not None:
            aegis_log.info(f"Found symbolic padding with length of {len(self.symbolic_padding)}")
            aegis_log.info(f"Symbolic Padding: {self.symbolic_padding}")

    def find_path(self, goal):
        """Find the path to the goal."""
        aegis_log.info("Starting symbolic analysis for path to goal")
        self.project = angr.Project(self.binary)
        lab = self.project.analyses.Laberynth(self.binary, goal)
        lab.find_path_solution()
        self.solution = lab.solution
        return self.solution


class BufferOverflow(angr.Analysis):
    """Angr analysis for symbolically detecting a buffer overflow."""

    def __init__(self, binary):
        self.binary = binary
        self.has_format = False
        self.stack_smash()

    def check_memory_corruption(self, simgr):
        """Return the simulation manager that checks for buffer overflow."""
        if simgr.unconstrained:
            for path in simgr.unconstrained:

                print(self.project.arch)
                
                target_pc = b"A" * 8
                target_bp = b"B" * 8 
 
                path.add_constraints(path.regs.pc == target_pc)
                path.add_constraints(path.regs.bp == target_bp)

                if path.satisfiable():
                    stack_smash = path.solver.eval(self.symbolic_input, cast_to=bytes)
                    try:
                        index = stack_smash.index(b"AAAAAAAA")
                        self.symbolic_padding = stack_smash[:index]
                        simgr.stashes["mem_corrupt"].append(path)
                    except ValueError:
                        aegis_log.warn("Could not find the index of the pc overwrite")
                        self.symbolic_padding = None
                simgr.stashes["unconstrained"].remove(path)
                simgr.drop(stash="active")
        return simgr

    def stack_smash(self):
        """Return the symbolic buffer for smashing the stack."""
        buff_size = 600
        self.symbolic_input = claripy.BVS("input", 8 * buff_size)
        self.symbolic_padding = None

        state = self.project.factory.entry_state(
            #start_addr = self.project.loader.find_symbol("main"),
            start_addr = self.project.loader.main_object.entry,
            stdin = self.symbolic_input,
            #add_options = angr.options.unicorn
        )

        simgr = self.project.factory.simgr(state)
        simgr.stashes["mem_corrupt"] = []

        #simgr.use_technique(angr.exploration_techniques.Timeout(timeout=10))
        # angr gets angy when fgets has a large buffer.
        # in this case 60000
        def stop_lg_fgets(state):
            size = state.solver.eval(state.regs.rsi)
            if size >= 1000:
                simgr.drop(stash = "active")
        
        def stop_bs(state):
            simgr.use_technique(angr.exploration_techniques.Timeout(timeout=5))
            
             
        self.project.hook_symbol("fgets", stop_lg_fgets)

        slow_functions = ["memmem", "md5init"]

        for func in slow_functions:
            self.project.hook_symbol(func, stop_bs)

        simgr.explore(step_func=self.check_memory_corruption)

        for e in simgr.errored:
            if str(e.error) == "Symbolic (format) string, game over :(":
                self.has_format = True
                aegis_log.warn(f"Found symbolic format string")
            else:
                aegis_log.warn(f"Angr error {e}")

        return self.symbolic_padding

class FormatVulnerability(angr.Analysis):
    """Class that uses angr to analyze for format string vulnerabilities."""

    def __init__(self, binary):
        self.binary = binary


class Laberynth(angr.Analysis):
    """Class that uses angr to find paths to the goal."""

    def __init__(self, binary, goal):
        self.binary = binary
        self.goal = goal
        self.solution = None

    def throwout_simgr(self, simgr): 
        if simgr.unconstrained:
            simgr.drop(stash="active")
            return simgr 

    def find_path_solution(self):        
 
        if self.goal is None:
            aegis_log.warn("Goal address is not set")
            return

        state = self.project.factory.entry_state(
            start_addr = self.project.loader.main_object.entry,
            #add_options = {
                #angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                #angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
            #}
        )

        simgr = self.project.factory.simgr(state) 
    
        #!TODO Handle the case where PIE is enabled
        goal_addr = self.goal
        simgr.explore(find=goal_addr)
        
        if simgr.found:  
            self.solution = simgr.found[0].posix.dumps(0)
            self.solution = self.solution[:self.solution.index(b"\x00")]
            aegis_log.info(f"Found input to reach goal at {hex(self.goal)} with input {self.solution}") 
        else:
            aegis_log.info(f"Could not find a path to the goal at {hex(self.goal)}")



class Printf(angr.SimProcedure):
    """Class that is an angr simprocedure for printf."""

    def run(self):
        return None

angr.analyses.AnalysesHub.register_default("BufferOverflow", BufferOverflow)
angr.analyses.AnalysesHub.register_default("FormatVulnerability", FormatVulnerability)
angr.analyses.AnalysesHub.register_default("Laberynth", Laberynth)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="rage",
        description="Symbolic analyzer for the aegis toolkit using angr"
    )

    parser.add_argument("-b", metavar="binary", type=str, help="The binary you are executing", default=None)
    parser.add_argument("-l", metavar="libc", type=str, help="The libc shared library object linked to the binary", default=None)

    args = parser.parse_args()

    anal = rAEG(args.b)

    anal.stack_smash()
