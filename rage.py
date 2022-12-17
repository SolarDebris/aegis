import angr, claripy
import logging



logging.getLogger("angr").setLevel(logging.CRITICAL)
logging.getLogger("os").setLevel(logging.CRITICAL)
logging.getLogger("pwnlib").setLevel(logging.CRITICAL)


class BufferOverflow(angr.Analysis):
    def __init__(self, binary):
        self.binary = binary
        self.proj = angr.Project(self.binary, load_options={"auto_load_libs":False})
        self.cfg = self.proj.analyses.CFGFast()

        self.stack_smash()


    def check_memory_corruption(self, simgr):
        if simgr.unconstrained:
            for path in simgr.unconstrained:
                path.add_constraints(path.regs.pc == b"AAAAAAAA")
                path.add_constraints(path.regs.bc == b"BBBBBBBB")

                if path.satisfiable():
                    stack_smash = path.solver.eval(self.symbolic_input, cast_to=bytes)
                    try:
                        index = stack_smash.index(b"AAAAAAAA")
                        self.symbolic_padding = self.symbolic_input[:index]
                        simgr.stashes["mem_corrupt"].append(path)
                    except ValueError:
                        print("Could not find the index of the pc overwrite")
                simgr.stashes["unconstrained"].remove(path)
                #simgr.drop(stash="active")
        return simgr

    def stack_smash(self):

        buff_size = 600
        self.symbolic_input = claripy.BVS("input", 8 * buff_size)
        self.symbolic_padding = None

        state = self.proj.factory.entry_state(
            stdin = self.symbolic_input,
            add_options = angr.options.unicorn
        )

        simgr = self.proj.factory.simgr(state)
        simgr.stashes["mem_corrupt"] = []

        simgr.explore(step_func=check_memory_corruption)

        for error in simgr.errored:
            print(error)

class FormatVulnerability(angr.Analysis):
    def __init__(self, binary):
        self.binary = binary



class Printf(SimProcedure):
    def run(self):
        return None






angr.AnalysesHub.register_default("BufferOverflow", BufferOverflow)
angr.AnalysesHub.register_defautl("FormatVulnerability", FormatVulnerability)
