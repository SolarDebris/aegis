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

    def stack_smash(self):
        """Analyze the buffer overflow."""
        aegis_log.info("Starting symbolic analysis for buffer overflow")
        stack_smash = self.project.analyses.BufferOverflow(self.binary)
        self.symbolic_padding = stack_smash.symbolic_padding
        if self.symbolic_padding is not None:
            aegis_log.info(f"Found symbolic padding with length of {len(self.symbolic_padding)}")
            aegis_log.info(f"Symbolic Padding: {self.symbolic_padding}")


class BufferOverflow(angr.Analysis):
    """Angr analysis for symbolically detecting a buffer overflow."""

    def __init__(self, binary):
        self.binary = binary
        self.stack_smash()

    def check_memory_corruption(self, simgr):
        """Return the simulation manager that checks for buffer overflow."""
        if simgr.unconstrained:
            for path in simgr.unconstrained:
                path.add_constraints(path.regs.pc == b"AAAAAAAA")
                path.add_constraints(path.regs.bp == b"BBBBBBBB")

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
            start_addr = self.project.loader.find_symbol("main"),
            stdin = self.symbolic_input,
            add_options = angr.options.unicorn
        )

        simgr = self.project.factory.simgr(state)
        simgr.stashes["mem_corrupt"] = []

        simgr.explore(step_func=self.check_memory_corruption)

        for e in simgr.errored:
            if e.error == angr.errors.SimProcedureError("Symbolic (format) string game over :("):
                aegis_log.warn(f"Found symbolic format string with error {e}")
            aegis_log.warn(f"angr simulation failed with error {e.error}")


        return self.symbolic_padding


class FormatVulnerability(angr.Analysis):
    """Class that uses angr to analyze for format string vulnerabilities."""

    def __init__(self, binary):
        self.binary = binary


class Printf(angr.SimProcedure):
    """Class that is an angr simprocedure for printf."""

    def run(self):
        return None


angr.AnalysesHub.register_default("BufferOverflow", BufferOverflow)
angr.AnalysesHub.register_default("FormatVulnerability", FormatVulnerability)


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
