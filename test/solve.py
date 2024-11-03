import angr
import claripy
import sys

def main(argv):
    binary_path = argv[1]


    good_strings = [b'Good', b'good',  b'Succ', b'succ', b'ongrat', b'flag', b'Flag']
    bad_strings = [b'Fail',b'fail',  b'Try', b'enied', b'ncorrect', b'pay']

    #start_addr =

    proj = angr.Project(binary_path)
    state = proj.factory.entry_state(
            #addr=start_addr,
            add_options = {
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            }
    )
    #good_address = proj.loader.find_symbol('win').rebased_addr
    #bad_address =
    good_address = 0x4012a3

    def is_successful(state):
        output = state.posix.dumps(sys.stdout.fileno())
        for i in good_strings:
            if i in output:
                return True

    def should_abort(state):
        output = state.posix.dumps(sys.stdout.fileno())
        for i in bad_strings:
            if i in output:
                return True

    sim = proj.factory.simgr(state)


    #sim.explore(find=is_successful, avoid=should_abort)
    sim.explore(find=good_address)#avoid=bad_address)

    if sim.found:
        print("[+] Success found a solution")
        solve = sim.found[0]
        output = solve.posix.dumps(0)
        for solve in sim.found:
            print(solve.posix.dumps(sys.stdin.fileno()).decode('utf-8'))
    else:
        raise Exception("[-] Couldn't find a solution")

if __name__=="__main__":
    main(sys.argv)
