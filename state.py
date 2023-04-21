from colorama import Fore
from state_machine import State, Event, acts_as_state_machine, after, before, InvalidStateTransition


@acts_as_state_machine
class Process:
    created = State(initial=True)
    waiting = State()
    running = State()
    terminated = State()
    blocked = State()
    swapped_out_waiting = State()
    swapped_out_blocked = State()

    wait = Event(from_states=(created, running, blocked, swapped_out_waiting), to_state=waiting)
    run = Event(from_states=waiting, to_state=running)
    terminate = Event(from_states=running, to_state=terminated)
    block = Event(from_states=(running, swapped_out_blocked), to_state=blocked)
    swap_block = Event(from_states=blocked, to_state=swapped_out_blocked)
    swap_wait = Event(from_states=swapped_out_blocked, to_state=swapped_out_waiting)

    def __init__(self, name):
        self.name = name

    @after('wait')
    def wait_info(self):
        print(Fore.GREEN + '{} entered waiting mode'.format(self.name) + Fore.RESET)

    @after('run')
    def run_info(self):
        print(Fore.GREEN + '{} is running'.format(self.name) + Fore.RESET)

    @before('terminate')
    def terminate_info(self):
        print(Fore.GREEN + '{} terminated'.format(self.name) + Fore.RESET)

    @after('block')
    def block_info(self):
        print(Fore.GREEN + '{} is blocked'.format(self.name) + Fore.RESET)

    @after('swap_wait')
    def swap_wait_info(self):
        print(Fore.GREEN + '{} is swapped out and waiting'.format(self.name) + Fore.RESET)

    @after('swap_block')
    def swap_block_info(self):
        print(Fore.GREEN + '{} is swapped out and blocked'.format(self.name) + Fore.RESET)


def transition(process, event, event_name):
    try:
        if process.current_state == 'created':
            state_info(process)
        event()
        state_info(process)
    except InvalidStateTransition as err:
        print(Fore.RED + f"Error: transition of {process.name} from {process.current_state} to {event_name} failed" + Fore.RESET)


def state_info(process):
    print(Fore.YELLOW + 'state of {}: {}'.format(process.name, process.current_state) + Fore.RESET)


def main():
    RUNNING = 'running'
    WAITING = 'waiting'
    BLOCKED = 'blocked'
    TERMINATED = 'terminated'

    p1, p2 = Process('process1'), Process('process2')
    [state_info(p) for p in (p1, p2)]

    print('-------1-------')
    transition(p1, p1.wait, WAITING)
    transition(p2, p2.terminate, TERMINATED)
    [state_info(p) for p in (p1, p2)]

    print('-------2-------')
    transition(p1, p1.run, RUNNING)
    transition(p2, p2.wait, WAITING)
    [state_info(p) for p in (p1, p2)]

    print('-------3-------')
    transition(p2, p2.run, RUNNING)
    [state_info(p) for p in (p1, p2)]

    print('-------4-------')
    [transition(p, p.block, BLOCKED) for p in (p1, p2)]
    [state_info(p) for p in (p1, p2)]

    print('-------5-------')
    [transition(p, p.terminate, TERMINATED) for p in (p1, p2)]
    [state_info(p) for p in (p1, p2)]

def run():
    RUNNING = 'running'
    WAITING = 'waiting'
    TERMINATED = 'terminated'
    BLOCKED = 'blocked'
    SWAP_BLOCKED = 'swap_blocked'
    SWAP_WAITING = 'swap_waiting'
    print(Fore.BLUE + 'Process1:   Created ===> Waiting ===> Running ===> Terminated' + Fore.RESET)
    p1 = Process('process1')
    transition(p1, p1.wait, WAITING)
    transition(p1, p1.run, RUNNING)
    transition(p1, p1.terminate, TERMINATED)

    print(Fore.BLUE + 'Process2:   Created ===> Waiting ===> Running ===> Blocked ===> Swapped_out_blocked ===> Swapped_out_waiting ===> Waiting ===> Running ===> Terminated' + Fore.RESET)
    p2 = Process('process2')
    transition(p2, p2.wait, WAITING)
    transition(p2, p2.run, RUNNING)
    transition(p2, p2.block, BLOCKED)
    transition(p2, p2.swap_block, SWAP_BLOCKED)
    transition(p2, p2.swap_wait, SWAP_WAITING)
    transition(p2, p2.wait, WAITING)
    transition(p2, p2.run, RUNNING)
    transition(p2, p2.terminate, TERMINATED)


if __name__ == '__main__':
    run()