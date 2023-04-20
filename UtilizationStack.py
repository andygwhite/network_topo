class UtilizationStack:
    """Stack to emulate the utilization of a server.
    Pushes are performed when a new task is added, pops are performed for each
    unit of time passing. Utilization can exceed 100% in this system to model
    tasks being queued."""
    def __init__(self, capacity=100):
        self.capacity = capacity
        self.num_active_units = 0

    def util_push(self, n=1):
        """Updates the active unit count to n"""
        self.num_active_units += n

    def util_pop(self, n=1):
        """Removes one active unit"""
        if self.num_active_units > 0:
            self.num_active_units -= n

    def get_utilization(self):
        return self.num_active_units / self.capacity