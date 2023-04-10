from queue import Queue

class UtilizationQueue(Queue):
    """Wrapper for queue which allows for multiple puts at once, handles
    flushing the queue when it gets too full"""
    def __init__(self, maxsize=0):
        super().__init__(maxsize=maxsize)
        # Track the ratio of sum to qsize (percentage full)
        self.current_utilization = 0
        # Track the sum each time an item is pushed onto queue
        self.sum = 0

    def util_put(self, item, n=1):
        """put method that allows for multiple insertions and manages pops"""
        if(self.qsize() + n >= self.maxsize):
            for i in range(int(n)):
                self.sum -= self.get()
        for i in range(int(n)):
            self.sum += item
            self.put(item)

    def get_utilization(self):
        if self.qsize() == 0:
            return 0
        return self.sum / self.maxsize