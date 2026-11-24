"""A shared per-user payload budget, independent of connection count."""
import threading,time

class Bandwidth:
    def __init__(self,rate):
        if type(rate) is not int or not 1024<=rate<=1024**3:raise ValueError('rate_bps must be 1024..1073741824')
        self.rate=rate;self.capacity=max(65536,rate//4);self.tokens=float(self.capacity);self.updated=time.monotonic();self.lock=threading.Lock();self.bytes=0
    def consume(self,size,stop=None):
        remaining=size
        while remaining:
            if stop and stop.is_set():raise RuntimeError('Server stopping')
            with self.lock:
                now=time.monotonic();self.tokens=min(self.capacity,self.tokens+(now-self.updated)*self.rate);self.updated=now
                amount=min(remaining,int(self.tokens));self.tokens-=amount;remaining-=amount;self.bytes+=amount
                wait=min(.1,max(.001,remaining/self.rate))
            if remaining:
                if stop:stop.wait(wait)
                else:time.sleep(wait)
