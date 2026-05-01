import threading
from scapy.all import sniff
from features import extract_features, features_to_vector

class PacketCapture:
    def __init__(self, callback):
        self.callback = callback
        self.running  = False

    def start(self, interface=None):
        self.running = True
        threading.Thread(
            target=self._loop,
            args=(interface,),
            daemon=True
        ).start()

    def stop(self):
        self.running = False

    def _loop(self, iface):
        sniff(
            iface=iface,
            prn=self._handle,
            store=False,
            stop_filter=lambda _: not self.running
        )

    def _handle(self, pkt):
        f = extract_features(pkt)
        if f:
            self.callback(f, features_to_vector(f))