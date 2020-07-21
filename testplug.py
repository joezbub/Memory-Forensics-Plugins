import volatility.obj as obj
import volatility.utils as utils
import volatility.plugins.linux.common as linux_common
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address
import volatility.plugins.linux.pslist as pslist
#python vol.py --plugins="./myplugins" --profile=LinuxUbuntu18043x64 -f /home/zhang/Downloads/dump.mem testplug

class TestPlug(pslist.linux_pslist):
    def render_text(self, outfd, data):
        for task in data:
            outfd.write("Task {0}: {1}\n".format(task.pid, task.comm))
        
    def calculate(self):
        data = pslist.linux_pslist.calculate(self)
        return data