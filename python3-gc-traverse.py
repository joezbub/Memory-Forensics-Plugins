import ctypes
import os
import re
import struct
import sys
import time
import timeit

from itertools import groupby

import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
from volatility.plugins.linux import pslist as linux_pslist
from volatility.renderers import TreeGrid
from volatility import utils


pyobjs_vtype_64 = { #Found info here: https://github.com/python/cpython/blob/3.7/Include
    '_PyTypeObject': [
        40,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['void']]],  # struct _typeobject *
            'ob_size': [16, ['long long']],  # Py_ssize_t = ssize_t
            'tp_name': [24, ['pointer', ['char']]],
            'tp_basicsize': [32, ['long long']]
        }],
    '_PyUnicodeString': [ #PyUnicodeObject already used?
        80,
        {
            'ob_refcnt': [0, ['long long']],
            'ob_type': [8, ['pointer', ['_PyTypeObject']]],  
            'length': [16, ['long long']],  # number of code points
            'ob_hash': [24, ['long long']],
            'ob_state': [32, ['unsigned int']], #interned 0-2, kind 1 2 4, compact 0-1, ascii 0-1, ready 0-1
            'ob_wstr': [36, ['pointer', ['void']]],
            'alignment1': [44, ['void']],
            'utf8_length': [48, ['long long']],
            'utf8_ptr': [56, ['pointer', ['char']]],
            'wstr_length': [64, ['long long']],
            'ob_data': [72, ['pointer', ['char']]]
        }],
    '_PyGC_Head': [
        24,
        {
            'gc_next': [0, ['unsigned long long']],
            'gc_prev': [8, ['unsigned long long']],
            'gc_refs': [16, ['long long']]
        }],
    '_GC_Runtime_State': [
        352,
        {
            'trash_delete_later': [0, ['address']],
            'trash_delete_nesting': [8, ['int']], 
            'enabled': [12, ['int']],
            'debug': [16, ['int']],
            'alignment1': [20, ['void']],
            'gen1_head': [32, ['_PyGC_Head']],
            'gen1_dummy': [56, ['void']],
            'gen1_threshold': [64, ['int']],
            'gen1_count': [68, ['int']],
            'gen1_alignment': [72, ['void']],
            'gen2_head': [80, ['_PyGC_Head']],
            'gen2_dummy': [104, ['void']],
            'gen2_threshold': [112, ['int']],
            'gen2_count': [116, ['int']],
            'gen1_alignment': [120, ['void']],
            'gen3_head': [128, ['_PyGC_Head']],
            'gen3_dummy': [152, ['void']],
            'gen3_threshold': [160, ['int']],
            'gen3_count': [164, ['int']],
            'gen1_alignment': [168, ['void']],
            'generation0': [176, ['pointer', ['_PyGC_Head']]],
            'alignment2': [184, ['void']],
            'perm_gen_head': [192, ['_PyGC_Head']],
            'perm_gen_dummy': [216, ['void']],
            'perm_gen_threshold': [224, ['int']],
            'perm_gen_count': [228, ['int']],
            'end_data': [232, ['void']]
        }],
    '_PyInterpreters': [
        32,
        {
            'interpreters_mutex': [0, ['address']],
            'interpreters_head': [8, ['address']], 
            'interpreters_main': [16, ['address']],
            'interpreters_next_id': [24, ['long long']]
        }],
    '_PyRuntimeState': [ 
        1520,
        {
            'initialized': [0, ['int']],
            'core_initialized': [4, ['int']],  
            'finalizing': [8, ['pointer', ['void']]], 
            'interpreters': [16, ['_PyInterpreters']],
            'exitfuncs': [48, ['void']],
            'nexitfuncs': [304, ['int']],
            'alignment1': [308, ['void']],
            'gc': [320, ['_GC_Runtime_State']],
            'end_data': [672, ['void']]
        }]
    }


class _PyTypeObject(obj.CType):
    def check_char(self, c):
        #make sure tp_name is one of these characters
        s = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM._-\/%"
        if c in s:
            return True
        else:
            return False
    
    @property
    def name(self):
        ret = ""
        for i in range(41):
            tmp = self.obj_vm.zread(self.tp_name + i, 1)
            if tmp == '\x00':
                if (i >= 2):
                    return ret
                else:
                    return "invalid"
            if not self.check_char(tmp):
                return "invalid"
            ret += tmp
        return "invalid"

    def is_valid(self):
        if not (self.ob_type.is_valid() and self.tp_name.is_valid() and self.tp_basicsize.is_valid()):
            return False
        s = self.name
        return (s != "invalid")


class _PyUnicodeString(obj.CType):
    def parse_state(self):
        interned = kind = compact = ascii_tmp = ready = -1

        if (self.ob_state >> 1) & 1 and not((self.ob_state >> 0) & 1): #interned
            interned = 2
        elif not(self.ob_state >> 1) & 1 and (self.ob_state >> 0) & 1:
            interned = 1
        elif not(self.ob_state >> 1) & 1 and not((self.ob_state >> 0) & 1):
            interned = 0

        if (self.ob_state >> 4) & 1: #kind
            if not((self.ob_state >> 3) & 1) and not((self.ob_state >> 2) & 1):
                kind = 4
        else:
            if ((self.ob_state >> 3) & 1) and not((self.ob_state >> 2) & 1):
                kind = 2
            elif not((self.ob_state >> 3) & 1) and ((self.ob_state >> 2) & 1):
                kind = 1
            elif not((self.ob_state >> 3) & 1) and not((self.ob_state >> 2) & 1):
                kind = 0
        
        compact = int(((self.ob_state >> 5) & 1))
        ascii_tmp = int(((self.ob_state >> 6) & 1))
        ready = int(((self.ob_state >> 7) & 1))

        return interned, kind, compact, ascii_tmp, ready

    def is_valid(self): #ob_hash is different from Python's builtin hash
        if not (self.ob_type.is_valid() and self.ob_type.dereference().is_valid()
                and self.length > 0 and self.length <= 1e2 and self.ob_hash.is_valid()
                and "str" in self.ob_type.dereference().name
                and self.ob_type.dereference().tp_basicsize == 80):
            return False

        interned, kind, compact, ascii_tmp, ready = self.parse_state()

        #ignore ready legacy or unready legacy or compact unicode
        if interned == -1 or kind <= 0 or compact <= 0 or ascii_tmp <= 0 or ready <= 0: 
            return False
        else:
            return True

    @property
    def val(self):
        interned, kind, compact, ascii_tmp, ready = self.parse_state()

        if ascii_tmp == 1: #should go here, never encountered compact unicode before
            uni_buff = self.obj_vm.zread(self.obj_offset + 48, self.length)
            return uni_buff
        elif ascii_tmp == 0: 
            uni_buff = self.obj_vm.zread(self.obj_offset + 72, self.length)
            print uni_buff.encode("utf-8")
            return uni_buff.decode()


class _PyGC_Head(obj.CType):
    def is_valid(self):
        return (self.gc_next.is_valid() and self.gc_prev.is_valid() and self.gc_refs.is_valid())

    @property
    def next_val(self):
        return self.gc_next

    @property
    def prev_val(self):
        return self.gc_prev
    

class _GC_Runtime_State(obj.CType):
    def is_valid(self):
        return (self.trash_delete_later.is_valid() and self.trash_delete_nesting.is_valid()
            and self.gen1_head.is_valid() and self.gen2_head.is_valid() and self.gen3_head.is_valid())


class _PyInterpreters(obj.CType):
    def is_valid(self):
        return (self.interpreters_mutex.is_valid() and self.interpreters_head.is_valid()
            and self.interpreters_main.is_valid())


class _PyRuntimeState(obj.CType):
    def is_valid(self):
        return (self.initialized.is_valid() and self.core_initialized.is_valid() 
            and self.interpreters.is_valid() and self.gc.is_valid())

    @property
    def gen1_next(self):
        return self.gc.gen1_head.next_val
    
    @property
    def gen2_next(self):
        return self.gc.gen2_head.next_val

    @property
    def gen3_next(self):
        return self.gc.gen3_head.next_val

    @property
    def gen1_prev(self):
        return self.gc.gen1_head.prev_val
    
    @property
    def gen2_prev(self):
        return self.gc.gen2_head.prev_val

    @property
    def gen3_prev(self):
        return self.gc.gen3_head.prev_val


class PythonClassTypes4(obj.ProfileModification):
    """
    Profile modifications for Python class types.  Only Linux and Mac OS,
    on 64-bit systems, are supported right now.
    """
    conditions = {"os": lambda x: x in ["linux", "mac"],
                  "memory_model": lambda x: x == "64bit"}
    
    def modification(self, profile): #writes to file somewhere (beware of duplicate names)
        profile.vtypes.update(pyobjs_vtype_64)
        profile.object_classes.update({
            "_PyTypeObject": _PyTypeObject,
            "_PyUnicodeString": _PyUnicodeString,
            "_PyGC_Head": _PyGC_Head,
            "_GC_Runtime_State": _GC_Runtime_State,
            "_PyInterpreters": _PyInterpreters,
            "_PyRuntimeState": _PyRuntimeState
        })


def brute_force_search(addr_space, obj_type_string, start, stop, class_name):
    """
    Brute-force search an area of memory for a given object type.  Returns
    valid types as a generator.
    """
    tmp = start
    arr = []

    while True:
        arr.append(tmp)
        found_head = obj.Object("_PyGC_Head",
                                  offset=tmp,
                                  vm=addr_space)
        #Just want to access ob_type -> tp_name from UnicodeObject
        found_object = obj.Object("_PyUnicodeString",
                            offset=tmp + 32,
                            vm=addr_space)
        
        if not found_head.is_valid():
            print "_PyGC_Head invalid"
            sys.exit(0)
            
        print "curr:", hex(tmp), "next:", hex(found_head.next_val), "prev:", hex(found_head.prev_val)
        print "type name:", found_object.ob_type.dereference().name
        if (tmp == stop):
            break
        tmp = found_head.next_val    

    return arr


def find_instance(task, class_name):
    """
    Go to _PyRuntimeState -> gc -> generations -> brute force through PyGC_Head pointers
    """
    addr_space = task.get_process_address_space() 

    pyruntime = obj.Object("_PyRuntimeState",
                                  offset=0xaa5560, #harcoded address of _PyRuntime (found in ELF header)
                                  vm=addr_space)
    if not pyruntime.is_valid():
        print "Not _PyRuntimeState"
        sys.exit(0)

    found_locs = []
    found_locs.extend(brute_force_search(
            addr_space=addr_space,
            obj_type_string="_PyGC_Head",
            start=pyruntime.gen1_next,
            stop=pyruntime.gen1_prev,
            class_name=class_name))
    found_locs.extend(brute_force_search(
            addr_space=addr_space,
            obj_type_string="_PyGC_Head",
            start=pyruntime.gen2_next,
            stop=pyruntime.gen2_prev,
            class_name=class_name))
    found_locs.extend(brute_force_search(
            addr_space=addr_space,
            obj_type_string="_PyGC_Head",
            start=pyruntime.gen3_next,
            stop=pyruntime.gen3_prev,
            class_name=class_name))

    print len(found_locs), "objects found"
    sys.exit(0)
    return found_locs


def _is_python_task(task, pidstr):
    """
    Checks if the task has the Python PID
    """
    if str(task.pid) != pidstr:
        return False
    else:
        return True


class linux_python3_instances(linux_pslist.linux_pslist):
    """
    Pull Tensorflow model instances from a Python process's GC generations. Under development.
    Still need to:
    1. Write Dict Object
    2. Understand how instances are represented
    3. Automate search for _PyRuntime
    """
    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option(
            'PID', short_option = 'p', default = None,
                          help = 'Operate on the Python PID',
                          action = 'store', type = 'str')

    def _validate_config(self):
        if self._config.PID is not None and len(self._config.PID.split(',')) != 1:
            debug.error("Please enter Python PID")
        
    def calculate(self):
        """
        Find the tasks that are actually python processes.  May not
        necessarily be called "python", but the executable is python.

        """
        start = timeit.default_timer()
        linux_common.set_plugin_members(self)

        self._validate_config()
        pidstr = self._config.PID

        tasks = []
        for task in linux_pslist.linux_pslist.calculate(self):
            if _is_python_task(task, pidstr):
                tasks.append(task)

        for task in tasks:
            for instance in find_instance(task, "model.Sequential"):
                yield instance
        
        #stop = timeit.default_timer()
        #print("Runtime: {0}".format(stop - start))

    def unified_output(self, data):
        """
        Return a TreeGrid with data to print out.
        """
        return TreeGrid([("Name", str)],
                        self.generator(data))

    def generator(self, data):
        """
        Generate data that may be formatted for printing.
        """
        for instance in data:
            yield (0, [str(instance.string)])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Name", "100")])
        for _, output in self.generator(data):
            self.table_row(outfd, *[str(o) for o in output])
