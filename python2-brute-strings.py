#159 seconds runtime

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

pyobjs_vtype_64 = { #Found info here: https://docs.python.org/2.7/c-api/structures.html#c.PyObject_HEAD
    '_PyStringObj': [
        37,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['void']]],  # struct _typeobject *
            'ob_size': [16, ['long long']],  # Py_ssize_t = ssize_t
            'ob_shash': [24, ['long long']],
            'ob_sstate': [32, ['Enumeration',
                               dict(target='int', choices={
                                   0: 'SSTATE_NOT_INTERNED',
                                   1: 'SSTATE_INTERNED_MORTAL',
                                   2: 'SSTATE_INTERNED_IMMORTAL'
                               })]],
            'ob_sval': [36, ['array', 1, ['char']]]
        }]
    }


class _PyStringObj(obj.CType):
    r"""
    A class for python string objects.
    Found info here: https://docs.python.org/2.7/c-api/structures.html#c.PyObject_HEAD

    Information found from CPython implementation code:

    ----
    From stringobject.h:

        typedef struct {
            PyObject_VAR_HEAD
            long ob_shash;
            int ob_sstate;
            char ob_sval[1];

            /* Invariants:
            *     ob_sval contains space for 'ob_size+1' elements.
            *     ob_sval[ob_size] == 0.
            *     ob_shash is the hash of the string or -1 if not computed yet.
            *     ob_sstate != 0 iff the string object is in stringobject.c's
            *       'interned' dictionary; in this case the two references
            *       from 'interned' to this object are *not counted* in
            *       ob_refcnt.
            */
        } PyStringObject;

        #define SSTATE_NOT_INTERNED 0
        #define SSTATE_INTERNED_MORTAL 1
        #define SSTATE_INTERNED_IMMORTAL 2

    ----
    From object.h:
    
        //Note that _PyObject_HEAD_EXTRA is empty if
        //Py_TRACE_REFs is not defined

        /* PyObject_HEAD defines the initial segment of every PyObject. */
        #define PyObject_HEAD                   
            _PyObject_HEAD_EXTRA                
            Py_ssize_t ob_refcnt;               
            struct _typeobject *ob_type;

        #define PyObject_VAR_HEAD               
            PyObject_HEAD                       
            Py_ssize_t ob_size; /* Number of items in variable part */

    """
    def is_valid(self):
        ob_sval_offset, _ = self.members['ob_sval']
        string_address = self.obj_offset + ob_sval_offset

        return ( #Make sure string is legit by checking size and hash
            self.ob_type.is_valid() and 
            self.ob_size > 0 and self.ob_size <= 1e6 and
            self.ob_sstate.v() in self.ob_sstate.choices.keys() and
            self.obj_vm.zread(string_address + self.ob_size, 1) == '\x00' and
            (self.ob_shash == -1 or self.ob_shash == hash(self.string)))

    @property
    def string(self):
        sval_offset, _ = self.members['ob_sval']
        return self.obj_vm.zread(self.obj_offset + sval_offset,
                                 self.ob_size)


class PythonStringTypes1(obj.ProfileModification): #update vtypes
    conditions = {"os": lambda x: x in ["linux", "mac"],
                  "memory_model": lambda x: x == "64bit"}

    def modification(self, profile):
        profile.vtypes.update(pyobjs_vtype_64)
        profile.object_classes.update({
            "_PyStringObj": _PyStringObj,
        })


def brute_force_search(addr_space, obj_type_string, start, end, step_size): #search through all addresses one by one
    offset = start 
    while offset < end:
        found_object = obj.Object(obj_type_string,
                                  offset=offset,
                                  vm=addr_space)
        if found_object.is_valid():
            yield found_object
            offset += found_object.size() + found_object.ob_size
        else:
            offset += step_size


def find_python_strings(task):
    addr_space = task.get_process_address_space()
    heaps = get_heaps_and_anon(task)
    bfed_strings = []
    chunk_size = 1024 * 5

    for heap_vma in heaps:
        for chunk_start in xrange(heap_vma.vm_start,
                                  heap_vma.vm_end,
                                  chunk_size):
            bfed_strings.extend(list(brute_force_search(
                addr_space=addr_space,
                obj_type_string="_PyStringObj",
                start=chunk_start,
                end=chunk_start + chunk_size - 1,
                step_size=1)))
    return bfed_strings


def get_heaps_and_anon(task):
    for vma in task.get_proc_maps():
        if (vma.vm_start <= task.mm.start_brk and vma.vm_end >= task.mm.brk):
            yield vma
        elif vma.vm_name(task) == "Anonymous Mapping": #[anon] includes heaps
            yield vma


def _is_python_task(task, pidstr):
    if str(task.pid) != pidstr:
        return False
    else:
        return True


class linux_python2_strings(linux_pslist.linux_pslist):
    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option(
            'PID', short_option = 'p', default = None,
                          help = 'Operate on the CARLA Process ID',
                          action = 'store', type = 'str')

    def _validate_config(self):
        if self._config.PID is not None and len(self._config.PID.split(',')) != 1:
            debug.error("Please enter the CARLA Python API process PID")

    def calculate(self):
        #start = timeit.default_timer()

        linux_common.set_plugin_members(self)
        self._validate_config()
        pidstr = self._config.PID

        tasks = []
        for task in linux_pslist.linux_pslist.calculate(self):
            if _is_python_task(task, pidstr):
                tasks.append(task)

        for task in tasks:
            for py_string in find_python_strings(task):
                yield task, py_string

        #stop = timeit.default_timer()
        #print("Runtime: {0}".format(stop - start))

    def unified_output(self, data):
        return TreeGrid([("Pid", int),
                         ("Name", str),
                         ("Size", int),
                         ("String", str)],
                        self.generator(data))

    def generator(self, data):
        files = {}

        for task, py_string in data:
            yield (0, [int(task.pid),
                       str(task.comm),
                       int(py_string.ob_size),
                       py_string.string])

        for file_handle in files.values():
            file_handle.close()

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Pid", "15"),
                                  ("Name", "10"),
                                  ("Size", "10"),
                                  ("String", "50")])
        for _, output in self.generator(data):
            self.table_row(outfd, *[str(o) for o in output])
