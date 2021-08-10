import ctypes
import os
import re
import struct
import sys
import time
import timeit
import io
import json
import random
from collections import OrderedDict

from itertools import groupby

import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
from volatility.plugins.linux import pslist as linux_pslist
from volatility.renderers import TreeGrid
from volatility import utils

PROFILE_PATH = "./Scripts/ScriptOutputs/profile_py.txt"  # PATH TO PYTHON PROFILE
PROFILE_DATA = None
recovered_c_structs = 0
recovered_python_objects = 0
false_positives = 0
hyperparameters = 0


pyobjs_vtype_64 = {
    'TorchParameter': [
        24,
        {
            'ob_refcnt': [0, ['long long']],
            'ob_type': [8, ['pointer', ['_PyTypeObject']]],
            'tensor': [16, ['pointer', ['TensorImpl']]]
        }],
    'TensorImpl': [
        80,
        {
            'vtable_ptr': [0, ['address']],
            'strong_refcnt': [8, ['long long']],
            'weak_refcnt': [16, ['long long']],  
            'storage': [24, ['pointer', ['StorageImpl']]],
            'autograd_metadata': [32, ['address']],
            'tensor_metadata': [40, ['address']],
            'version_ctr': [48, ['address']],
            'parameter': [56, ['pointer', ['TorchParameter']]],
            'num_dims': [64, ['long long']],
            'shape': [72, ['long long']]
        }],
    'StorageImpl': [
        32,
        {
            'vtable_ptr': [0, ['address']],
            'strong_refcnt': [8, ['long long']],
            'weak_refcnt': [16, ['long long']],  
            'buf': [24, ['pointer', ['float32']]]
        }]
    }


class TorchParameter(obj.CType):
    def is_valid(self):
        return self.ob_type.dereference().name in ["parameter", "tensor"]


class TensorImpl(obj.CType):
    def is_valid(self):
        return self.parameter.dereference().is_valid() and self.num_dims > 0
        
    @property
    def shape(self):
        dims = self.num_dims
        ret = []
        for i in range(dims):
            shape = obj.Object("long long", 
                                offset=self.obj_offset + 72 + 8 * i, 
                                vm=self.obj_vm)
            ret.insert(0, int(shape))
        return ret

    @property
    def num_elements(self):
        l = self.shape
        tot = 1
        for x in l:
            tot *= x
        return tot


class StorageImpl(obj.CType):
    def is_valid(self):
        return self.buf.dereference().is_valid()


class PythonClassTypes5(obj.ProfileModification):
    """
    Profile modifications for Python class types.  Only Linux and Mac OS,
    on 64-bit systems, are supported right now.
    """
    conditions = {"os": lambda x: x in ["linux", "mac"],
                  "memory_model": lambda x: x == "64bit"}
    
    def modification(self, profile):
        profile.vtypes.update(pyobjs_vtype_64)
        profile.object_classes.update({
            "TorchParameter": TorchParameter,
            "TensorImpl": TensorImpl,
            "StorageImpl": StorageImpl
        })


def extract_data(addr_space, num_elements, buf):
    ct = 0
    ret = []
    while (ct != num_elements):
        found_object = obj.Object("float32",
                                offset=buf,
                                vm=addr_space)
        if (ct < 3):
            print found_object.val
        if not isinstance(found_object.val, float): #invalid tensor
            return []
        else:
            ret.append(found_object.val)
        buf += 4
        ct += 1

    return ret


def bfs(model_root):
    """
    Searches model tree and returns list of leaves in order
    """

    global recovered_python_objects

    layers_ordered = []
    queue = [("model", model_root)]
    while (len(queue)):
        path, node = queue.pop(0)
        node_dict = node.in_dict.dereference().val
        recovered_python_objects += 1
        if node_dict['_modules'].ma_used == 0:
            layers_ordered.append((path, node))
            continue
        for key in node_dict['_modules'].val:
            recovered_python_objects += 1
            queue.append((path + "." + key, node_dict['_modules'].val[key]))
    return layers_ordered


def check_weights(task, out_dict):
    """
    Prints metrics about accuracy of weight recovery relative to ground truth
    """
    f = open("correct_weights_" + str(task.pid) + ".txt", "r")
    correct_dump = json.load(f)

    missing_weights = 0
    missing_layers = 0
    diff_weights = 0
    sum_diff = 0
    missing_arr = []
    diff_layers = []

    for layer in correct_dump['tensors']:
        if (layer in out_dict['tensors']):
            print (layer)
            
            correct_arr = correct_dump['tensors'][layer]
            recovered_arr = out_dict['tensors'][layer]

            diff_pos = []
            
            if (len(recovered_arr) != len(correct_arr)):
                print "Shapes Different"
            else:
                for i in range(len(correct_arr)):
                    if (recovered_arr[i] != correct_arr[i]):
                        diff_pos.append(i)

            if (len(diff_pos) == len(correct_arr)):
                print "No Valid Tensors"
            else:
                print("{} weights different".format(len(diff_pos)))
                print (diff_pos)
                sum_diff += len(diff_pos)
            if len(diff_pos) > 0:
                diff_layers.append(layer)
            print

        else:
            missing_layers += 1
            missing_weights += len(correct_dump['tensors'][layer])
            missing_arr.append(layer)

    print ("Correct model_name: {}".format(correct_dump['model_name']))
    print("Received model_name: {}".format(out_dict['model_name']))
    print ("Correct num_elements: {}".format(correct_dump['num_elements']))
    print ("Received num_elements: {}\n".format(out_dict['num_elements']))
    print (len(diff_layers))
    print (diff_layers)
    print (sum_diff)
    print ("{} layers not found".format(missing_layers))
    print (missing_arr)
    print ("{} out of {} found weights are different".format(sum_diff, correct_dump['num_elements'] - missing_weights))


def export_weights(task, weights, tot_num_elements, export_path, alpha, name):
    out_dict = {'model_name': name, 'num_elements': tot_num_elements, 'tensors': {}}
    for key in weights:
        out_dict['tensors'][key] = weights[key]

    with open(export_path + "weights_" + str(task.pid) + "_" + str(int(alpha*100)) + ".txt", 'w') as f:
        json.dump(out_dict, f)
    
    check_weights(task, out_dict) # if ground truth weights available


def export_offsets(task, tensor_offsets, export_path, alpha):
    """
    Write offsets of TensorImpl structs to file for rehosting
    File format:
        First line contains integer n, the number of tensors.
        n lines follow containing the name of the TensorImpl struct and its address.
    """
    f = open(export_path + "offsets_" + str(task.pid) + "_" + str(int(alpha*100)) + ".txt", 'w')
    f.write(str(len(tensor_offsets)) + "\n")
    for name in tensor_offsets:
        f.write(name + " " + str(hex(tensor_offsets[name])) + "\n")
    f.close()


def process_parameters(task, addr_space, model, export_path, alpha):
    """
    Extract shape and other hyperparameters of each slot variable in Python layer
    """

    global recovered_c_structs
    global recovered_python_objects
    global false_positives
    global hyperparameters

    all_layers = []
    shape = OrderedDict()
    name_to_weights = {}
    tot_num_elements = 0
    tensor_offsets = {}

    all_layers = bfs(model)
    
    for path, layer in all_layers:
        layer_dict = layer.in_dict.dereference().val
        layer_name = layer.ob_type.dereference().name
        recovered_python_objects += 1

        print
        print path, layer.ob_type.dereference().name

        if "Dropout" in layer_name:
            shape[path] = layer_dict['p'] # dropout rate
            recovered_python_objects += 1
            hyperparameters += 1
            print "Dropout Rate:", shape[path]

        elif "ReLU" in layer_name:
            shape[path] = None

        elif layer_dict['_parameters'].ma_used == 0 and layer_dict['_buffers'].ma_used == 0:
            shape[path] = None
            print "No Weights"
            continue
                
        if layer_dict['_parameters'].ma_used > 0:
            tensor_dict = layer_dict['_parameters'].val
            for key in tensor_dict:
                if tensor_dict[key] == None:
                    continue
                tensor = tensor_dict[key].tensor.dereference()
                uid = path + "." + key
                print "Path:", uid
                print "Num Elements:", tensor.num_elements
                print "Shape:", tensor.shape
                recovered_python_objects += 1
                recovered_c_structs += 2
                shape[uid] = tensor.shape
                final_addr = tensor.storage.buf
                name_to_weights[uid] = extract_data(addr_space, tensor.num_elements, final_addr)
                tensor_offsets[uid] = int(tensor.obj_offset)
                tot_num_elements += tensor.num_elements

        if layer_dict['_buffers'].ma_used > 0:
            tensor_dict = layer_dict['_buffers'].val
            for key in tensor_dict:
                if tensor_dict[key] == None:
                    continue
                tensor = tensor_dict[key].tensor.dereference()
                uid = path + "." + key
                print "Path:", uid
                print "Num Elements:", tensor.num_elements
                print "Shape:", tensor.shape
                recovered_python_objects += 1
                recovered_c_structs += 2
                shape[uid] = tensor.shape
                final_addr = tensor.storage.dereference().buf
                if key != "num_batches_tracked":
                    name_to_weights[uid] = extract_data(addr_space, tensor.num_elements, final_addr)
                else:
                    found_object = obj.Object("int",
                                offset=final_addr,
                                vm=addr_space)
                    name_to_weights[uid] = [int(found_object)]
                    print name_to_weights[uid]
                tensor_offsets[uid] = int(tensor.obj_offset)
                tot_num_elements += tensor.num_elements

    export_weights(task, name_to_weights, tot_num_elements, export_path, alpha, str(task.pid))
    export_offsets(task, tensor_offsets, export_path, alpha)

    print "\nMODEL SUMMARY"
    for key in shape:
        print key
        print shape[key]
        print

    print "\nEVAL TABLE SUMMARY"
    print "Layers:", len(all_layers)
    print "Tensors:", len(name_to_weights)
    print "Weights:", tot_num_elements
    print "Hyper Parameters:", hyperparameters
    print "Precision:", len(name_to_weights), "/", len(name_to_weights) + false_positives, "=", float(len(name_to_weights)) / float(len(name_to_weights) + false_positives)
    print "Python Objects:", recovered_python_objects
    print "C Structs:", recovered_c_structs


def is_model(found_object, class_names):
    model_name = found_object.ob_type.dereference().name
    if model_name in class_names:
        return True
    else:
        return False


def traverse_gc(task, addr_space, obj_type_string, start, stop, class_names, export_path, alpha):
    """
    Traverses the garbage collector generation (doubly linked list)
    Searches for model root
    """
    tmp = start

    global recovered_python_objects

    while True:
        found_head = obj.Object("_PyGC_Head", offset=tmp, vm=addr_space)
        found_object = obj.Object("_PyInstanceObject1",
                            offset=tmp + 32,
                            vm=addr_space)
        
        if not found_head.is_valid():
            print "_PyGC_Head invalid"
            sys.exit(0)
        
        recovered_python_objects += 2

        print "curr:", hex(tmp), "next:", hex(found_head.next_val), "prev:", hex(found_head.prev_val)
        print found_object.ob_type.dereference().name
        
        if is_model(found_object, class_names):
            print "Found", found_object.ob_type.dereference().name, "at", hex(found_object.obj_offset)
            process_parameters(task, addr_space, found_object, export_path, alpha)
            return True
        
        if (tmp == stop):
            break
        tmp = found_head.next_val
    return False


def get_profile_data():
    with open(PROFILE_PATH) as json_file:
        profile_data = json.load(json_file)
    return profile_data


def find_PyRuntime():
    profile_data = get_profile_data()
    for p in profile_data['globals']:
        if p['name'] == '_PyRuntime':
            return int(p['offset'],16)
    return -1


def find_model(task, class_names, export_path, alpha):
    """
    Go to _PyRuntimeState -> gc -> generations
    Traverse PyGC_Head pointers
    """
    start = timeit.default_timer()

    addr_space = task.get_process_address_space() 

    _PyRuntimeLoc = find_PyRuntime()

    print "_PyRuntime", hex(_PyRuntimeLoc)

    if _PyRuntimeLoc == -1:
        print "Failed to find any _pyruntime location"
        sys.exit(0)
    
    pyruntime = obj.Object("_PyRuntimeState",
                                  offset=_PyRuntimeLoc, #0xaa6560
                                  vm=addr_space)

    if not pyruntime.is_valid():
        print "Not _PyRuntimeState"
        sys.exit(0)

    if (traverse_gc(task=task, 
            addr_space=addr_space,
            obj_type_string="_PyGC_Head",
            start=pyruntime.gen1_next,
            stop=pyruntime.gen1_prev,
           class_names=class_names,
           export_path=export_path,
           alpha=alpha)):
           return
    if (traverse_gc(task=task, 
            addr_space=addr_space,
            obj_type_string="_PyGC_Head",
            start=pyruntime.gen2_next,
            stop=pyruntime.gen2_prev,
            class_names=class_names,
            export_path=export_path,
            alpha=alpha)):
            return
    if (traverse_gc(task=task, 
            addr_space=addr_space,
            obj_type_string="_PyGC_Head",
            start=pyruntime.gen3_next,
            stop=pyruntime.gen3_prev,
            class_names=class_names,
            export_path=export_path,
            alpha=alpha)):
            return
    
    print "Model Root not found"
    return


def read_addr_range(task, start, end):
	pagesize = 4096
	proc_as = task.get_process_address_space() # set as with our new kernel dtb to read from userland
	while start < end:
		page = proc_as.zread(start, pagesize)
		yield page
		start = start + pagesize


def dump_heaps(task, export_path, alpha):
    pid = int(task.pid)
    file_path = export_path + '%d_%d_dump' % (pid, alpha * 100)
    outfile = open(file_path, "wb+")
    for vma in task.get_proc_maps():
	    (fname, major, minor, ino, pgoff) = vma.info(task)
	    if str(fname) == '[heap]':
	    	for page in read_addr_range(task, vma.vm_start, vma.vm_end):
	    		outfile.write(page)


def _is_python_task(task, pidstr):
    """
    Checks if the task has the specified Python PID
    """
    if str(task.pid) != pidstr:
        return False
    else:
        return True


class pytorch_weights(linux_pslist.linux_pslist):
    """
    Recovers Tensorflow model attributes from a Python process.
    Includes VType definitions.
    """
    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option(
            'PID', short_option = 'p', default = None,
                          help = 'Operate on the Python Process ID',
                          action = 'store', type = 'str')

    def _validate_config(self):
        if self._config.PID is not None and len(self._config.PID.split(',')) != 1:
            debug.error("Please enter the process PID")
        
    def calculate(self):
        """
        Locate specified process and dump heap memory.
        """
        start = timeit.default_timer()
        linux_common.set_plugin_members(self)

        self._validate_config()
        pidstr = self._config.PID

        tasks = []
        for task in linux_pslist.linux_pslist.calculate(self):
            if _is_python_task(task, pidstr):
                tasks.append(task)

        alpha = 0.10
        export_path = './volatility_dumps_pytorch/'

        for task in tasks:
            find_model(task, ["MobileNetV2", "VGG16", "MobileNetV1"], export_path, alpha)
            dump_heaps(task, export_path, alpha)

        stop = timeit.default_timer()
        print("\nRuntime: {0} seconds".format(stop - start))
        sys.exit(0)

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
        self.table_header(outfd, [("Dict", "70")])
        for _, output in self.generator(data):
            self.table_row(outfd, *[str(o) for o in output])